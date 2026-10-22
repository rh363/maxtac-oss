"""Composition root: l'unico posto dove si istanziano gli adapter concreti."""

from __future__ import annotations

import logging
import os
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from maxtac.adapters.anthropic_llm import AnthropicLLM
from maxtac.adapters.docker_sandbox import DockerSandbox, SandboxSpec, netrc_text
from maxtac.adapters.gitlab_vcs import GitLabRouter, GitLabVCS, TokenUnavailable, introspect_token
from maxtac.adapters.notifier import NoopNotifier, WebhookNotifier
from maxtac.adapters.scanners import build_scanners
from maxtac.adapters.sqlite_store import (
    SqliteBudget,
    SqliteRepoRegistry,
    SqliteRunStore,
    SqliteStore,
    SqliteTokenRegistry,
    connect,
)
from maxtac.config import (
    SECRETS_DIR,
    AppConfig,
    Secrets,
    load_secrets,
    read_extra_registries,
    read_registry_credential,
    read_token_secret,
)
from maxtac.domain.models import RepoConfig
from maxtac.domain.policy import Redactor, merge_repos, registry_conflicts, resolve_token
from maxtac.domain.ports import NotifierPort, SandboxPort, ScannerPort
from maxtac.services.discovery import Discovery, DiscoverySettings
from maxtac.services.pipeline import Pipeline
from maxtac.services.redaction import RedactingSandboxes
from maxtac.services.ripperdoc import registries_note
from maxtac.services.scan import ScanService

log = logging.getLogger(__name__)


class MissingSecret(RuntimeError):
    pass


class RegistryConflict(RuntimeError):
    """L'allowlist locale del proxy lascerebbe il sandbox raggiungere GitLab."""


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class Container:
    config: AppConfig
    conn: sqlite3.Connection
    store: SqliteStore
    budget: SqliteBudget
    runs: SqliteRunStore
    registry: SqliteRepoRegistry
    tokens: SqliteTokenRegistry
    clock: Callable[[], datetime] = utcnow
    secrets: Secrets = field(default_factory=load_secrets)
    secrets_dir: Path = SECRETS_DIR
    # Client python-gitlab per un token: sostituibile nei test
    gitlab_client: Callable[[str], Any] | None = None

    @classmethod
    def build(cls, config: AppConfig) -> Container:
        conn = connect(config.db_path)
        return cls(
            config,
            conn,
            SqliteStore(conn),
            SqliteBudget(conn),
            SqliteRunStore(conn),
            SqliteRepoRegistry(conn),
            SqliteTokenRegistry(conn),
        )

    def repos(self) -> list[RepoConfig]:
        """Repo del config.yaml più quelli approvati dall'autodiscovery. Vince il config.

        Un repo approvato che nessun token copre resta nell'elenco: la run lo salta con il
        motivo nel report (il config.yaml invece viene rifiutato già al caricamento).
        """
        repos = merge_repos(
            self.config.to_repos(), (a.repo for a in self.registry.approved_repos())
        )
        scopes = self.config.gitlab.token_scopes()
        for r in repos:
            if resolve_token(r.project, scopes) is None:
                log.warning("%s: approvato ma nessun token in gitlab.tokens lo copre", r.project)
        return repos

    def _client(self, token: str) -> Any:
        if self.gitlab_client is not None:
            return self.gitlab_client(token)
        import gitlab

        g = self.config.gitlab
        return gitlab.Gitlab(
            g.url,
            private_token=token,
            ssl_verify=str(g.ca_bundle) if g.ca_bundle else True,
            timeout=g.timeout_s,
        )

    def _token_value(self, name: str) -> str:
        g = self.config.gitlab
        if g.tokens is None:
            tok = self.secrets.gitlab_token
            value = tok.get_secret_value().strip() if tok is not None else ""
            # anche come file secrets/gitlab_tokens/default, montato dal compose
            value = value or read_token_secret(name, self.secrets_dir) or ""
            label = "token GitLab"
        else:
            value = read_token_secret(name, self.secrets_dir) or ""
            label = f"token GitLab {name}"
        if not value:
            raise MissingSecret(f"{label} mancante ({g.secret_hint(name)})")
        return value

    def vcs(self) -> GitLabRouter:
        """Un GitLabVCS per token, dietro un router che sceglie il token dal path del repo.

        A ogni costruzione (una per run, quindi segreti ruotati vengono riletti) ogni token
        viene controllato su GitLab (utente, scadenza, scope) e lo stato finisce nello store,
        dove lo leggono `status` e la dashboard, che non hanno i token.
        """
        g = self.config.gitlab
        backends: dict[str, GitLabVCS | TokenUnavailable] = {}
        infos = []
        # Prima tutti i segreti: un token mancante è un errore di config, prima di ogni chiamata
        values = {name: self._token_value(name) for name in g.token_scopes()}
        for name, scope in g.token_scopes().items():
            value = values[name]
            client = self._client(value)
            info, ident = introspect_token(
                name,
                scope,
                client,
                g.url,
                self.clock(),
                secrets=[value],
                name_override=g.name_override(name),
                email_override=g.email_override(),
            )
            infos.append(info)
            if ident is None:
                log.error("%s", info.error)
                backends[name] = TokenUnavailable(info.error or f"token {name} non utilizzabile")
                continue
            backends[name] = GitLabVCS(
                url=g.url,
                token=value,
                bot_name=ident.name,
                bot_email=ident.email,
                client=client,
                ca_bundle=g.ca_bundle,
            )
        self.tokens.save_tokens(infos)
        return GitLabRouter(g.token_scopes(), backends)

    def extra_registries(self) -> tuple[list[str], list[str]]:
        """Registry interni dell'allowlist del proxy e quelli che coprirebbero GitLab."""
        extra = read_extra_registries(self.config.sandbox.extra_registries_file)
        return extra, registry_conflicts(extra, self.config.gitlab.host)

    def registry_credentials(self) -> list[tuple[str, str, str]]:
        """(host, utente, password) per il ~/.netrc dei sandbox."""
        out = []
        for c in self.config.sandbox.registry_credentials:
            try:
                user, password = read_registry_credential(c.secret, self.secrets_dir)
            except (OSError, ValueError) as e:
                raise MissingSecret(f"registry {c.host}: {e}") from None
            out.append((c.host, user, password))
        return out

    def registries_note(self) -> str:
        extra, _ = self.extra_registries()
        hosts = [c.host for c in self.config.sandbox.registry_credentials]
        return registries_note(extra, hosts)

    def redactor(self) -> Redactor:
        return Redactor.for_credentials((u, p) for _, u, p in self.registry_credentials())

    def sandboxes(self) -> SandboxPort:
        _, conflicts = self.extra_registries()
        if conflicts:
            raise RegistryConflict(
                f"{self.config.sandbox.extra_registries_file}: {conflicts} coprono "
                f"{self.config.gitlab.host}: il sandbox non deve mai raggiungere GitLab"
            )
        creds = self.registry_credentials()
        s = self.config.sandbox
        # Con il compose l'immagine arriva da AUTOFIX_SANDBOX_IMAGE (tag o digest pubblicato),
        # la stessa che `docker compose --profile sandbox pull` scarica.
        image = os.environ.get("AUTOFIX_SANDBOX_IMAGE") or s.image
        sandbox = DockerSandbox(
            SandboxSpec(
                image=image,
                network=s.network,
                proxy_url=s.proxy_url,
                user=s.user,
                mem_limit=s.mem_limit,
                cpus=s.cpus,
                pids_limit=s.pids_limit,
                tmp_size=s.tmp_size,
                home_size=s.home_size,
                netrc=netrc_text(creds),
            )
        )
        if not creds:
            return sandbox
        return RedactingSandboxes(sandbox, Redactor.for_credentials((u, p) for _, u, p in creds))

    def scanners(self) -> list[ScannerPort]:
        langs = {lang for r in self.repos() for lang in r.languages}
        return list(build_scanners(self.config.semgrep_rulesets(langs)))

    def scan_service(self) -> ScanService:
        return ScanService(
            vcs=self.vcs(),
            sandboxes=self.sandboxes(),
            scanners=self.scanners(),
            # lo scan non spende token: in --scan-only girano tutti gli scanner
            kinds=frozenset({"cve", "sast"}),
            workdir=self.config.workdir,
        )

    def llm(self) -> AnthropicLLM:
        key = self.secrets.anthropic_api_key
        if key is None or not key.get_secret_value().strip():
            raise MissingSecret(
                "chiave Anthropic mancante (/run/secrets/anthropic_api_key o ANTHROPIC_API_KEY)"
            )
        a = self.config.anthropic
        return AnthropicLLM.from_api_key(
            key.get_secret_value().strip(),
            timeout_s=a.timeout_s,
            max_retries=a.max_retries,
            effort=a.effort,
            refusal_fallback=a.refusal_fallback,
            fallback_models=a.fallback_models,
        )

    def notifier(self) -> NotifierPort:
        n = self.config.notify
        if not n.webhook:
            return NoopNotifier()
        url = self.secrets.notify_webhook_url
        if url is None or not url.get_secret_value().strip():
            raise MissingSecret(
                "webhook di notifica attivo ma URL mancante "
                "(/run/secrets/notify_webhook_url o NOTIFY_WEBHOOK_URL)"
            )
        return WebhookNotifier(url.get_secret_value().strip(), timeout_s=n.timeout_s)

    def pipeline(self, *, dry_run: bool) -> Pipeline:
        """Pipeline completa con gli adapter reali, segreti letti da Secrets()."""
        llm = self.llm()  # prima i segreti locali, poi il controllo dei token su GitLab
        notifier = self.notifier()
        return Pipeline(
            vcs=self.vcs(),
            sandboxes=self.sandboxes(),
            scanners=self.scanners(),
            llm=llm,
            store=self.store,
            budget=self.budget,
            pricing=self.config.to_pricing(),
            settings=replace(
                self.config.to_settings(dry_run=dry_run), registries_note=self.registries_note()
            ),
            clock=self.clock,
            runs=self.runs,
            notifier=notifier,
            redactor=self.redactor(),
        )

    def discovery(self, *, use_llm: bool) -> Discovery:
        b = self.config.budget
        llm = self.llm() if use_llm else None  # chiave mancante: errore prima di chiamare GitLab
        return Discovery(
            vcs=self.vcs(),
            sandboxes=self.sandboxes(),
            llm=llm,
            registry=self.registry,
            budget=self.budget,
            pricing=self.config.to_pricing(),
            settings=DiscoverySettings(
                model=self.config.models.discovery,
                per_repo_usd=b.discovery_per_repo_usd,
                max_iterations=b.discovery_max_iterations,
                workdir=self.config.workdir,
                monthly_credits_usd=b.monthly_credits_usd,
                registries_note=self.registries_note(),
            ),
            clock=self.clock,
        )

    def close(self) -> None:
        self.conn.close()
