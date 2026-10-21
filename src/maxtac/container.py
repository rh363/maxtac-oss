"""Composition root: l'unico posto dove si istanziano gli adapter concreti."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from maxtac.adapters.anthropic_llm import AnthropicLLM
from maxtac.adapters.docker_sandbox import DockerSandbox, SandboxSpec
from maxtac.adapters.gitlab_vcs import GitLabVCS
from maxtac.adapters.notifier import NoopNotifier, WebhookNotifier
from maxtac.adapters.scanners import build_scanners
from maxtac.adapters.sqlite_store import (
    SqliteBudget,
    SqliteRepoRegistry,
    SqliteRunStore,
    SqliteStore,
    connect,
)
from maxtac.config import AppConfig, Secrets, load_secrets
from maxtac.domain.models import RepoConfig
from maxtac.domain.policy import merge_repos
from maxtac.domain.ports import NotifierPort, ScannerPort
from maxtac.services.discovery import Discovery, DiscoverySettings
from maxtac.services.pipeline import Pipeline
from maxtac.services.scan import ScanService


class MissingSecret(RuntimeError):
    pass


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
    clock: Callable[[], datetime] = utcnow
    secrets: Secrets = field(default_factory=load_secrets)

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
        )

    def repos(self) -> list[RepoConfig]:
        """Repo del config.yaml più quelli approvati dall'autodiscovery. Vince il config."""
        return merge_repos(self.config.to_repos(), (a.repo for a in self.registry.approved_repos()))

    def vcs(self) -> GitLabVCS:
        token = self.secrets.gitlab_token
        if token is None or not token.get_secret_value().strip():
            raise MissingSecret("token GitLab mancante (/run/secrets/gitlab_token o GITLAB_TOKEN)")
        g = self.config.gitlab
        return GitLabVCS(
            url=g.url,
            token=token.get_secret_value().strip(),
            bot_name=g.bot_name,
            bot_email=g.commit_email(),
            ca_bundle=g.ca_bundle,
        )

    def sandboxes(self) -> DockerSandbox:
        s = self.config.sandbox
        return DockerSandbox(
            SandboxSpec(
                image=s.image,
                network=s.network,
                proxy_url=s.proxy_url,
                user=s.user,
                mem_limit=s.mem_limit,
                cpus=s.cpus,
                pids_limit=s.pids_limit,
                tmp_size=s.tmp_size,
                home_size=s.home_size,
            )
        )

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
        return Pipeline(
            vcs=self.vcs(),
            sandboxes=self.sandboxes(),
            scanners=self.scanners(),
            llm=self.llm(),
            store=self.store,
            budget=self.budget,
            pricing=self.config.to_pricing(),
            settings=self.config.to_settings(dry_run=dry_run),
            clock=self.clock,
            runs=self.runs,
            notifier=self.notifier(),
        )

    def discovery(self, *, use_llm: bool) -> Discovery:
        b = self.config.budget
        return Discovery(
            vcs=self.vcs(),
            sandboxes=self.sandboxes(),
            llm=self.llm() if use_llm else None,
            registry=self.registry,
            budget=self.budget,
            pricing=self.config.to_pricing(),
            settings=DiscoverySettings(
                model=self.config.models.discovery,
                per_repo_usd=b.discovery_per_repo_usd,
                max_iterations=b.discovery_max_iterations,
                workdir=self.config.workdir,
                monthly_credits_usd=b.monthly_credits_usd,
            ),
            clock=self.clock,
        )

    def close(self) -> None:
        self.conn.close()
