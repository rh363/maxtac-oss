"""Config di fiducia: un file YAML dell'orchestrator. I segreti stanno nei Docker secret."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from maxtac.domain.budget import ModelPrice, Pricing
from maxtac.domain.models import Language, RepoConfig
from maxtac.domain.policy import registry_conflicts, resolve_token
from maxtac.services.pipeline import Limits, Models, PipelineSettings

ThemeName = Literal["neutral", "cyberpunk"]
PROJECT_RE = re.compile(r"^[\w.-]+(/[\w.-]+)+$")
DEFAULT_CONFIG_PATH = Path("/etc/autofix/config.yaml")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


SCOPE_RE = re.compile(r"^[\w.-]+(/[\w.-]+)*$")
LEGACY_TOKEN = "default"


class TokenConf(_Model):
    """Un token GitLab (Group, Project o Personal Access Token) e i path che copre.

    Il valore sta nel file `secrets/gitlab_tokens/<name>` (o nella variabile d'ambiente
    GITLAB_TOKEN_<NAME>), mai qui.
    """

    name: str = Field(pattern=r"^[a-z0-9-]+$", max_length=40)
    # Prefissi di path: un gruppo, un sottogruppo o un progetto (es. `backend`, `alex/ecs2`)
    scope: list[str] = Field(min_length=1)
    bot_name: str | None = None  # nome dei commit; default: il nome dell'utente su GitLab

    @field_validator("scope")
    @classmethod
    def _scope_format(cls, v: list[str]) -> list[str]:
        bad = [p for p in v if not SCOPE_RE.match(p)]
        if bad:
            raise ValueError(f"scope deve contenere path GitLab (gruppo o gruppo/progetto): {bad}")
        return v


class GitLabConf(_Model):
    url: str = Field(pattern=r"^https://[^/\s]+(/[^\s]*)?$")
    # Più token, uno per gruppo o progetto. Senza `tokens` vale il solo segreto `gitlab_token`
    # per tutta l'istanza (configurazione delle versioni precedenti).
    tokens: list[TokenConf] | None = Field(default=None, min_length=1)
    # Identità dei commit: di norma si legge da GitLab (utente del token). Questi campi la
    # forzano, e valgono solo per il token unico `gitlab_token`.
    bot_username: str | None = None
    bot_name: str | None = None
    bot_email: str | None = None
    # CA interna per un GitLab self-hosted con certificato non pubblico: usata da API, git e
    # login OIDC della dashboard. Il sandbox non la riceve (e non raggiunge GitLab).
    ca_bundle: Path | None = None
    # Timeout delle chiamate API: senza, una GitLab irraggiungibile blocca la run per sempre
    timeout_s: float = Field(default=30.0, gt=0)

    @model_validator(mode="after")
    def _check_tokens(self) -> Self:
        if self.tokens is None:
            return self
        names = [t.name for t in self.tokens]
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            raise ValueError(f"gitlab.tokens: nomi duplicati {dupes}")
        prefixes = [p for t in self.tokens for p in t.scope]
        same = sorted({p for p in prefixes if prefixes.count(p) > 1})
        if same:
            raise ValueError(f"gitlab.tokens: lo stesso prefisso in più token {same}")
        return self

    @property
    def host(self) -> str:
        return self.url.split("://", 1)[1].split("/", 1)[0]

    def token_scopes(self) -> dict[str, tuple[str, ...]]:
        if self.tokens is None:
            return {LEGACY_TOKEN: ("",)}
        return {t.name: tuple(t.scope) for t in self.tokens}

    def secret_hint(self, token: str) -> str:
        """Dove mettere il valore del token, per i messaggi d'errore."""
        if self.tokens is None:
            return "/run/secrets/gitlab_token o GITLAB_TOKEN"
        env = f"GITLAB_TOKEN_{token}".upper().replace("-", "_")
        return f"secrets/gitlab_tokens/{token} o {env}"

    def name_override(self, token: str) -> str | None:
        if self.tokens is None:
            return self.bot_name
        return next((t.bot_name for t in self.tokens if t.name == token), None)

    def email_override(self) -> str | None:
        """Solo per il token unico: email esplicita, o noreply dello username indicato."""
        if self.tokens is not None:
            return None
        if self.bot_email:
            return self.bot_email
        return f"{self.bot_username}@noreply.{self.host}" if self.bot_username else None


HOST_RE = r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"


class RegistryCredentialConf(_Model):
    """Credenziale di sola lettura per un registry interno (PyPI, npm...), scritta nel
    ~/.netrc di ogni sandbox. Il valore `utente:password` sta in
    /run/secrets/registry_credentials/<secret>. Mai credenziali verso GitLab."""

    host: str = Field(pattern=HOST_RE)
    secret: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")


class SandboxConf(_Model):
    image: str = "ghcr.io/rh363/autofix-sandbox:main"  # sovrascritta da AUTOFIX_SANDBOX_IMAGE
    network: str = "autofix_sandbox"
    proxy_url: str = "http://proxy:3128"
    user: str = Field(default="1000:1000", pattern=r"^[1-9]\d*(:[1-9]\d*)?$")  # mai root
    mem_limit: str = Field(default="4g", pattern=r"^\d+[kmg]$")
    cpus: float = Field(default=2.0, gt=0, le=64)
    pids_limit: int = Field(default=512, ge=64)
    tmp_size: str = Field(default="1g", pattern=r"^\d+[kmg]$")
    home_size: str = Field(default="4g", pattern=r"^\d+[kmg]$")
    registry_credentials: list[RegistryCredentialConf] = Field(default_factory=list)
    # Registry interni aggiunti all'allowlist del proxy, uno per riga: file locale della VM
    # (proxy/local/extra-registries.txt), letto qui solo per controllare che non copra GitLab.
    extra_registries_file: Path = Path("/etc/autofix/proxy-local/extra-registries.txt")
    # Immagine per prefisso di progetto (il più specifico vince) per setup, fix, test e
    # hunting: deve partire dall'immagine standard (FROM), che resta per scan e rescan.
    # "" copre tutti i progetti.
    images: dict[str, str] = Field(default_factory=dict)

    @field_validator("images")
    @classmethod
    def _valid_images(cls, v: dict[str, str]) -> dict[str, str]:
        for prefix, image in v.items():
            if prefix and not re.fullmatch(r"[\w.-]+(/[\w.-]+)*", prefix):
                raise ValueError(f"sandbox.images: prefisso non valido {prefix!r} (es. team/api)")
            if not re.fullmatch(r"[\w.-]+(/[\w.-]+)*(:[\w.-]+)?(@sha256:[0-9a-f]{64})?", image):
                raise ValueError(f"sandbox.images: immagine non valida {image!r}")
        return v


def _default_semgrep_by_language() -> dict[str, list[str]]:
    return {
        "python": ["p/python"],
        "go": ["p/golang"],
        "javascript": ["p/javascript"],
        "typescript": ["p/typescript"],
    }


class SemgrepConf(_Model):
    rulesets: list[str] = Field(default_factory=lambda: ["p/default"])
    by_language: dict[str, list[str]] = Field(default_factory=_default_semgrep_by_language)


class ScannersConf(_Model):
    semgrep: SemgrepConf = SemgrepConf()


class ScheduleConf(_Model):
    timezone: str = "Europe/Rome"
    at: str = Field(default="02:30", pattern=r"^([01]\d|2[0-3]):[0-5]\d$")


class BudgetConf(_Model):
    monthly_credits_usd: float = Field(default=100.0, gt=0)  # crediti API inclusi nel piano
    per_night_usd: float = Field(default=3.0, gt=0)
    per_task_usd: float = Field(default=0.80, gt=0)
    triage_per_repo_usd: float = Field(default=0.10, gt=0)
    hunting_per_night_usd: float = Field(default=1.0, ge=0)
    max_mrs_per_night: int = Field(default=3, ge=0)
    max_attempts: int = Field(default=2, ge=1)
    max_iterations: int = Field(default=30, ge=1)
    discovery_per_repo_usd: float = Field(default=0.15, gt=0)
    discovery_max_iterations: int = Field(default=12, ge=1, le=40)


class ModelsConf(_Model):
    triage: str = "claude-haiku-5-5"
    fix: str = "claude-sonnet-5-5"
    hunt: str = "claude-opus-5-5"
    discovery: str = "claude-haiku-5-5"


Effort = Literal["low", "medium", "high", "xhigh", "max"]


def _default_effort() -> dict[str, Effort]:
    return {"claude-haiku-5-5": "low", "claude-sonnet-5-5": "medium", "claude-opus-5-5": "high"}


class AnthropicConf(_Model):
    timeout_s: float = Field(default=600.0, gt=0)
    max_retries: int = Field(default=4, ge=0, le=10)  # 429, 5xx e overloaded, con backoff
    # Su un rifiuto dei classificatori la richiesta riparte su un altro modello lato server
    # (Opus 5.5 e Sonnet 5.5). Il costo si conta al prezzo del modello che ha risposto.
    refusal_fallback: bool = True
    fallback_models: list[str] = Field(
        default_factory=lambda: ["claude-opus-5-5", "claude-sonnet-5-5"]
    )
    effort: dict[str, Effort] = Field(default_factory=_default_effort)


class HuntingConf(_Model):
    repos_per_night: int = Field(default=2, ge=0)
    lookback_days: int = Field(default=7, ge=1)


class FeaturesConf(_Model):
    cve: bool = True
    sast: bool = False
    hunting: bool = False


class VCSConf(_Model):
    branch_prefix: str = Field(default="autofix", pattern=r"^[a-z0-9][a-z0-9._-]*$")
    mr_labels: list[str] = Field(default_factory=lambda: ["autofix"])


class NotifyConf(_Model):
    # URL del webhook come segreto (notify_webhook_url): spesso contiene un token
    webhook: bool = False
    timeout_s: float = Field(default=10.0, gt=0)


def same_user(a: str, b: str) -> bool:
    """Email e username GitLab non distinguono maiuscole e minuscole."""
    return a.casefold() == b.casefold()


class UIConf(_Model):
    default_theme: ThemeName = "neutral"
    themes: dict[str, ThemeName] = Field(default_factory=dict)  # utente (email) -> tema

    def theme_for(self, username: str | None) -> ThemeName:
        if username:
            for user, theme in self.themes.items():
                if same_user(user, username):
                    return theme
        return self.default_theme


class OIDCConf(_Model):
    """Login della dashboard: Authorization Code + PKCE verso GitLab, Keycloak o altro IdP."""

    issuer: str = Field(pattern=r"^https://[^/\s]+(/[^\s]*)?$")
    client_id: str = Field(min_length=1)
    redirect_uri: str = Field(pattern=r"^https://[^/\s]+/[^\s]*$")
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    # GitLab mette lo username in `nickname` (e in `preferred_username` nelle versioni recenti)
    username_claims: list[str] = Field(
        default_factory=lambda: ["preferred_username", "nickname"], min_length=1
    )
    timeout_s: float = Field(default=10.0, gt=0)

    @field_validator("scopes")
    @classmethod
    def _openid_scope(cls, v: list[str]) -> list[str]:
        if "openid" not in v:
            raise ValueError("gli scope OIDC devono includere openid")
        return v


class WebConf(_Model):
    # "email": l'utente è l'email verificata dell'id_token (scope `email`, `email_verified`
    # obbligatorio). "username": il primo di oidc.username_claims.
    user_claim: Literal["email", "username"] = "email"
    allowed_users: list[str] = Field(min_length=1)
    oidc: OIDCConf | None = None
    host: str = "0.0.0.0"  # dentro il container; sull'host la porta va pubblicata su 127.0.0.1
    port: int = Field(default=8080, ge=1, le=65535)
    session_max_age_s: int = Field(default=8 * 3600, ge=300, le=7 * 24 * 3600)
    # Solo sviluppo: utente fisso senza login, accettato solo con `maxtac web --dev` su loopback
    dev_user: str | None = None
    login_rate_limit: int = Field(default=10, ge=1)  # tentativi per finestra, per client
    login_rate_window_s: int = Field(default=300, ge=10)
    # IP o reti del reverse proxy di cui fidarsi per X-Forwarded-For (vuoto: header ignorati)
    trusted_proxies: list[str] = Field(default_factory=list)
    # Build della SPA (frontend/build). Vuoto: quella accanto al sorgente, se esiste
    static_dir: Path | None = None

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.dev_user is not None and not self.is_allowed(self.dev_user):
            raise ValueError("web.dev_user deve stare in web.allowed_users")
        if self.user_claim == "email":
            bad = [u for u in self.allowed_users if "@" not in u]
            if bad:
                raise ValueError(
                    f"web.allowed_users deve contenere email (user_claim=email): {bad}"
                )
            if self.oidc is not None and "email" not in self.oidc.scopes:
                self.oidc.scopes.append("email")
        return self

    def is_allowed(self, user: str) -> bool:
        return any(same_user(u, user) for u in self.allowed_users)


class PriceConf(_Model):
    input: float = Field(ge=0)
    output: float = Field(ge=0)
    cache_read: float = Field(ge=0)
    cache_write: float = Field(ge=0)


class RepoConf(_Model):
    project: str
    languages: list[Language]
    test_command: str
    setup_command: str | None = None
    default_branch: str | None = None
    scan_only: bool = False  # finding tracciati, nessun fix né bug hunting

    @field_validator("project")
    @classmethod
    def _project_format(cls, v: str) -> str:
        if not PROJECT_RE.match(v):
            raise ValueError(f"project deve essere nel formato gruppo/nome, non {v!r}")
        return v


class AppConfig(_Model):
    gitlab: GitLabConf
    schedule: ScheduleConf = ScheduleConf()
    budget: BudgetConf = BudgetConf()
    models: ModelsConf = ModelsConf()
    anthropic: AnthropicConf = AnthropicConf()
    hunting: HuntingConf = HuntingConf()
    features: FeaturesConf = FeaturesConf()
    vcs: VCSConf = VCSConf()
    ui: UIConf = UIConf()
    notify: NotifyConf = NotifyConf()
    web: WebConf | None = None
    sandbox: SandboxConf = SandboxConf()
    scanners: ScannersConf = ScannersConf()
    workdir: Path = Path("/var/lib/autofix/work")
    db_path: Path = Path("/var/lib/autofix/autofix.sqlite3")
    # Repo di fiducia scritti a mano. Si aggiungono quelli scoperti e approvati con
    # `maxtac repos approve` (in caso di conflitto vince questo file).
    repos: list[RepoConf] = Field(default_factory=list)
    prices_usd_per_mtok: dict[str, PriceConf]

    @model_validator(mode="after")
    def _check(self) -> Self:
        missing = [
            m
            for m in (self.models.triage, self.models.fix, self.models.hunt, self.models.discovery)
            if m not in self.prices_usd_per_mtok
        ]
        if missing:
            raise ValueError(f"modelli senza prezzo in prices_usd_per_mtok: {sorted(set(missing))}")
        projects = [r.project for r in self.repos]
        dupes = {p for p in projects if projects.count(p) > 1}
        if dupes:
            raise ValueError(f"repo duplicati: {sorted(dupes)}")
        scopes = self.gitlab.token_scopes()
        uncovered = [r.project for r in self.repos if resolve_token(r.project, scopes) is None]
        if uncovered:
            raise ValueError(f"repo non coperti da nessun token in gitlab.tokens: {uncovered}")
        hosts = [c.host for c in self.sandbox.registry_credentials]
        if len(hosts) != len(set(hosts)):
            raise ValueError("sandbox.registry_credentials: host duplicati")
        bad = registry_conflicts(hosts, self.gitlab.host)
        if bad:
            raise ValueError(
                "sandbox.registry_credentials: il sandbox non riceve mai credenziali "
                f"per GitLab {bad}"
            )
        if self.budget.per_task_usd > self.budget.per_night_usd:
            raise ValueError("per_task_usd non può superare per_night_usd")
        return self

    def semgrep_rulesets(self, extra_languages: Iterable[str] = ()) -> list[str]:
        """Ruleset base più quelli dei linguaggi presenti nei repo (config e approvati).

        Semgrep applica ogni regola solo ai file del suo linguaggio: i ruleset in più costano
        tempo di download, non finding sbagliati.
        """
        langs = {lang for r in self.repos for lang in r.languages} | set(extra_languages)
        sg = self.scanners.semgrep
        extra = [rs for lang in sorted(langs) for rs in sg.by_language.get(lang, [])]
        return list(dict.fromkeys([*sg.rulesets, *extra]))

    def to_repos(self) -> list[RepoConfig]:
        return [
            RepoConfig(
                project=r.project,
                languages=tuple(r.languages),
                test_command=r.test_command,
                setup_command=r.setup_command,
                default_branch=r.default_branch,
                scan_only=r.scan_only,
            )
            for r in self.repos
        ]

    def to_pricing(self) -> Pricing:
        return Pricing(
            {
                name: ModelPrice(p.input, p.output, p.cache_read, p.cache_write)
                for name, p in self.prices_usd_per_mtok.items()
            }
        )

    def to_settings(self, *, dry_run: bool = False) -> PipelineSettings:
        b, f = self.budget, self.features
        kinds = {k for k, on in (("cve", f.cve), ("sast", f.sast), ("bug", f.hunting)) if on}
        return PipelineSettings(
            limits=Limits(
                per_night_usd=b.per_night_usd,
                per_task_usd=b.per_task_usd,
                triage_per_repo_usd=b.triage_per_repo_usd,
                hunting_per_night_usd=b.hunting_per_night_usd,
                max_mrs_per_night=b.max_mrs_per_night,
                max_attempts=b.max_attempts,
                max_iterations=b.max_iterations,
                monthly_credits_usd=b.monthly_credits_usd,
            ),
            models=Models(self.models.triage, self.models.fix, self.models.hunt),
            workdir=self.workdir,
            enabled_kinds=frozenset(kinds),
            hunting_repos_per_night=self.hunting.repos_per_night,
            lookback_days=self.hunting.lookback_days,
            branch_prefix=self.vcs.branch_prefix,
            mr_labels=tuple(self.vcs.mr_labels),
            dry_run=dry_run,
        )


class Secrets(BaseSettings):
    """Letti da /run/secrets/<nome> (Docker secret) o dalle variabili d'ambiente omonime
    (ANTHROPIC_API_KEY, GITLAB_TOKEN, NOTIFY_WEBHOOK_URL, OIDC_CLIENT_SECRET,
    WEB_SESSION_SECRET)."""

    model_config = SettingsConfigDict()  # secrets_dir passato da load_secrets()

    anthropic_api_key: SecretStr | None = None
    gitlab_token: SecretStr | None = None
    notify_webhook_url: SecretStr | None = None
    oidc_client_secret: SecretStr | None = None
    web_session_secret: SecretStr | None = None


SECRETS_DIR = Path("/run/secrets")


TOKENS_DIR = "gitlab_tokens"


def read_token_secret(
    name: str, secrets_dir: Path = SECRETS_DIR, environ: Mapping[str, str] | None = None
) -> str | None:
    """Valore del token `name` di gitlab.tokens, nell'ordine:
    - file `gitlab_tokens/<name>` nella directory dei segreti (il compose la monta da
      `./secrets/gitlab_tokens`: un file per token, senza toccare il compose);
    - Docker secret `gitlab_token_<name>`;
    - variabile d'ambiente GITLAB_TOKEN_<NAME> (`-` diventa `_`)."""
    for path in (secrets_dir / TOKENS_DIR / name, secrets_dir / f"gitlab_token_{name}"):
        if path.is_file():
            value = path.read_text(encoding="utf-8").strip()
            if value:
                return value
    env = os.environ if environ is None else environ
    value = env.get(f"GITLAB_TOKEN_{name}".upper().replace("-", "_"), "").strip()
    return value or None


REGISTRY_CREDENTIALS_DIR = "registry_credentials"


def read_registry_credential(secret: str, secrets_dir: Path = SECRETS_DIR) -> tuple[str, str]:
    """`utente:password` da /run/secrets/registry_credentials/<secret>. Niente spazi né
    virgolette: il valore finisce in un ~/.netrc."""
    path = secrets_dir / REGISTRY_CREDENTIALS_DIR / secret
    if not path.is_file():
        raise FileNotFoundError(f"credenziale mancante: {path}")
    user, sep, password = path.read_text(encoding="utf-8").strip().partition(":")
    if not sep or not user or not password:
        raise ValueError(f"{path}: il formato è utente:password")
    if any(c.isspace() or c in "\"'\\" for c in user + password):
        raise ValueError(f"{path}: utente e password senza spazi né virgolette")
    return user, password


def read_extra_registries(path: Path) -> list[str]:
    """Registry interni dell'allowlist del proxy: uno per riga, `#` per i commenti."""
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = line.split("#", 1)[0].strip()
        if entry:
            out.append(entry)
    return out


def load_secrets(secrets_dir: Path = SECRETS_DIR) -> Secrets:
    """Senza Docker secret (sviluppo, test) valgono solo le variabili d'ambiente."""
    return Secrets(_secrets_dir=secrets_dir if secrets_dir.is_dir() else None)  # type: ignore[call-arg]


def load_config(path: Path) -> AppConfig:
    with path.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return AppConfig.model_validate(raw)
