"""Config di fiducia: un file YAML dell'orchestrator. I segreti stanno nei Docker secret."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from maxtac.domain.budget import ModelPrice, Pricing
from maxtac.domain.models import RepoConfig
from maxtac.services.pipeline import Limits, Models, PipelineSettings

ThemeName = Literal["neutral", "cyberpunk"]
PROJECT_RE = re.compile(r"^[\w.-]+(/[\w.-]+)+$")
DEFAULT_CONFIG_PATH = Path("/etc/autofix/config.yaml")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GitLabConf(_Model):
    url: str = Field(pattern=r"^https://[^/\s]+(/[^\s]*)?$")
    bot_username: str
    bot_name: str = "Autofix Bot"
    bot_email: str | None = None  # default: <bot_username>@noreply.<host di GitLab>

    def commit_email(self) -> str:
        host = self.url.split("://", 1)[1].split("/", 1)[0]
        return self.bot_email or f"{self.bot_username}@noreply.{host}"


class SandboxConf(_Model):
    image: str = "autofix-sandbox:latest"
    network: str = "autofix_sandbox"
    proxy_url: str = "http://proxy:3128"
    user: str = Field(default="1000:1000", pattern=r"^[1-9]\d*(:[1-9]\d*)?$")  # mai root
    mem_limit: str = Field(default="4g", pattern=r"^\d+[kmg]$")
    cpus: float = Field(default=2.0, gt=0, le=64)
    pids_limit: int = Field(default=512, ge=64)
    tmp_size: str = Field(default="1g", pattern=r"^\d+[kmg]$")
    home_size: str = Field(default="4g", pattern=r"^\d+[kmg]$")


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


class ModelsConf(_Model):
    triage: str = "claude-haiku-5-5"
    fix: str = "claude-sonnet-5-5"
    hunt: str = "claude-opus-5-5"


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


class UIConf(_Model):
    default_theme: ThemeName = "neutral"
    themes: dict[str, ThemeName] = Field(default_factory=dict)

    def theme_for(self, username: str | None) -> ThemeName:
        if username and username in self.themes:
            return self.themes[username]
        return self.default_theme


class OIDCConf(_Model):
    """Login della dashboard: Authorization Code + PKCE verso GitLab, Keycloak o altro IdP."""

    issuer: str = Field(pattern=r"^https://[^/\s]+(/[^\s]*)?$")
    client_id: str = Field(min_length=1)
    redirect_uri: str = Field(pattern=r"^https://[^/\s]+/[^\s]*$")
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile"])
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

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.dev_user is not None and self.dev_user not in self.allowed_users:
            raise ValueError("web.dev_user deve stare in web.allowed_users")
        return self


class PriceConf(_Model):
    input: float = Field(ge=0)
    output: float = Field(ge=0)
    cache_read: float = Field(ge=0)
    cache_write: float = Field(ge=0)


class RepoConf(_Model):
    project: str
    languages: list[Literal["python", "go", "javascript", "typescript"]]
    test_command: str
    setup_command: str | None = None
    default_branch: str | None = None

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
    repos: list[RepoConf] = Field(min_length=1)
    prices_usd_per_mtok: dict[str, PriceConf]

    @model_validator(mode="after")
    def _check(self) -> Self:
        missing = [
            m
            for m in (self.models.triage, self.models.fix, self.models.hunt)
            if m not in self.prices_usd_per_mtok
        ]
        if missing:
            raise ValueError(f"modelli senza prezzo in prices_usd_per_mtok: {sorted(set(missing))}")
        projects = [r.project for r in self.repos]
        dupes = {p for p in projects if projects.count(p) > 1}
        if dupes:
            raise ValueError(f"repo duplicati: {sorted(dupes)}")
        if self.budget.per_task_usd > self.budget.per_night_usd:
            raise ValueError("per_task_usd non può superare per_night_usd")
        return self

    def semgrep_rulesets(self) -> list[str]:
        """Ruleset base più quelli dei linguaggi presenti nei repo configurati.

        Semgrep applica ogni regola solo ai file del suo linguaggio: i ruleset in più costano
        tempo di download, non finding sbagliati.
        """
        langs = {lang for r in self.repos for lang in r.languages}
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


def load_secrets(secrets_dir: Path = SECRETS_DIR) -> Secrets:
    """Senza Docker secret (sviluppo, test) valgono solo le variabili d'ambiente."""
    return Secrets(_secrets_dir=secrets_dir if secrets_dir.is_dir() else None)  # type: ignore[call-arg]


def load_config(path: Path) -> AppConfig:
    with path.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return AppConfig.model_validate(raw)
