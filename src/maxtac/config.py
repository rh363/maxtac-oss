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
    url: str
    bot_username: str


class ScheduleConf(_Model):
    timezone: str = "Europe/Rome"
    at: str = Field(default="02:30", pattern=r"^([01]\d|2[0-3]):[0-5]\d$")


class BudgetConf(_Model):
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


class UIConf(_Model):
    default_theme: ThemeName = "neutral"
    themes: dict[str, ThemeName] = Field(default_factory=dict)

    def theme_for(self, username: str | None) -> ThemeName:
        if username and username in self.themes:
            return self.themes[username]
        return self.default_theme


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
    hunting: HuntingConf = HuntingConf()
    features: FeaturesConf = FeaturesConf()
    vcs: VCSConf = VCSConf()
    ui: UIConf = UIConf()
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
    """Letti da /run/secrets/<nome> (Docker secret) o da ANTHROPIC_API_KEY e GITLAB_TOKEN."""

    model_config = SettingsConfigDict(secrets_dir="/run/secrets")

    anthropic_api_key: SecretStr | None = None
    gitlab_token: SecretStr | None = None


def load_config(path: Path) -> AppConfig:
    with path.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return AppConfig.model_validate(raw)
