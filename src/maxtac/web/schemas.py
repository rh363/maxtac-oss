"""Contratto dell'API della dashboard. Lo schema OpenAPI esportato sta in web/openapi.json."""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SeverityName = Literal["info", "low", "medium", "high", "critical"]
StatusName = Literal["new", "ignored", "needs_human", "mr_open"]
KindName = Literal["cve", "sast", "bug"]


class _Out(BaseModel):
    model_config = ConfigDict(extra="ignore")


class Me(_Out):
    username: str
    # "default" per chiunque non abbia un tema assegnato: nessun elenco delle alternative
    theme: str


class MonthSpendOut(_Out):
    label: str
    spent_usd: float
    credits_usd: float
    projected_usd: float


class NightSpendOut(_Out):
    run_id: str | None
    spent_usd: float
    cap_usd: float


class OpenMR(_Out):
    project: str
    kind: str
    rule: str
    location: str
    mr_url: str


class HuntingSlotOut(_Out):
    project: str
    last_hunted: datetime | None
    hunt_count: int
    next_up: bool


class RunSummaryOut(_Out):
    run_id: str
    started_at: datetime | None
    finished_at: datetime | None
    dry_run: bool
    spent_usd: float
    mrs_opened: int
    aborted: str | None


class DashboardOut(_Out):
    month: MonthSpendOut
    night: NightSpendOut
    open_mrs: list[OpenMR]
    findings_by_status: dict[str, int]
    hunting_enabled: bool
    hunting: list[HuntingSlotOut]
    recent_runs: list[RunSummaryOut]
    repos: list[str]
    max_mrs_per_night: int
    hunting_per_night: int
    next_run_at: datetime | None


class FindingOut(_Out):
    project: str
    fingerprint: str
    kind: str
    tool: str
    rule: str
    location: str
    severity: SeverityName
    status: StatusName
    attempts: int
    reason: str
    mr_url: str | None
    first_seen: datetime
    last_seen: datetime


class FindingPage(_Out):
    items: list[FindingOut]
    total: int
    limit: int
    offset: int


class RunList(_Out):
    items: list[RunSummaryOut]
    limit: int
    offset: int


class TaskFinding(_Out):
    fingerprint: str
    kind: str
    tool: str
    rule: str
    location: str
    line: int | None = None
    severity: str


class TaskOut(_Out):
    fingerprint: str
    kind: str
    title: str
    severity: str
    findings: list[TaskFinding]


class FixOut(_Out):
    task: TaskOut
    outcome: str
    cost_usd: float
    detail: str = Field(description="Testo semplice: va mostrato escaped")
    branch: str | None = None
    mr_url: str | None = None
    diff: str = Field(default="", description="Diff unificato, testo semplice")
    test_output: str = ""
    triage_reason: str = ""
    iterations: int | None = Field(default=None, description="Passi del loop dell'agente")
    agent_stop: str | None = None


class TriagedOut(_Out):
    task: TaskOut
    reason: str


class RepoRunOut(_Out):
    project: str
    findings_total: int
    findings_new: int
    skipped_open_mr: int
    hunted: bool
    bugs_found: int
    fixes: list[FixOut]
    ignored: list[TriagedOut]
    needs_human: list[TriagedOut]
    errors: list[str]


class RunDetail(_Out):
    run_id: str
    dry_run: bool
    started_at: datetime | None = None
    finished_at: datetime | None = None
    spent_usd: float
    night_cap_usd: float
    aborted: str | None = None
    mrs_opened: int
    repos: list[RepoRunOut]


class TaskDetail(_Out):
    run_id: str
    project: str
    task: TaskOut
    outcome: str  # un Outcome della pipeline, oppure "ignored" / "needs_human" dal triage
    cost_usd: float = 0.0
    detail: str = ""
    triage_reason: str = ""
    branch: str | None = None
    mr_url: str | None = None
    diff: str = ""
    test_output: str = ""
    iterations: int | None = None
    agent_stop: str | None = None


# --- spesa giornaliera ---


class DaySpendOut(_Out):
    date: date
    triage: float
    fix: float
    hunt: float
    discovery: float
    other: float
    total: float


class MonthPointOut(_Out):
    date: date
    cumulative_usd: float


class SpendSeriesOut(_Out):
    timezone: str
    days: list[DaySpendOut]
    month: list[MonthPointOut]
    cap_usd: float
    credits_usd: float


# --- repository e proposte ---

OriginName = Literal["config", "approved"]
ProposalStatusName = Literal["pending", "superseded", "rejected"]


class RepoOut(_Out):
    project: str
    origin: OriginName
    languages: list[str]
    setup_command: str | None
    test_command: str
    default_branch: str | None
    approved_at: datetime | None
    last_hunted: datetime | None
    hunt_count: int
    rotation: int
    next_up: bool
    findings_by_status: dict[str, int]
    open_mrs: int
    token: str | None = Field(description="Nome del token GitLab che copre il repo; null: nessuno")


class FieldChangeOut(_Out):
    field: str
    active: str | None
    proposed: str | None


class ProposalOut(_Out):
    id: int | None
    project: str
    status: ProposalStatusName
    languages: list[str]
    setup_command: str | None = Field(description="Non fidato: proposto dal contenuto del repo")
    test_command: str = Field(description="Non fidato: proposto dal contenuto del repo")
    default_branch: str | None
    rationale: str
    baseline_ok: bool | None
    baseline_output: str
    duration_s: float
    cost_usd: float
    suspicious: list[str]
    blockers: list[str]
    created_at: datetime
    approve_command: str | None
    token: str | None = Field(description="Nome del token GitLab che userebbe il repo")
    changes: list[FieldChangeOut]


class ReposOut(_Out):
    repos: list[RepoOut]
    proposals: list[ProposalOut]


# --- impostazioni (sola lettura, senza segreti né utenti) ---


class ScheduleOut(_Out):
    timezone: str
    at: str
    next_run_at: datetime


class FeaturesOut(_Out):
    cve: bool
    sast: bool
    hunting: bool


class ModelsOut(_Out):
    triage: str
    fix: str
    hunt: str
    discovery: str


class BudgetOut(_Out):
    monthly_credits_usd: float
    per_night_usd: float
    per_task_usd: float
    triage_per_repo_usd: float
    hunting_per_night_usd: float
    discovery_per_repo_usd: float


class LimitsOut(_Out):
    max_mrs_per_night: int
    max_attempts: int
    max_iterations: int


class HuntingOut(_Out):
    repos_per_night: int
    lookback_days: int


class VCSOut(_Out):
    branch_prefix: str
    mr_labels: list[str]


class PriceOut(_Out):
    model: str
    input: float
    output: float
    cache_read: float
    cache_write: float


TokenStateName = Literal["ok", "expiring", "expired", "unknown", "error"]


class TokenOut(_Out):
    """Un token GitLab all'ultimo controllo dell'orchestrator. Mai il valore."""

    name: str
    scope: list[str] = Field(description="Prefissi di path coperti; vuoto: tutta l'istanza")
    username: str | None
    expires_at: date | None
    state: TokenStateName
    error: str | None
    checked_at: datetime


class SettingsOut(_Out):
    schedule: ScheduleOut
    features: FeaturesOut
    models: ModelsOut
    budget: BudgetOut
    limits: LimitsOut
    hunting: HuntingOut
    vcs: VCSOut
    tokens: list[TokenOut]
    prices: list[PriceOut]
