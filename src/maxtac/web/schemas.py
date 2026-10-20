"""Contratto dell'API della dashboard. Lo schema OpenAPI esportato sta in web/openapi.json."""

from __future__ import annotations

from datetime import datetime
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
