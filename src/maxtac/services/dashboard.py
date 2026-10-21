"""Letture per la dashboard web: solo query sulle porte, nessuna scrittura."""

from __future__ import annotations

import calendar
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from maxtac.domain.models import (
    FindingQuery,
    FindingRow,
    FindingStatus,
    ProposalStatus,
    RepoConfig,
    RepoProposal,
    RunSummary,
    SpendEntry,
)
from maxtac.domain.policy import (
    approval_blockers,
    next_run_at,
    pick_hunting_repos,
    spend_category,
    truncate,
)
from maxtac.domain.ports import BudgetPort, FindingStore, RepoRegistry, RunStore

PROPOSALS_LIMIT = 50
CLI = "autofix"  # alias neutro del comando: la dashboard lo mostra a tutti gli utenti
BASELINE_LIMIT = 4000


@dataclass(frozen=True)
class MonthSpend:
    label: str  # YYYY-MM
    spent_usd: float
    credits_usd: float
    projected_usd: float


@dataclass(frozen=True)
class NightSpend:
    run_id: str | None
    spent_usd: float
    cap_usd: float


@dataclass(frozen=True)
class HuntingSlot:
    project: str
    last_hunted: datetime | None
    hunt_count: int
    next_up: bool  # tra i repo della prossima notte


@dataclass(frozen=True)
class Dashboard:
    month: MonthSpend
    night: NightSpend
    open_mrs: list[dict[str, Any]]
    findings_by_status: dict[str, int]
    hunting: list[HuntingSlot]
    hunting_enabled: bool
    recent_runs: list[RunSummary]
    repos: list[str]
    max_mrs_per_night: int
    hunting_per_night: int
    next_run_at: datetime | None


@dataclass(frozen=True)
class DaySpend:
    date: date
    triage: float = 0.0
    fix: float = 0.0
    hunt: float = 0.0
    discovery: float = 0.0
    other: float = 0.0

    @property
    def total(self) -> float:
        return self.triage + self.fix + self.hunt + self.discovery + self.other


@dataclass(frozen=True)
class MonthPoint:
    date: date
    cumulative_usd: float


@dataclass(frozen=True)
class SpendSeries:
    timezone: str
    days: list[DaySpend]
    month: list[MonthPoint]  # cumulato dal primo del mese a oggi
    cap_usd: float
    credits_usd: float


@dataclass(frozen=True)
class RepoView:
    project: str
    origin: str  # "config" (config.yaml) o "approved" (autodiscovery approvata da CLI)
    languages: list[str]
    setup_command: str | None
    test_command: str
    default_branch: str | None
    approved_at: datetime | None
    last_hunted: datetime | None
    hunt_count: int
    rotation: int  # posizione nella rotazione del bug hunting, da 1
    next_up: bool
    findings_by_status: dict[str, int]
    open_mrs: int


@dataclass(frozen=True)
class FieldChange:
    field: str
    active: str | None
    proposed: str | None


@dataclass(frozen=True)
class ProposalView:
    id: int | None
    project: str
    status: str
    languages: list[str]
    setup_command: str | None
    test_command: str
    default_branch: str | None
    rationale: str
    baseline_ok: bool | None
    baseline_output: str
    duration_s: float
    cost_usd: float
    suspicious: list[str]
    blockers: list[str]
    created_at: datetime
    approve_command: str | None  # solo per le proposte in attesa
    changes: list[FieldChange] = field(default_factory=list)


@dataclass(frozen=True)
class ReposPage:
    repos: list[RepoView]
    proposals: list[ProposalView]


def aggregate_daily(
    entries: Iterable[SpendEntry], *, start: date, end: date, tz: str
) -> list[DaySpend]:
    """Spesa per giorno locale (fuso `tz`) da `start` a `end` inclusi, giorni vuoti a zero."""
    zone = ZoneInfo(tz)
    sums: dict[date, dict[str, float]] = {}
    for e in entries:
        day = e.at.astimezone(zone).date()
        if start <= day <= end:
            bucket = sums.setdefault(day, {})
            cat = spend_category(e.scope)
            bucket[cat] = bucket.get(cat, 0.0) + e.usd
    out = []
    d = start
    while d <= end:
        out.append(DaySpend(d, **{k: round(v, 6) for k, v in sums.get(d, {}).items()}))
        d += timedelta(days=1)
    return out


def _changes(active: RepoConfig | None, p: RepoProposal) -> list[FieldChange]:
    if active is None:
        return []
    pairs = (
        ("languages", ", ".join(active.languages), ", ".join(p.languages)),
        ("setup_command", active.setup_command, p.setup_command),
        ("test_command", active.test_command, p.test_command),
    )
    return [FieldChange(name, a, b) for name, a, b in pairs if a != b]


class Scrubber:
    """Toglie dai testi serviti i path dell'host (workdir, db) e i link che non sono di GitLab."""

    def __init__(self, host_paths: Sequence[str], gitlab_url: str) -> None:
        self._paths = sorted({p.rstrip("/") for p in host_paths if p and p != "/"}, key=len)[::-1]
        self._gitlab = gitlab_url.rstrip("/") + "/"

    def text(self, value: str) -> str:
        for p in self._paths:
            value = value.replace(p, "<workdir>")
        return value

    def url(self, value: str | None) -> str | None:
        return value if value and value.startswith(self._gitlab) else None

    def tree(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.tree(v) for v in value]
        if isinstance(value, dict):
            return {k: (self.url(v) if k == "mr_url" else self.tree(v)) for k, v in value.items()}
        return value


@dataclass
class DashboardService:
    store: FindingStore
    runs: RunStore
    budget: BudgetPort
    repos: Sequence[RepoConfig]
    credits_usd: float
    night_cap_usd: float
    hunting_enabled: bool
    hunting_per_night: int
    scrub: Scrubber
    clock: Callable[[], datetime]
    max_mrs_per_night: int = 3
    schedule_at: str | None = None  # HH:MM, ora locale di `schedule_tz`
    schedule_tz: str = "Europe/Rome"
    registry: RepoRegistry | None = None
    config_projects: frozenset[str] = frozenset()  # repo definiti in config.yaml

    def dashboard(self, recent: int = 10) -> Dashboard:
        now = self.clock()
        spent = self.budget.spent_month(now.year, now.month)
        days = calendar.monthrange(now.year, now.month)[1]
        runs = self.runs.recent_runs(recent)
        last = runs[0] if runs else None
        mrs: dict[str, dict[str, Any]] = {}
        for row in self.store.open_mrs():  # una MR può coprire più CVE dello stesso package
            url = self.scrub.url(row.get("mr_url"))
            if url and url not in mrs:
                mrs[url] = {
                    "project": row["project"],
                    "kind": row["kind"],
                    "rule": row["rule"],
                    "location": row["location"],
                    "mr_url": url,
                }
        next_up = (
            {
                r.project
                for r in pick_hunting_repos(
                    self.repos,
                    self.store.last_hunted,
                    self.hunting_per_night,
                    self.store.hunt_count,
                )
            }
            if self.hunting_enabled
            else set()
        )
        hunting = [
            HuntingSlot(
                r.project,
                self.store.last_hunted(r.project),
                self.store.hunt_count(r.project),
                r.project in next_up,
            )
            for r in self.repos
        ]
        counts = {s.value: 0 for s in FindingStatus} | self.store.counts_by_status()
        return Dashboard(
            month=MonthSpend(
                now.strftime("%Y-%m"),
                round(spent, 6),
                self.credits_usd,
                round(spent / now.day * days, 6),
            ),
            night=NightSpend(
                last.run_id if last else None,
                last.spent_usd if last else 0.0,
                self.night_cap_usd,
            ),
            open_mrs=list(mrs.values()),
            findings_by_status=counts,
            hunting=hunting,
            hunting_enabled=self.hunting_enabled,
            recent_runs=runs,
            repos=[r.project for r in self.repos],
            max_mrs_per_night=self.max_mrs_per_night,
            hunting_per_night=self.hunting_per_night,
            next_run_at=(
                next_run_at(now, self.schedule_at, self.schedule_tz) if self.schedule_at else None
            ),
        )

    def findings(self, q: FindingQuery) -> tuple[list[FindingRow], int]:
        rows, total = self.store.list_findings(q)
        return [
            FindingRow(
                **{
                    **r.__dict__,
                    "reason": self.scrub.text(r.reason),
                    "mr_url": self.scrub.url(r.mr_url),
                }
            )
            for r in rows
        ], total

    def recent_runs(self, limit: int, offset: int) -> list[RunSummary]:
        return self.runs.recent_runs(limit, offset)

    def run(self, run_id: str) -> dict[str, Any] | None:
        data = self.runs.get_run(run_id)
        return None if data is None else dict(self.scrub.tree(data))

    def task(self, run_id: str, fingerprint: str, project: str | None) -> dict[str, Any] | None:
        """Un task di una run: esito del fix, oppure ignorato o passato a un umano dal triage."""
        data = self.run(run_id)
        if data is None:
            return None
        for repo in data.get("repos", []):
            if project is not None and repo.get("project") != project:
                continue
            for fx in repo.get("fixes", []):
                if fx["task"]["fingerprint"] == fingerprint:
                    return {"run_id": run_id, "project": repo["project"], **fx}
            for status, key in (("ignored", "ignored"), ("needs_human", "needs_human")):
                for item in repo.get(key, []):
                    if item["task"]["fingerprint"] == fingerprint:
                        return {
                            "run_id": run_id,
                            "project": repo["project"],
                            "task": item["task"],
                            "outcome": status,
                            "triage_reason": item["reason"],
                        }
        return None

    # --- spesa giornaliera ---

    def daily_spend(self, days: int) -> SpendSeries:
        zone = ZoneInfo(self.schedule_tz)
        today = self.clock().astimezone(zone).date()
        start = today - timedelta(days=days - 1)
        first = today.replace(day=1)
        since = datetime.combine(min(start, first), time(), tzinfo=zone)
        entries = self.budget.ledger(since)
        window = aggregate_daily(entries, start=start, end=today, tz=self.schedule_tz)
        month, total = [], 0.0
        for d in aggregate_daily(entries, start=first, end=today, tz=self.schedule_tz):
            total += d.total
            month.append(MonthPoint(d.date, round(total, 6)))
        return SpendSeries(self.schedule_tz, window, month, self.night_cap_usd, self.credits_usd)

    # --- repository e proposte dell'autodiscovery ---

    def repos_page(self) -> ReposPage:
        order = pick_hunting_repos(
            self.repos, self.store.last_hunted, len(self.repos), self.store.hunt_count
        )
        rotation = {r.project: i + 1 for i, r in enumerate(order)}
        tonight = (
            {r.project for r in order[: self.hunting_per_night]} if self.hunting_enabled else set()
        )
        counts = self.store.counts_by_project()
        mrs: dict[str, set[str]] = {}
        for row in self.store.open_mrs():
            url = self.scrub.url(row.get("mr_url"))
            if url:
                mrs.setdefault(row["project"], set()).add(url)
        repos = []
        for r in self.repos:
            approved = None
            if r.project not in self.config_projects and self.registry is not None:
                approved = self.registry.approved(r.project)
            repos.append(
                RepoView(
                    project=r.project,
                    origin="config" if r.project in self.config_projects else "approved",
                    languages=list(r.languages),
                    setup_command=self.scrub.text(r.setup_command) if r.setup_command else None,
                    test_command=self.scrub.text(r.test_command),
                    default_branch=r.default_branch,
                    approved_at=approved.approved_at if approved else None,
                    last_hunted=self.store.last_hunted(r.project),
                    hunt_count=self.store.hunt_count(r.project),
                    rotation=rotation[r.project],
                    next_up=r.project in tonight,
                    findings_by_status={s.value: 0 for s in FindingStatus}
                    | counts.get(r.project, {}),
                    open_mrs=len(mrs.get(r.project, set())),
                )
            )
        return ReposPage(repos, self._proposals())

    def _proposals(self) -> list[ProposalView]:
        if self.registry is None:
            return []
        active = {r.project: r for r in self.repos}
        shown = [
            p for p in self.registry.list_proposals() if p.status is not ProposalStatus.APPROVED
        ]
        shown.sort(key=lambda p: (p.created_at, p.id or 0), reverse=True)
        out = []
        for p in shown[:PROPOSALS_LIMIT]:
            blockers = approval_blockers(p)
            command = None
            if p.status is ProposalStatus.PENDING:
                command = f"{CLI} repos approve {p.project}" + (" --force" if blockers else "")
            out.append(
                ProposalView(
                    id=p.id,
                    project=p.project,
                    status=p.status.value,
                    languages=list(p.languages),
                    setup_command=self.scrub.text(p.setup_command) if p.setup_command else None,
                    test_command=self.scrub.text(p.test_command),
                    default_branch=p.default_branch,
                    rationale=self.scrub.text(p.rationale),
                    baseline_ok=p.baseline_ok,
                    baseline_output=truncate(self.scrub.text(p.baseline_output), BASELINE_LIMIT),
                    duration_s=p.duration_s,
                    cost_usd=p.cost_usd,
                    suspicious=[self.scrub.text(x) for x in p.suspicious],
                    blockers=[self.scrub.text(x) for x in blockers],
                    created_at=p.created_at,
                    approve_command=command,
                    changes=_changes(active.get(p.project), p),
                )
            )
        return out
