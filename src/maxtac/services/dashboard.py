"""Letture per la dashboard web: solo query sulle porte, nessuna scrittura."""

from __future__ import annotations

import calendar
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from maxtac.domain.models import FindingQuery, FindingRow, FindingStatus, RepoConfig, RunSummary
from maxtac.domain.policy import next_run_at, pick_hunting_repos
from maxtac.domain.ports import BudgetPort, FindingStore, RunStore


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
