"""Store SQLite per finding, rotazione del bug hunting e spesa. Un solo file db."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from maxtac.domain.models import Finding, FindingRecord, FindingStatus, RunReport, RunSummary
from maxtac.domain.serialize import report_to_dict

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    project TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    kind TEXT NOT NULL,
    tool TEXT NOT NULL,
    rule TEXT NOT NULL,
    location TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    attempts INTEGER NOT NULL DEFAULT 0,
    reason TEXT NOT NULL DEFAULT '',
    mr_url TEXT,
    branch TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (project, fingerprint)
);
CREATE TABLE IF NOT EXISTS hunting (
    project TEXT PRIMARY KEY,
    last_hunted TEXT NOT NULL,
    hunt_count INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS spend (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    model TEXT NOT NULL,
    usd REAL NOT NULL,
    at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS spend_run ON spend(run_id);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    started_at TEXT,
    finished_at TEXT,
    dry_run INTEGER NOT NULL,
    spent_usd REAL NOT NULL,
    mrs_opened INTEGER NOT NULL,
    aborted TEXT,
    report TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS runs_started ON runs(started_at);
"""


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("datetime senza fuso orario")
    return dt.astimezone(UTC).isoformat()


def connect(path: str | Path) -> sqlite3.Connection:
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), isolation_level=None)  # autocommit
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


class SqliteStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._db = conn

    def get(self, project: str, fingerprint: str) -> FindingRecord | None:
        row = self._db.execute(
            "SELECT * FROM findings WHERE project = ? AND fingerprint = ?", (project, fingerprint)
        ).fetchone()
        if row is None:
            return None
        return FindingRecord(
            fingerprint=row["fingerprint"],
            status=FindingStatus(row["status"]),
            attempts=row["attempts"],
            reason=row["reason"],
            mr_url=row["mr_url"],
            branch=row["branch"],
        )

    def observe(self, project: str, findings: Sequence[Finding], seen_at: datetime) -> None:
        now = _iso(seen_at)
        self._db.executemany(
            """INSERT INTO findings
                   (project, fingerprint, kind, tool, rule, location, severity, first_seen,
                    last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(project, fingerprint) DO UPDATE SET
                   last_seen = excluded.last_seen, severity = excluded.severity""",
            [
                (
                    project,
                    f.fingerprint,
                    f.kind,
                    f.tool,
                    f.rule,
                    f.location,
                    f.severity.name,
                    now,
                    now,
                )
                for f in findings
            ],
        )

    def set_status(
        self,
        project: str,
        fingerprint: str,
        status: FindingStatus,
        reason: str = "",
        *,
        mr_url: str | None = None,
        branch: str | None = None,
    ) -> None:
        self._db.execute(
            """UPDATE findings SET status = ?, reason = ?,
                   mr_url = COALESCE(?, mr_url), branch = COALESCE(?, branch)
               WHERE project = ? AND fingerprint = ?""",
            (status.value, reason, mr_url, branch, project, fingerprint),
        )

    def record_failed_attempt(self, project: str, fingerprint: str, reason: str) -> int:
        row = self._db.execute(
            """UPDATE findings SET attempts = attempts + 1, reason = ?
               WHERE project = ? AND fingerprint = ? RETURNING attempts""",
            (reason, project, fingerprint),
        ).fetchone()
        return int(row["attempts"]) if row else 0

    def last_hunted(self, project: str) -> datetime | None:
        row = self._db.execute(
            "SELECT last_hunted FROM hunting WHERE project = ?", (project,)
        ).fetchone()
        return datetime.fromisoformat(row["last_hunted"]) if row else None

    def mark_hunted(self, project: str, at: datetime) -> None:
        self._db.execute(
            """INSERT INTO hunting (project, last_hunted) VALUES (?, ?)
               ON CONFLICT(project) DO UPDATE SET
                   last_hunted = excluded.last_hunted, hunt_count = hunt_count + 1""",
            (project, _iso(at)),
        )

    def hunt_count(self, project: str) -> int:
        row = self._db.execute(
            "SELECT hunt_count FROM hunting WHERE project = ?", (project,)
        ).fetchone()
        return int(row["hunt_count"]) if row else 0

    def counts_by_status(self) -> dict[str, int]:
        rows = self._db.execute("SELECT status, COUNT(*) AS n FROM findings GROUP BY status")
        return {r["status"]: r["n"] for r in rows}

    def open_mrs(self) -> list[dict[str, Any]]:
        rows = self._db.execute(
            """SELECT project, fingerprint, kind, tool, rule, location, mr_url, branch
               FROM findings
               WHERE status = 'mr_open' ORDER BY last_seen DESC"""
        )
        return [dict(r) for r in rows]


class SqliteBudget:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._db = conn

    def record(self, run_id: str, scope: str, model: str, usd: float, at: datetime) -> None:
        self._db.execute(
            "INSERT INTO spend (run_id, scope, model, usd, at) VALUES (?, ?, ?, ?, ?)",
            (run_id, scope, model, usd, _iso(at)),
        )

    def spent(self, run_id: str, scope: str | None = None) -> float:
        if scope is None:
            row = self._db.execute(
                "SELECT COALESCE(SUM(usd), 0) AS s FROM spend WHERE run_id = ?", (run_id,)
            ).fetchone()
        else:
            row = self._db.execute(
                "SELECT COALESCE(SUM(usd), 0) AS s FROM spend WHERE run_id = ? AND scope = ?",
                (run_id, scope),
            ).fetchone()
        return float(row["s"])

    def spent_month(self, year: int, month: int) -> float:
        prefix = f"{year:04d}-{month:02d}-"
        row = self._db.execute(
            "SELECT COALESCE(SUM(usd), 0) AS s FROM spend WHERE substr(at, 1, 8) = ?", (prefix,)
        ).fetchone()
        return float(row["s"])


def _dt(raw: str | None) -> datetime | None:
    return datetime.fromisoformat(raw) if raw else None


class SqliteRunStore:
    """Storico delle run: una riga per notte con il report completo in JSON."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._db = conn

    def save_run(self, report: RunReport) -> None:
        self._db.execute(
            """INSERT INTO runs
                   (run_id, started_at, finished_at, dry_run, spent_usd, mrs_opened, aborted,
                    report)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(run_id) DO UPDATE SET
                   started_at = excluded.started_at, finished_at = excluded.finished_at,
                   dry_run = excluded.dry_run, spent_usd = excluded.spent_usd,
                   mrs_opened = excluded.mrs_opened, aborted = excluded.aborted,
                   report = excluded.report""",
            (
                report.run_id,
                _iso(report.started_at) if report.started_at else None,
                _iso(report.finished_at) if report.finished_at else None,
                int(report.dry_run),
                report.spent_usd,
                len(report.mrs_opened),
                report.aborted,
                json.dumps(report_to_dict(report), ensure_ascii=False),
            ),
        )

    def recent_runs(self, limit: int) -> list[RunSummary]:
        rows = self._db.execute(
            """SELECT run_id, started_at, finished_at, dry_run, spent_usd, mrs_opened, aborted
               FROM runs ORDER BY COALESCE(started_at, '') DESC, run_id DESC LIMIT ?""",
            (limit,),
        )
        return [
            RunSummary(
                run_id=r["run_id"],
                started_at=_dt(r["started_at"]),
                finished_at=_dt(r["finished_at"]),
                dry_run=bool(r["dry_run"]),
                spent_usd=float(r["spent_usd"]),
                mrs_opened=int(r["mrs_opened"]),
                aborted=r["aborted"],
            )
            for r in rows
        ]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        row = self._db.execute("SELECT report FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            return None
        data: dict[str, Any] = json.loads(row["report"])
        return data
