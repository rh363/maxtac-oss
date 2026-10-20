"""Store SQLite per finding, rotazione del bug hunting e spesa. Un solo file db."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from maxtac.domain.models import Finding, FindingRecord, FindingStatus

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    fingerprint TEXT PRIMARY KEY,
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
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hunting (
    project TEXT PRIMARY KEY,
    last_hunted TEXT NOT NULL
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

    def get(self, fingerprint: str) -> FindingRecord | None:
        row = self._db.execute(
            "SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,)
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

    def observe(self, findings: Sequence[Finding], seen_at: datetime) -> None:
        now = _iso(seen_at)
        self._db.executemany(
            """INSERT INTO findings
                   (fingerprint, kind, tool, rule, location, severity, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(fingerprint) DO UPDATE SET
                   last_seen = excluded.last_seen, severity = excluded.severity""",
            [
                (f.fingerprint, f.kind, f.tool, f.rule, f.location, f.severity.name, now, now)
                for f in findings
            ],
        )

    def set_status(
        self,
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
               WHERE fingerprint = ?""",
            (status.value, reason, mr_url, branch, fingerprint),
        )

    def record_failed_attempt(self, fingerprint: str, reason: str) -> int:
        row = self._db.execute(
            """UPDATE findings SET attempts = attempts + 1, reason = ?
               WHERE fingerprint = ? RETURNING attempts""",
            (reason, fingerprint),
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
               ON CONFLICT(project) DO UPDATE SET last_hunted = excluded.last_hunted""",
            (project, _iso(at)),
        )

    def counts_by_status(self) -> dict[str, int]:
        rows = self._db.execute("SELECT status, COUNT(*) AS n FROM findings GROUP BY status")
        return {r["status"]: r["n"] for r in rows}

    def open_mrs(self) -> list[dict[str, Any]]:
        rows = self._db.execute(
            """SELECT fingerprint, kind, tool, rule, location, mr_url, branch FROM findings
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
