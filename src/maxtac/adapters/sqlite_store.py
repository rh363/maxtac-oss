"""Store SQLite per finding, rotazione del bug hunting e spesa. Un solo file db."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from maxtac.domain.models import (
    LANGUAGES,
    ApprovedRepo,
    Finding,
    FindingQuery,
    FindingRecord,
    FindingRow,
    FindingStatus,
    Language,
    ProposalStatus,
    RepoConfig,
    RepoProposal,
    RunReport,
    RunSummary,
    Severity,
    SpendEntry,
    TokenInfo,
)
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
    detail TEXT NOT NULL DEFAULT '',
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
CREATE INDEX IF NOT EXISTS spend_at ON spend(at);
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
CREATE TABLE IF NOT EXISTS repo_proposals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project TEXT NOT NULL,
    status TEXT NOT NULL,
    languages TEXT NOT NULL,
    setup_command TEXT,
    test_command TEXT NOT NULL,
    default_branch TEXT,
    rationale TEXT NOT NULL,
    baseline_ok INTEGER,
    baseline_output TEXT NOT NULL,
    duration_s REAL NOT NULL,
    cost_usd REAL NOT NULL,
    suspicious TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS repo_proposals_project ON repo_proposals(project, status);
CREATE TABLE IF NOT EXISTS repos (
    project TEXT PRIMARY KEY,
    languages TEXT NOT NULL,
    setup_command TEXT,
    test_command TEXT NOT NULL,
    default_branch TEXT,
    approved_at TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    proposal_id INTEGER,
    scan_only INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS gitlab_tokens (
    name TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    username TEXT,
    expires_at TEXT,
    scopes TEXT,
    error TEXT
);
"""


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("datetime senza fuso orario")
    return dt.astimezone(UTC).isoformat()


def connect(path: str | Path) -> sqlite3.Connection:
    """Connessione dell'orchestrator: crea lo schema.

    Journal in modalità DELETE e non WAL: la dashboard apre lo stesso file da un mount in sola
    lettura, e un lettore WAL deve poter scrivere il file -shm. Con una scrittura per task il
    WAL non porta vantaggi misurabili.
    """
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), isolation_level=None)  # autocommit
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.executescript(SCHEMA)
    _migrate(conn)
    return conn


DETAIL_LIMIT = 2000


def _migrate(conn: sqlite3.Connection) -> None:
    """Colonne aggiunte dopo la prima versione dello schema."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(findings)")}
    if "detail" not in cols:  # fase 6b: ricerca testuale nella dashboard
        conn.execute("ALTER TABLE findings ADD COLUMN detail TEXT NOT NULL DEFAULT ''")
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(repos)")}
    if "scan_only" not in cols:  # repo approvati in sola scansione
        conn.execute("ALTER TABLE repos ADD COLUMN scan_only INTEGER NOT NULL DEFAULT 0")


def _like(text: str) -> str:
    """Pattern LIKE per una ricerca per sottostringa: % e _ dell'utente restano letterali."""
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def connect_readonly(path: str | Path) -> sqlite3.Connection:
    """Connessione della dashboard: sola lettura, nessuna creazione di file o schema."""
    uri = f"{Path(path).resolve().as_uri()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA query_only=ON")
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
                    last_seen, detail)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(project, fingerprint) DO UPDATE SET
                   last_seen = excluded.last_seen, severity = excluded.severity,
                   detail = excluded.detail""",
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
                    f.detail[:DETAIL_LIMIT],
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

    def counts_by_project(self) -> dict[str, dict[str, int]]:
        rows = self._db.execute(
            "SELECT project, status, COUNT(*) AS n FROM findings GROUP BY project, status"
        )
        out: dict[str, dict[str, int]] = {}
        for r in rows:
            out.setdefault(r["project"], {})[r["status"]] = r["n"]
        return out

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

    def list_findings(self, q: FindingQuery) -> tuple[list[FindingRow], int]:
        where, params = [], []
        for col, val in (
            ("project", q.project),
            ("kind", q.kind),
            ("severity", q.severity.name if q.severity is not None else None),
            ("status", q.status.value if q.status is not None else None),
        ):
            if val is not None:
                where.append(f"{col} = ?")
                params.append(val)
        if q.q:
            # LIKE di SQLite ignora già le maiuscole per l'ASCII; lower() copre il resto
            where.append(
                "("
                + " OR ".join(
                    f"lower({c}) LIKE lower(?) ESCAPE '\\'"
                    for c in ("rule", "location", "detail", "tool")
                )
                + ")"
            )
            params += [_like(q.q)] * 4
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        total = self._db.execute(f"SELECT COUNT(*) AS n FROM findings {clause}", params).fetchone()
        rank = " ".join(f"WHEN '{s.name}' THEN {int(s)}" for s in Severity)
        rows = self._db.execute(
            f"""SELECT * FROM findings {clause}
                ORDER BY CASE severity {rank} ELSE -1 END DESC, last_seen DESC, fingerprint
                LIMIT ? OFFSET ?""",
            [*params, q.limit, q.offset],
        )
        return [
            FindingRow(
                project=r["project"],
                fingerprint=r["fingerprint"],
                kind=r["kind"],
                tool=r["tool"],
                rule=r["rule"],
                location=r["location"],
                severity=Severity.parse(r["severity"]),
                status=FindingStatus(r["status"]),
                attempts=r["attempts"],
                reason=r["reason"],
                mr_url=r["mr_url"],
                first_seen=datetime.fromisoformat(r["first_seen"]),
                last_seen=datetime.fromisoformat(r["last_seen"]),
                detail=r["detail"],
            )
            for r in rows
        ], int(total["n"])


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

    def ledger(self, since: datetime) -> list[SpendEntry]:
        rows = self._db.execute(
            "SELECT at, scope, usd FROM spend WHERE at >= ? ORDER BY at, id", (_iso(since),)
        )
        return [SpendEntry(datetime.fromisoformat(r["at"]), r["scope"], r["usd"]) for r in rows]

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

    def recent_runs(self, limit: int, offset: int = 0) -> list[RunSummary]:
        rows = self._db.execute(
            """SELECT run_id, started_at, finished_at, dry_run, spent_usd, mrs_opened, aborted
               FROM runs ORDER BY COALESCE(started_at, '') DESC, run_id DESC LIMIT ? OFFSET ?""",
            (limit, offset),
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


def _languages(raw: str) -> tuple[Language, ...]:
    return tuple(lang for lang in LANGUAGES if lang in json.loads(raw))


class SqliteRepoRegistry:
    """Proposte dell'autodiscovery e repo approvati."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._db = conn

    @staticmethod
    def _proposal(r: sqlite3.Row) -> RepoProposal:
        return RepoProposal(
            id=int(r["id"]),
            project=r["project"],
            status=ProposalStatus(r["status"]),
            languages=_languages(r["languages"]),
            setup_command=r["setup_command"],
            test_command=r["test_command"],
            default_branch=r["default_branch"],
            rationale=r["rationale"],
            baseline_ok=None if r["baseline_ok"] is None else bool(r["baseline_ok"]),
            baseline_output=r["baseline_output"],
            duration_s=float(r["duration_s"]),
            cost_usd=float(r["cost_usd"]),
            suspicious=tuple(json.loads(r["suspicious"])),
            created_at=datetime.fromisoformat(r["created_at"]),
        )

    def save_proposal(self, proposal: RepoProposal) -> int:
        p = proposal
        self._db.execute("BEGIN")
        try:
            self._db.execute(
                "UPDATE repo_proposals SET status = ? WHERE project = ? AND status = ?",
                (ProposalStatus.SUPERSEDED.value, p.project, ProposalStatus.PENDING.value),
            )
            row = self._db.execute(
                """INSERT INTO repo_proposals
                       (project, status, languages, setup_command, test_command, default_branch,
                        rationale, baseline_ok, baseline_output, duration_s, cost_usd,
                        suspicious, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id""",
                (
                    p.project,
                    ProposalStatus.PENDING.value,
                    json.dumps(list(p.languages)),
                    p.setup_command,
                    p.test_command,
                    p.default_branch,
                    p.rationale,
                    None if p.baseline_ok is None else int(p.baseline_ok),
                    p.baseline_output,
                    p.duration_s,
                    p.cost_usd,
                    json.dumps(list(p.suspicious), ensure_ascii=False),
                    _iso(p.created_at),
                ),
            ).fetchone()
            self._db.execute("COMMIT")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        return int(row["id"])

    def pending_proposal(self, project: str) -> RepoProposal | None:
        row = self._db.execute(
            "SELECT * FROM repo_proposals WHERE project = ? AND status = ? ORDER BY id DESC",
            (project, ProposalStatus.PENDING.value),
        ).fetchone()
        return self._proposal(row) if row else None

    def list_proposals(self, status: ProposalStatus | None = None) -> list[RepoProposal]:
        if status is None:
            rows = self._db.execute("SELECT * FROM repo_proposals ORDER BY id DESC")
        else:
            rows = self._db.execute(
                "SELECT * FROM repo_proposals WHERE status = ? ORDER BY id DESC", (status.value,)
            )
        return [self._proposal(r) for r in rows]

    def approve(self, proposal: RepoProposal, repo: RepoConfig, by: str, at: datetime) -> None:
        self._db.execute("BEGIN")
        try:
            self._db.execute(
                """INSERT INTO repos
                       (project, languages, setup_command, test_command, default_branch,
                        approved_at, approved_by, proposal_id, scan_only)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(project) DO UPDATE SET
                       languages = excluded.languages, setup_command = excluded.setup_command,
                       test_command = excluded.test_command,
                       default_branch = excluded.default_branch,
                       approved_at = excluded.approved_at, approved_by = excluded.approved_by,
                       proposal_id = excluded.proposal_id,
                       scan_only = excluded.scan_only""",
                (
                    repo.project,
                    json.dumps(list(repo.languages)),
                    repo.setup_command,
                    repo.test_command,
                    repo.default_branch,
                    _iso(at),
                    by,
                    proposal.id,
                    int(repo.scan_only),
                ),
            )
            if proposal.id is not None:
                self._db.execute(
                    "UPDATE repo_proposals SET status = ? WHERE id = ?",
                    (ProposalStatus.APPROVED.value, proposal.id),
                )
            self._db.execute("COMMIT")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise

    def reject(self, project: str) -> bool:
        cur = self._db.execute(
            "UPDATE repo_proposals SET status = ? WHERE project = ? AND status = ?",
            (ProposalStatus.REJECTED.value, project, ProposalStatus.PENDING.value),
        )
        return cur.rowcount > 0

    def remove(self, project: str) -> bool:
        return self._db.execute("DELETE FROM repos WHERE project = ?", (project,)).rowcount > 0

    @staticmethod
    def _approved(r: sqlite3.Row) -> ApprovedRepo:
        return ApprovedRepo(
            repo=RepoConfig(
                project=r["project"],
                languages=_languages(r["languages"]),
                test_command=r["test_command"],
                setup_command=r["setup_command"],
                default_branch=r["default_branch"],
                scan_only=bool(r["scan_only"]),
            ),
            approved_at=datetime.fromisoformat(r["approved_at"]),
            approved_by=r["approved_by"],
            proposal_id=r["proposal_id"],
        )

    def approved(self, project: str) -> ApprovedRepo | None:
        row = self._db.execute("SELECT * FROM repos WHERE project = ?", (project,)).fetchone()
        return self._approved(row) if row else None

    def approved_repos(self) -> list[ApprovedRepo]:
        return [self._approved(r) for r in self._db.execute("SELECT * FROM repos ORDER BY project")]


class SqliteTokenRegistry:
    """Ultimo stato noto dei token GitLab, per `status` e per la dashboard (che non ha token)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._db = conn

    def save_tokens(self, infos: Sequence[TokenInfo]) -> None:
        """Sostituisce l'elenco: i token tolti dalla config spariscono anche da qui."""
        self._db.execute("BEGIN")
        try:
            self._db.execute("DELETE FROM gitlab_tokens")
            self._db.executemany(
                "INSERT INTO gitlab_tokens VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        t.name,
                        json.dumps(list(t.scope)),
                        _iso(t.checked_at),
                        t.username,
                        t.expires_at.isoformat() if t.expires_at else None,
                        None if t.scopes is None else json.dumps(list(t.scopes)),
                        t.error,
                    )
                    for t in infos
                ],
            )
            self._db.execute("COMMIT")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise

    def tokens(self) -> list[TokenInfo]:
        try:
            rows = self._db.execute("SELECT * FROM gitlab_tokens ORDER BY name").fetchall()
        except sqlite3.OperationalError:  # db di una versione precedente, aperto in sola lettura
            return []
        return [
            TokenInfo(
                name=r["name"],
                scope=tuple(json.loads(r["scope"])),
                checked_at=datetime.fromisoformat(r["checked_at"]),
                username=r["username"],
                expires_at=date.fromisoformat(r["expires_at"]) if r["expires_at"] else None,
                scopes=None if r["scopes"] is None else tuple(json.loads(r["scopes"])),
                error=r["error"],
            )
            for r in rows
        ]
