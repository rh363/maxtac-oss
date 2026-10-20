"""Modelli del dominio. Nessun import di GitLab, Docker o Anthropic."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Any, Literal

FindingKind = Literal["cve", "sast", "bug"]


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, raw: str | None) -> Severity:
        """Normalizza le severità dei vari scanner (WARNING, moderate, ERROR...)."""
        aliases = {
            "": cls.INFO,
            "unknown": cls.INFO,
            "note": cls.INFO,
            "warning": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "error": cls.HIGH,
            "important": cls.HIGH,
        }
        key = (raw or "").strip().lower()
        if key in aliases:
            return aliases[key]
        try:
            return cls[key.upper()]
        except KeyError:
            return cls.INFO


@dataclass(frozen=True)
class Finding:
    kind: FindingKind
    tool: str  # osv-scanner, semgrep, hunter...
    rule: str  # GHSA-xxxx, python.lang.security..., ecc.
    location: str  # path del file o package@versione
    severity: Severity
    detail: str
    line: int | None = None  # informativo: non entra nel fingerprint

    @property
    def fingerprint(self) -> str:
        raw = f"{self.kind}|{self.tool}|{self.rule}|{self.location}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def package(self) -> str:
        """Per le CVE la location è `package@versione`: il package senza versione."""
        return self.location.rsplit("@", 1)[0]


@dataclass(frozen=True)
class Task:
    """Unità di lavoro del fix agent: una MR per task."""

    kind: FindingKind
    key: str  # package per le CVE, fingerprint del finding per SAST e bug
    findings: tuple[Finding, ...]

    @property
    def fingerprint(self) -> str:
        if self.kind != "cve" and len(self.findings) == 1:
            return self.findings[0].fingerprint
        raw = f"task|{self.kind}|{self.key}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def severity(self) -> Severity:
        return max(f.severity for f in self.findings)

    @property
    def tools(self) -> frozenset[str]:
        return frozenset(f.tool for f in self.findings)

    @property
    def title(self) -> str:
        if self.kind == "cve":
            rules = ", ".join(sorted({f.rule for f in self.findings}))
            return f"Aggiorna {self.key} ({rules})"
        f = self.findings[0]
        if self.kind == "bug":  # la regola è un simbolo: il titolo del modello è più leggibile
            what = f.detail.splitlines()[0][:100] if f.detail.strip() else f.rule
            return f"Correggi {what} in {f.location}"
        return f"Correggi {f.rule} in {f.location}"


class Decision(StrEnum):
    FIX = "fix"
    IGNORE = "ignore"
    NEEDS_HUMAN = "needs_human"


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    reason: str


class FindingStatus(StrEnum):
    NEW = "new"
    IGNORED = "ignored"
    NEEDS_HUMAN = "needs_human"
    MR_OPEN = "mr_open"


@dataclass(frozen=True)
class FindingRecord:
    fingerprint: str
    status: FindingStatus
    attempts: int  # tentativi di fix falliti
    reason: str = ""
    mr_url: str | None = None
    branch: str | None = None


@dataclass(frozen=True)
class RepoConfig:
    """Config di fiducia del repo: viene dal file dell'orchestrator, mai dal repo."""

    project: str  # gruppo/nome su GitLab
    languages: tuple[str, ...]
    test_command: str
    setup_command: str | None = None
    default_branch: str | None = None  # None = quello di GitLab

    @property
    def slug(self) -> str:
        return self.project.replace("/", "__")


@dataclass(frozen=True)
class Checkout:
    repo: RepoConfig
    worktree: Path  # unica directory montata nel sandbox
    gitdir: Path  # fuori dal mount del sandbox
    base_branch: str
    base_sha: str


@dataclass(frozen=True)
class FileChange:
    path: str
    status: Literal["added", "modified", "deleted", "renamed"]


@dataclass(frozen=True)
class ExecResult:
    code: int
    output: str

    @property
    def ok(self) -> bool:
        return self.code == 0


# --- Tipi della conversazione con il modello (indipendenti dall'SDK) ---


@dataclass(frozen=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    args: dict[str, Any]


@dataclass(frozen=True)
class ToolResult:
    call_id: str
    content: str
    is_error: bool = False


@dataclass(frozen=True)
class UserText:
    text: str


@dataclass(frozen=True)
class ToolResults:
    results: tuple[ToolResult, ...]


@dataclass(frozen=True)
class AssistantTurn:
    text: str
    tool_calls: tuple[ToolCall, ...]
    stop_reason: Literal["end_turn", "tool_use", "max_tokens", "refusal", "other"]
    usage: Usage
    model: str
    # Blocchi originali del provider (thinking compresi), da rimandare identici al turno dopo.
    # Il dominio non li legge: servono solo all'adapter.
    raw: tuple[Any, ...] = ()


Message = UserText | ToolResults | AssistantTurn


@dataclass(frozen=True)
class StructuredResult:
    data: dict[str, Any]
    usage: Usage
    model: str


# --- Esiti e report ---


class Outcome(StrEnum):
    MR_OPENED = "mr_opened"
    DRY_RUN = "dry_run"  # fix verificato, niente push né MR
    NEEDS_HUMAN = "needs_human"
    VERIFY_FAILED = "verify_failed"
    AGENT_FAILED = "agent_failed"
    BUDGET_EXHAUSTED = "budget_exhausted"
    ERROR = "error"


@dataclass(frozen=True)
class FixResult:
    task: Task
    outcome: Outcome
    cost_usd: float
    detail: str = ""
    branch: str | None = None
    mr_url: str | None = None
    diff: str = ""


@dataclass
class RepoReport:
    project: str
    findings_total: int = 0
    findings_new: int = 0
    ignored: list[tuple[Task, str]] = field(default_factory=list)
    needs_human: list[tuple[Task, str]] = field(default_factory=list)
    skipped_open_mr: int = 0
    fixes: list[FixResult] = field(default_factory=list)
    hunted: bool = False
    bugs_found: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class RunReport:
    run_id: str
    dry_run: bool
    repos: list[RepoReport] = field(default_factory=list)
    spent_usd: float = 0.0
    night_cap_usd: float = 0.0
    aborted: str | None = None  # motivo per cui la notte si è fermata prima (es. crediti finiti)
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @property
    def mrs_opened(self) -> list[FixResult]:
        return [f for r in self.repos for f in r.fixes if f.outcome is Outcome.MR_OPENED]


@dataclass(frozen=True)
class RunSummary:
    """Riga dello storico delle run (per `status` e per la dashboard)."""

    run_id: str
    started_at: datetime | None
    finished_at: datetime | None
    dry_run: bool
    spent_usd: float
    mrs_opened: int
    aborted: str | None
