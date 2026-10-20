"""Porte del dominio: cosa la pipeline chiede al mondo esterno."""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import AbstractContextManager
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from .models import (
    AssistantTurn,
    Checkout,
    ExecResult,
    FileChange,
    Finding,
    FindingRecord,
    FindingStatus,
    Message,
    RepoConfig,
    StructuredResult,
    ToolSpec,
)


class LLMUnavailable(Exception):
    """Il modello non è utilizzabile per il resto della notte (crediti finiti, chiave rifiutata).

    Non è colpa del finding: la pipeline si ferma senza contare tentativi.
    """


class VCSPort(Protocol):
    def checkout(self, repo: RepoConfig, workdir: Path) -> Checkout: ...

    def reset(self, co: Checkout) -> None:
        """Riporta la working tree esattamente al commit base, senza file extra."""
        ...

    def start_branch(self, co: Checkout, branch: str) -> None:
        """Riporta la working tree al commit base e crea `branch` pulito da lì."""
        ...

    def changes(self, co: Checkout) -> list[FileChange]: ...

    def diff(self, co: Checkout) -> str: ...

    def recent_diff(self, co: Checkout, days: int) -> tuple[str, list[str]]:
        """Diff degli ultimi `days` giorni e file toccati ancora esistenti."""
        ...

    def push_branch(self, co: Checkout, branch: str, message: str) -> None: ...

    def open_mr(
        self, repo: RepoConfig, branch: str, title: str, body: str, labels: Sequence[str]
    ) -> str: ...

    def has_open_mr(self, repo: RepoConfig, branch: str) -> bool: ...


class Sandbox(Protocol):
    """Container effimero con la working tree montata in /work."""

    def exec(self, cmd: str, timeout: int) -> ExecResult: ...

    def read(self, path: str) -> str: ...

    def write(self, path: str, content: str) -> None: ...

    def list_files(self, path: str) -> list[str]: ...


class SandboxPort(Protocol):
    def open(self, worktree: Path) -> AbstractContextManager[Sandbox]: ...


class ScannerPort(Protocol):
    name: str
    kind: str  # "cve" o "sast"

    def supports(self, languages: Sequence[str]) -> bool: ...

    def scan(self, sandbox: Sandbox) -> list[Finding]: ...


class LLMPort(Protocol):
    def structured(
        self,
        *,
        model: str,
        system: str,
        prompt: str,
        tool: ToolSpec,
        max_tokens: int,
    ) -> StructuredResult:
        """Una chiamata con output JSON vincolato allo schema di `tool` (structured output)."""
        ...

    def turn(
        self,
        *,
        model: str,
        system: str,
        messages: Sequence[Message],
        tools: Sequence[ToolSpec],
        max_tokens: int,
    ) -> AssistantTurn:
        """Un passo del loop agentico. Il loop vive nel dominio, non nell'adapter."""
        ...


class FindingStore(Protocol):
    def get(self, fingerprint: str) -> FindingRecord | None: ...

    def observe(self, findings: Sequence[Finding], seen_at: datetime) -> None: ...

    def set_status(
        self,
        fingerprint: str,
        status: FindingStatus,
        reason: str = "",
        *,
        mr_url: str | None = None,
        branch: str | None = None,
    ) -> None: ...

    def record_failed_attempt(self, fingerprint: str, reason: str) -> int: ...

    def last_hunted(self, project: str) -> datetime | None: ...

    def mark_hunted(self, project: str, at: datetime) -> None: ...

    def counts_by_status(self) -> dict[str, int]: ...

    def open_mrs(self) -> list[dict[str, Any]]: ...


class BudgetPort(Protocol):
    def record(self, run_id: str, scope: str, model: str, usd: float, at: datetime) -> None: ...

    def spent(self, run_id: str, scope: str | None = None) -> float: ...

    def spent_month(self, year: int, month: int) -> float: ...
