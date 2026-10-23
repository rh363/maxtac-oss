"""Porte del dominio: cosa la pipeline chiede al mondo esterno."""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import AbstractContextManager
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from .models import (
    ApprovedRepo,
    AssistantTurn,
    Checkout,
    ExecResult,
    FileChange,
    Finding,
    FindingQuery,
    FindingRecord,
    FindingRow,
    FindingStatus,
    Message,
    ProposalStatus,
    RepoConfig,
    RepoProposal,
    RunReport,
    RunSummary,
    SpendEntry,
    StructuredResult,
    TokenInfo,
    ToolSpec,
    Usage,
)


class LLMUnavailable(Exception):
    """Il modello non è utilizzabile per il resto della notte (crediti finiti, chiave rifiutata).

    Non è colpa del finding: la pipeline si ferma senza contare tentativi.
    """


class StructuredOutputError(Exception):
    """Risposta strutturata inutilizzabile (max_tokens, JSON non valido): la spesa però c'è
    stata, quindi l'eccezione porta con sé `usage` e `model` per addebitarla."""

    def __init__(self, message: str, usage: Usage, model: str) -> None:
        super().__init__(message)
        self.usage = usage
        self.model = model


class VCSPort(Protocol):
    def checkout(self, repo: RepoConfig, workdir: Path) -> Checkout: ...

    def reset(self, co: Checkout) -> None:
        """Riporta la working tree esattamente al commit base, senza file extra."""
        ...

    def start_branch(self, co: Checkout, branch: str) -> None:
        """Riporta la working tree al commit base e crea `branch` pulito da lì."""
        ...

    def changes(self, co: Checkout) -> list[FileChange]: ...

    def discard_untracked(self, co: Checkout) -> None:
        """Elimina i file non tracciati né in stage (venv, node_modules, pyc creati
        dall'agente): non finirebbero nella MR, ma potrebbero truccare la verifica."""
        ...

    def snapshot(self, co: Checkout) -> str:
        """Fotografa la working tree come tree git (fuori dal sandbox); ritorna l'id."""
        ...

    def materialize(
        self,
        co: Checkout,
        tree: str,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] = (),
    ) -> None:
        """Riporta la working tree a `tree`. Con `include`: base + solo quei path da `tree`.
        Con `exclude`: `tree` senza quei path."""
        ...

    def file_versions(self, co: Checkout, path: str) -> tuple[str | None, str | None]:
        """Contenuto di `path` al commit base e nella working tree (None se assente)."""
        ...

    def cleanup(self, co: Checkout) -> None:
        """Elimina working tree e git dir del checkout."""
        ...

    def diff(self, co: Checkout) -> str: ...

    def recent_diff(self, co: Checkout, days: int) -> tuple[str, list[str]]:
        """Diff degli ultimi `days` giorni e file toccati ancora esistenti."""
        ...

    def push_branch(self, co: Checkout, branch: str, message: str) -> None: ...

    def open_mr(
        self, repo: RepoConfig, branch: str, title: str, body: str, labels: Sequence[str]
    ) -> str: ...

    def has_open_mr(self, repo: RepoConfig, branch: str) -> bool: ...

    def list_projects(self) -> list[str]:
        """Progetti non archiviati su cui il bot può aprire MR (candidati all'autodiscovery)."""
        ...


class Sandbox(Protocol):
    """Container effimero con la working tree montata in /work."""

    def exec(self, cmd: str, timeout: int) -> ExecResult: ...

    def read(self, path: str) -> str: ...

    def write(self, path: str, content: str) -> None: ...

    def list_files(self, path: str) -> list[str]: ...


class SandboxPort(Protocol):
    def open(
        self, worktree: Path, image: str | None = None
    ) -> AbstractContextManager[Sandbox]: ...  # image None: quella standard


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
    """Stato dei finding per repo: lo stesso fingerprint in due repo sono due finding."""

    def get(self, project: str, fingerprint: str) -> FindingRecord | None: ...

    def observe(self, project: str, findings: Sequence[Finding], seen_at: datetime) -> None: ...

    def set_status(
        self,
        project: str,
        fingerprint: str,
        status: FindingStatus,
        reason: str = "",
        *,
        mr_url: str | None = None,
        branch: str | None = None,
    ) -> None: ...

    def record_failed_attempt(self, project: str, fingerprint: str, reason: str) -> int: ...

    def last_hunted(self, project: str) -> datetime | None: ...

    def mark_hunted(self, project: str, at: datetime) -> None:
        """`at` è l'inizio della run: tutti i repo di una notte condividono lo stesso istante."""
        ...

    def hunt_count(self, project: str) -> int: ...

    def counts_by_status(self) -> dict[str, int]: ...

    def counts_by_project(self) -> dict[str, dict[str, int]]: ...

    def open_mrs(self) -> list[dict[str, Any]]: ...

    def list_findings(self, q: FindingQuery) -> tuple[list[FindingRow], int]:
        """Pagina di finding (severità decrescente, più recenti prima) e totale filtrato."""
        ...


class BudgetPort(Protocol):
    def record(self, run_id: str, scope: str, model: str, usd: float, at: datetime) -> None: ...

    def spent(self, run_id: str, scope: str | None = None) -> float: ...

    def spent_month(self, year: int, month: int) -> float: ...

    def ledger(self, since: datetime) -> list[SpendEntry]:
        """Le singole spese da `since` in poi, in ordine di tempo."""
        ...


class RunStore(Protocol):
    """Storico delle run notturne: report completo in JSON, letto da `status` e dalla dashboard."""

    def save_run(self, report: RunReport) -> None: ...

    def recent_runs(self, limit: int, offset: int = 0) -> list[RunSummary]: ...

    def get_run(self, run_id: str) -> dict[str, Any] | None: ...


class RepoRegistry(Protocol):
    """Repo scoperti dall'autodiscovery: proposte (non fidate) e repo approvati dall'operatore."""

    def save_proposal(self, proposal: RepoProposal) -> int:
        """Salva una proposta pending; quella pending precedente dello stesso repo diventa
        superseded. Ritorna l'id."""
        ...

    def pending_proposal(self, project: str) -> RepoProposal | None: ...

    def list_proposals(self, status: ProposalStatus | None = None) -> list[RepoProposal]: ...

    def approve(self, proposal: RepoProposal, repo: RepoConfig, by: str, at: datetime) -> None:
        """`repo` è la config approvata (eventualmente corretta a mano rispetto alla proposta)."""
        ...

    def reject(self, project: str) -> bool: ...

    def remove(self, project: str) -> bool: ...

    def approved(self, project: str) -> ApprovedRepo | None: ...

    def approved_repos(self) -> list[ApprovedRepo]: ...


class TokenRegistry(Protocol):
    """Ultimo stato noto dei token GitLab (nome, scope, utente, scadenza): mai i valori."""

    def save_tokens(self, infos: Sequence[TokenInfo]) -> None: ...

    def tokens(self) -> list[TokenInfo]: ...


class NotifierPort(Protocol):
    """Notifica del mattino. Il testo è sempre neutro: può finire in canali condivisi."""

    def notify(self, report: RunReport) -> None: ...
