"""Credenziali dei registry nel sandbox: oscurate prima che arrivino a modello, report e GitLab.

Il sandbox riceve le credenziali di sola lettura dei registry interni (~/.netrc). Tutto ciò che
esce dal sandbox passa da qui, così output di setup e test, letture dell'agente e scanner
arrivano già senza valori segreti.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path

from maxtac.domain.models import ExecResult, RunReport
from maxtac.domain.policy import Redactor
from maxtac.domain.ports import Sandbox, SandboxPort


@dataclass
class RedactingSandbox:
    inner: Sandbox
    redactor: Redactor

    def exec(self, cmd: str, timeout: int) -> ExecResult:
        r = self.inner.exec(cmd, timeout)
        return ExecResult(r.code, self.redactor.redact(r.output))

    def read(self, path: str) -> str:
        return self.redactor.redact(self.inner.read(path))

    def write(self, path: str, content: str) -> None:
        self.inner.write(path, content)

    def list_files(self, path: str) -> list[str]:
        return [self.redactor.redact(f) for f in self.inner.list_files(path)]


@dataclass
class RedactingSandboxes:
    inner: SandboxPort
    redactor: Redactor

    @contextmanager
    def open(self, worktree: Path) -> Iterator[RedactingSandbox]:
        with self.inner.open(worktree) as sb:
            yield RedactingSandbox(sb, self.redactor)


def redact_report(report: RunReport, r: Redactor) -> None:
    """Ultima passata sul report della notte, prima di disco, storico e webhook."""
    if not r.secrets:
        return
    report.aborted = r.redact(report.aborted) if report.aborted else report.aborted
    for repo in report.repos:
        repo.errors = [r.redact(e) for e in repo.errors]
        repo.ignored = [(t, r.redact(why)) for t, why in repo.ignored]
        repo.needs_human = [(t, r.redact(why)) for t, why in repo.needs_human]
        repo.fixes = [
            replace(
                fx,
                detail=r.redact(fx.detail),
                diff=r.redact(fx.diff),
                test_output=r.redact(fx.test_output),
                triage_reason=r.redact(fx.triage_reason),
            )
            for fx in repo.fixes
        ]
