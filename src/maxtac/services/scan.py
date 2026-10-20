"""Checkout e scan deterministico: la parte della notte che non spende token."""

from __future__ import annotations

import logging
from collections.abc import Collection, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from maxtac.domain.models import Checkout, Finding, RepoConfig
from maxtac.domain.ports import Sandbox, SandboxPort, ScannerPort, VCSPort

log = logging.getLogger(__name__)


def applicable(
    scanners: Sequence[ScannerPort], kinds: Collection[str], languages: Sequence[str]
) -> list[ScannerPort]:
    return [sc for sc in scanners if sc.kind in kinds and sc.supports(languages)]


def run_scanners(sb: Sandbox, scanners: Sequence[ScannerPort], errors: list[str]) -> list[Finding]:
    """Uno scanner che fallisce non ferma gli altri: l'errore finisce nel report."""
    out: list[Finding] = []
    for sc in scanners:
        try:
            out.extend(sc.scan(sb))
        except Exception as e:
            log.exception("scanner %s fallito", sc.name)
            errors.append(f"scanner {sc.name}: {type(e).__name__}: {e}")
    return out


@dataclass
class ScanResult:
    repo: RepoConfig
    checkout: Checkout | None
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class ScanService:
    """Solo checkout e scan: è il criterio della Fase 1 (`run --scan-only`)."""

    vcs: VCSPort
    sandboxes: SandboxPort
    scanners: Sequence[ScannerPort]
    kinds: Collection[str]
    workdir: Path

    def scan(self, repo: RepoConfig, run_id: str) -> ScanResult:
        res = ScanResult(repo, None)
        try:
            res.checkout = self.vcs.checkout(repo, self.workdir / run_id / repo.slug)
            scanners = applicable(self.scanners, self.kinds, repo.languages)
            with self.sandboxes.open(res.checkout.worktree) as sb:
                res.findings = run_scanners(sb, scanners, res.errors)
        except Exception as e:
            log.exception("scan di %s fallito", repo.project)
            res.errors.append(f"{type(e).__name__}: {e}")
        return res
