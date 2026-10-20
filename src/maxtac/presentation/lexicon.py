"""Lessici di presentazione. Il tema cambia solo le parole che vede l'operatore.

Branch, label, commit e testo delle MR non passano mai da qui: su GitLab resta tutto neutro.
"""

from __future__ import annotations

from dataclasses import dataclass

from maxtac.domain.models import Outcome


@dataclass(frozen=True)
class Lexicon:
    name: str
    product: str
    tagline: str
    run: str  # la run notturna
    finding: str
    findings: str
    triage: str
    fixer: str
    hunting: str
    sandbox: str
    proxy: str
    spend: str
    currency: str  # simbolo usato nei report
    ignored: str
    needs_human: str
    mr_open: str
    outcomes: dict[Outcome, str]

    def money(self, usd: float) -> str:
        return f"{self.currency}{usd:.2f}"


NEUTRAL = Lexicon(
    name="neutral",
    product="Autofix",
    tagline="Fix automatici e verificati per CVE, finding SAST e bug",
    run="run notturna",
    finding="finding",
    findings="finding",
    triage="triage",
    fixer="fix agent",
    hunting="bug hunting",
    sandbox="sandbox",
    proxy="proxy di uscita",
    spend="spesa",
    currency="$",
    ignored="ignorati",
    needs_human="da rivedere",
    mr_open="MR aperte",
    outcomes={
        Outcome.MR_OPENED: "MR aperta",
        Outcome.DRY_RUN: "fix verificato (dry-run)",
        Outcome.NEEDS_HUMAN: "da rivedere",
        Outcome.VERIFY_FAILED: "verifica fallita",
        Outcome.AGENT_FAILED: "fix non riuscito",
        Outcome.BUDGET_EXHAUSTED: "budget esaurito",
        Outcome.ERROR: "errore",
    },
)

CYBERPUNK = Lexicon(
    name="cyberpunk",
    product="MAXTAC",
    tagline="Night City non dorme. Nemmeno i tuoi bug.",
    run="patrol",
    finding="cyberpsycho",
    findings="cyberpsycho",
    triage="Trauma Team",
    fixer="ripperdoc",
    hunting="squadra MaxTac",
    sandbox="braindance",
    proxy="Blackwall",
    spend="eddies bruciati",
    currency="€$",
    ignored="falsi allarmi NCPD",
    needs_human="passati al fixer umano",
    mr_open="bounty riscosse",
    outcomes={
        Outcome.MR_OPENED: "neutralizzato, MR in coda",
        Outcome.DRY_RUN: "neutralizzato in braindance (dry-run)",
        Outcome.NEEDS_HUMAN: "serve un fixer umano",
        Outcome.VERIFY_FAILED: "flatline in verifica",
        Outcome.AGENT_FAILED: "il ripperdoc ha fallito",
        Outcome.BUDGET_EXHAUSTED: "eddies finiti",
        Outcome.ERROR: "glitch",
    },
)

LEXICONS = {lx.name: lx for lx in (NEUTRAL, CYBERPUNK)}


def lexicon(name: str | None) -> Lexicon:
    return LEXICONS.get(name or "", NEUTRAL)
