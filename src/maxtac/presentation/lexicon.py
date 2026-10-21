"""Lessici di presentazione. Il tema cambia solo le parole che vede l'operatore.

Branch, label, commit e testo delle MR non passano mai da qui: su GitLab resta tutto neutro.
"""

from __future__ import annotations

from dataclasses import dataclass, field

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
    ui: dict[str, str] = field(default_factory=dict)  # override delle etichette web

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

# Tema dell'operatore, nella versione attenuata approvata: le etichette funzionali restano
# chiare (sono le stesse del neutro); il gioco compare solo nel marchio, in piccoli sottotitoli
# secondari e in qualche easter egg. Mai una parola del gioco come unica etichetta di un dato.
CYBERPUNK = Lexicon(
    name="cyberpunk",
    product="MaxTac",
    tagline="Autofix · edizione operatore. Il Blackwall regge.",
    run="run notturna",
    finding="finding",
    findings="finding",
    triage="triage",
    fixer="fix agent",
    hunting="bug hunting",
    sandbox="sandbox",
    proxy="proxy egress (Blackwall)",
    spend="spesa",
    currency="$",
    ignored="ignorati",
    needs_human="serve un umano",
    mr_open="MR aperte",
    outcomes={
        Outcome.MR_OPENED: "MR aperta",
        Outcome.DRY_RUN: "dry run",
        Outcome.NEEDS_HUMAN: "serve un umano",
        Outcome.VERIFY_FAILED: "verifica fallita",
        Outcome.AGENT_FAILED: "fix non riuscito",
        Outcome.BUDGET_EXHAUSTED: "budget esaurito",
        Outcome.ERROR: "errore",
    },
    # Override delle etichette della dashboard (chiavi di frontend/src/lib/lexicon/neutral.json)
    ui={
        "brand": "MaxTac",
        "brandSub": "Autofix · edizione operatore",
        "greeting": "Bentornato, {user}",
        "nextRun": "Prossima run {time} · il Blackwall regge",
        "nextRunNone": "Nessuna run pianificata · il Blackwall regge",
        "find.subtitle": "Tutti i finding di scanner e bug hunting · bounty board",
        "tag.byStatus": "bounty board",
        "tag.runs": "log delle patrol",
        "tag.hunt": "squadra MaxTac",
        "tag.triage": "referto Trauma Team",
        "tag.change": "note del ripperdoc",
        "tag.spend": "eddies bruciati",
        "tag.repos": "distretti sotto controllo",
        "tag.proposals": "nuove soffiate",
        "empty.proposals": "Nessuna proposta. Nessuna soffiata in arrivo.",
        "status.needs_human": "Serve un umano",
        "outcome.needs_human": "Serve un umano",
        "outcome.dry_run": "Dry run",
        "kpi.human": "Serve un umano",
        "kpi.humanSub": "In attesa di una review",
        "task.gitlabNeutral": "su GitLab branch e testo restano neutri",
        "costTip": "eddies",
        "empty.runs": "Nessuna run ancora. Night City dorme, per ora.",
        "empty.findings": "Nessun finding con questi filtri. Strade pulite.",
    },
)

LEXICONS = {lx.name: lx for lx in (NEUTRAL, CYBERPUNK)}


def lexicon(name: str | None) -> Lexicon:
    return LEXICONS.get(name or "", NEUTRAL)
