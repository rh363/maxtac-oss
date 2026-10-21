"""Report della notte e stato del servizio, resi con il lessico dell'operatore."""

from __future__ import annotations

import html
import json
import re
from collections.abc import Callable, Sequence
from datetime import date
from typing import Any

from maxtac.domain.models import FindingRecord, Outcome, RunReport, RunSummary, TokenInfo
from maxtac.domain.policy import group_into_tasks, token_state
from maxtac.services.scan import ScanResult

from .lexicon import Lexicon

_CONTROL = re.compile(r"[\x00-\x1f\x7f\u2028\u2029\u0085]")


def safe(text: str, limit: int = 300) -> str:
    """Testo non fidato (titoli, motivazioni, errori) dentro report e webhook: una riga,
    niente HTML/markup di Slack (`<!channel>`, `<url|testo>`) e niente menzioni."""
    text = html.escape(_CONTROL.sub(" ", text)[:limit], quote=False)
    return text.replace("@", "@\u200b")


def render_run(report: RunReport, lx: Lexicon) -> str:
    """Report della notte: finisce su disco e nel webhook, quindi il testo non fidato
    passa da `safe`. Stato e scan restano testo per il terminale dell'operatore."""
    mode = " (dry-run)" if report.dry_run else ""
    lines = [
        f"# {lx.product}: {lx.run} {report.run_id}{mode}",
        "",
        f"- {lx.mr_open}: {len(report.mrs_opened)}",
        f"- {lx.spend}: {lx.money(report.spent_usd)} su {lx.money(report.night_cap_usd)}",
    ]
    if report.aborted:
        lines.append(f"- interrotta: {safe(report.aborted)}")
    lines.append("")
    for r in report.repos:
        lines += [
            f"## {r.project}",
            "",
            f"- {lx.findings}: {r.findings_total} totali, {r.findings_new} nuovi",
        ]
        if r.skipped_open_mr:
            lines.append(f"- già con MR aperta: {r.skipped_open_mr}")
        if r.hunted:
            lines.append(f"- {lx.hunting}: {r.bugs_found} bug")
        for fx in r.fixes:
            where = f" {safe(fx.mr_url)}" if fx.mr_url else ""
            first = fx.detail.splitlines()[0] if fx.detail else ""
            detail = f" ({safe(first, 160)})" if first and not fx.mr_url else ""
            lines.append(
                f"- {lx.outcomes[fx.outcome]}: {safe(fx.task.title)}, "
                f"{lx.money(fx.cost_usd)}{where}{detail}"
            )
        for label, items in ((lx.ignored, r.ignored), (lx.needs_human, r.needs_human)):
            for task, reason in items:
                lines.append(f"- {label}: {safe(task.title)} ({safe(reason, 160)})")
        for err in r.errors:
            lines.append(f"- errore: {safe(err)}")
        lines.append("")
    return "\n".join(lines)


def signoff(report: RunReport, lx: Lexicon) -> str | None:
    """Riga di chiusura per il terminale dell'operatore. Il lessico neutro non ne ha."""
    if report.aborted or any(r.errors for r in report.repos):
        return None
    fixes = [fx for r in report.repos for fx in r.fixes]
    mrs = len(report.mrs_opened)
    if mrs and lx.clean_sweep and all(fx.outcome is Outcome.MR_OPENED for fx in fixes):
        return lx.clean_sweep.format(n=mrs)
    if lx.quiet_night and not fixes and not any(r.findings_new for r in report.repos):
        return lx.quiet_night
    return None


def render_status(
    lx: Lexicon,
    *,
    month_spent: float,
    month_label: str,
    counts: dict[str, int],
    open_mrs: list[dict[str, Any]],
    next_run: str,
    credits_usd: float | None = None,
    day_of_month: int | None = None,
    days_in_month: int | None = None,
    runs: Sequence[RunSummary] = (),
    tokens: Sequence[TokenInfo] = (),
    today: date | None = None,
) -> str:
    total = sum(counts.values())
    # una MR può coprire più finding (CVE dello stesso package): una riga per MR
    by_mr = {mr["mr_url"] or mr["fingerprint"]: mr for mr in open_mrs}
    lines = [
        f"{lx.product}: {lx.tagline}",
        "",
        f"{lx.spend} ({month_label}): {lx.money(month_spent)}"
        + (f" su {lx.money(credits_usd)} di crediti" if credits_usd else ""),
        f"prossima {lx.run}: {next_run}",
        f"{lx.findings} tracciati: {total}"
        + (" (" + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) + ")" if total else ""),
        f"{lx.mr_open}: {len(by_mr)}",
    ]
    if credits_usd and day_of_month and days_in_month:
        projected = month_spent / day_of_month * days_in_month
        lines.insert(3, f"proiezione a fine mese: {lx.money(projected)}")
        if projected > credits_usd:
            lines.insert(4, "ATTENZIONE: la proiezione supera i crediti del mese")
    for mr in by_mr.values():
        lines.append(f"  - {mr['kind']} {mr['rule']} {mr['location']}: {mr['mr_url'] or '-'}")
    if runs:
        lines.append(f"ultime {lx.run}:")
    for r in runs:
        flags = " dry-run" if r.dry_run else ""
        flags += f" interrotta ({r.aborted[:80]})" if r.aborted else ""
        lines.append(f"  - {r.run_id}: {lx.money(r.spent_usd)}, {r.mrs_opened} MR{flags}")
    if tokens:
        lines.append("token GitLab (ultimo controllo):")
    for t in tokens:
        lines.append("  - " + token_line(t, today or t.checked_at.date()))
    return "\n".join(lines)


TOKEN_STATE_LABEL = {
    "ok": "ok",
    "expiring": "ATTENZIONE: scade a breve",
    "expired": "ATTENZIONE: scaduto",
    "unknown": "scadenza non leggibile",
    "error": "ERRORE",
}


def token_line(t: TokenInfo, today: date) -> str:
    """Nome, scope, utente e scadenza di un token. Mai il valore."""
    scope = ", ".join(p or "(tutta l'istanza)" for p in t.scope)
    state = token_state(t, today)
    expiry = f"scade il {t.expires_at.isoformat()}" if t.expires_at else ""
    who = f"utente {t.username}" if t.username else ""
    detail = safe(t.error or "") if state == "error" else expiry
    parts = [p for p in (who, detail) if p]
    return f"{t.name} [{scope}]: {TOKEN_STATE_LABEL[state]}" + (
        f" ({'; '.join(parts)})" if parts else ""
    )


Lookup = Callable[[str, str], FindingRecord | None]  # (project, fingerprint)


def render_scan(results: Sequence[ScanResult], lx: Lexicon, lookup: Lookup) -> str:
    """Finding normalizzati di `run --scan-only`, raggruppati come li vedrebbe il fix agent."""
    lines = [f"# {lx.product}: scan", ""]
    for res in results:
        tasks = group_into_tasks(res.findings)
        lines += [
            f"## {res.repo.project}",
            "",
            f"- {lx.findings}: {len(res.findings)}, task: {len(tasks)}",
        ]
        for f in sorted(res.findings, key=lambda f: (-f.severity, f.kind, f.rule, f.location)):
            rec = lookup(res.repo.project, f.fingerprint)
            state = rec.status.value if rec else "new"
            where = f"{f.location}:{f.line}" if f.line else f.location
            lines.append(
                f"- [{f.severity.name}] {f.kind}/{f.tool} {f.rule} @ {where} "
                f"({state}, {f.fingerprint})"
            )
        for err in res.errors:
            lines.append(f"- errore: {err[:300]}")
        lines.append("")
    return "\n".join(lines)


def scan_json(results: Sequence[ScanResult], lookup: Lookup) -> str:
    """Versione macchina dello scan: sempre neutra, finisce su disco."""
    data = []
    for res in results:
        findings = []
        for f in res.findings:
            rec = lookup(res.repo.project, f.fingerprint)
            findings.append(
                {
                    "fingerprint": f.fingerprint,
                    "kind": f.kind,
                    "tool": f.tool,
                    "rule": f.rule,
                    "location": f.location,
                    "line": f.line,
                    "severity": f.severity.name.lower(),
                    "status": rec.status.value if rec else "new",
                    "detail": f.detail,
                }
            )
        data.append({"project": res.repo.project, "findings": findings, "errors": res.errors})
    return json.dumps({"repos": data}, indent=2, ensure_ascii=False)
