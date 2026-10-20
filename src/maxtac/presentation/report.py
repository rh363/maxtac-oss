"""Report della notte e stato del servizio, resi con il lessico dell'operatore."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import Any

from maxtac.domain.models import FindingRecord, RunReport
from maxtac.domain.policy import group_into_tasks
from maxtac.services.scan import ScanResult

from .lexicon import Lexicon


def render_run(report: RunReport, lx: Lexicon) -> str:
    mode = " (dry-run)" if report.dry_run else ""
    lines = [
        f"# {lx.product}: {lx.run} {report.run_id}{mode}",
        "",
        f"- {lx.mr_open}: {len(report.mrs_opened)}",
        f"- {lx.spend}: {lx.money(report.spent_usd)} su {lx.money(report.night_cap_usd)}",
    ]
    if report.aborted:
        lines.append(f"- interrotta: {report.aborted}")
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
            where = f" {fx.mr_url}" if fx.mr_url else ""
            detail = f" ({fx.detail.splitlines()[0][:160]})" if fx.detail and not fx.mr_url else ""
            lines.append(
                f"- {lx.outcomes[fx.outcome]}: {fx.task.title}, "
                f"{lx.money(fx.cost_usd)}{where}{detail}"
            )
        for label, items in ((lx.ignored, r.ignored), (lx.needs_human, r.needs_human)):
            for task, reason in items:
                lines.append(f"- {label}: {task.title} ({reason[:160]})")
        for err in r.errors:
            lines.append(f"- errore: {err[:300]}")
        lines.append("")
    return "\n".join(lines)


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
    return "\n".join(lines)


Lookup = Callable[[str], FindingRecord | None]


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
            rec = lookup(f.fingerprint)
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
            rec = lookup(f.fingerprint)
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
