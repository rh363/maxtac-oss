"""Report della notte e stato del servizio, resi con il lessico dell'operatore."""

from __future__ import annotations

from typing import Any

from maxtac.domain.models import RunReport

from .lexicon import Lexicon


def render_run(report: RunReport, lx: Lexicon) -> str:
    mode = " (dry-run)" if report.dry_run else ""
    lines = [
        f"# {lx.product}: {lx.run} {report.run_id}{mode}",
        "",
        f"- {lx.mr_open}: {len(report.mrs_opened)}",
        f"- {lx.spend}: {lx.money(report.spent_usd)} su {lx.money(report.night_cap_usd)}",
        "",
    ]
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
) -> str:
    total = sum(counts.values())
    # una MR può coprire più finding (CVE dello stesso package): una riga per MR
    by_mr = {mr["mr_url"] or mr["fingerprint"]: mr for mr in open_mrs}
    lines = [
        f"{lx.product}: {lx.tagline}",
        "",
        f"{lx.spend} ({month_label}): {lx.money(month_spent)}",
        f"prossima {lx.run}: {next_run}",
        f"{lx.findings} tracciati: {total}"
        + (" (" + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) + ")" if total else ""),
        f"{lx.mr_open}: {len(by_mr)}",
    ]
    for mr in by_mr.values():
        lines.append(f"  - {mr['kind']} {mr['rule']} {mr['location']}: {mr['mr_url'] or '-'}")
    return "\n".join(lines)
