"""RunReport in forma JSON-serializzabile: storico delle run e dashboard."""

from __future__ import annotations

from typing import Any

from .models import Finding, FixResult, RunReport, Task
from .policy import truncate

DIFF_LIMIT = 20_000
DETAIL_LIMIT = 4_000


def _finding(f: Finding) -> dict[str, Any]:
    return {
        "fingerprint": f.fingerprint,
        "kind": f.kind,
        "tool": f.tool,
        "rule": f.rule,
        "location": f.location,
        "line": f.line,
        "severity": f.severity.name.lower(),
    }


def _task(t: Task) -> dict[str, Any]:
    return {
        "fingerprint": t.fingerprint,
        "kind": t.kind,
        "title": t.title,
        "severity": t.severity.name.lower(),
        "findings": [_finding(f) for f in t.findings],
    }


def _fix(fx: FixResult) -> dict[str, Any]:
    return {
        "task": _task(fx.task),
        "outcome": fx.outcome.value,
        "cost_usd": round(fx.cost_usd, 6),
        "detail": truncate(fx.detail, DETAIL_LIMIT),
        "branch": fx.branch,
        "mr_url": fx.mr_url,
        "diff": truncate(fx.diff, DIFF_LIMIT),
        "test_output": truncate(fx.test_output, DETAIL_LIMIT * 2),
        "triage_reason": truncate(fx.triage_reason, DETAIL_LIMIT),
        "iterations": fx.iterations,
        "agent_stop": fx.agent_stop,
    }


def report_to_dict(report: RunReport) -> dict[str, Any]:
    return {
        "run_id": report.run_id,
        "dry_run": report.dry_run,
        "started_at": report.started_at.isoformat() if report.started_at else None,
        "finished_at": report.finished_at.isoformat() if report.finished_at else None,
        "spent_usd": round(report.spent_usd, 6),
        "night_cap_usd": report.night_cap_usd,
        "aborted": report.aborted,
        "mrs_opened": len(report.mrs_opened),
        "repos": [
            {
                "project": r.project,
                "findings_total": r.findings_total,
                "findings_new": r.findings_new,
                "skipped_open_mr": r.skipped_open_mr,
                "hunted": r.hunted,
                "bugs_found": r.bugs_found,
                "fixes": [_fix(fx) for fx in r.fixes],
                "ignored": [{"task": _task(t), "reason": why} for t, why in r.ignored],
                "needs_human": [{"task": _task(t), "reason": why} for t, why in r.needs_human],
                "errors": r.errors,
            }
            for r in report.repos
        ],
    }
