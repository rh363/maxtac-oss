"""Finding come tabella Markdown, da incollare in issue, MR o documenti: sempre neutra."""

from __future__ import annotations

import re
from collections.abc import Sequence
from urllib.parse import quote

from maxtac.domain.models import FindingRow

from .report import safe

STATUS = {
    "new": "nuovo",
    "mr_open": "MR aperta",
    "needs_human": "da rivedere",
    "ignored": "ignorato",
}
_ADVISORY = re.compile(r"^(CVE|GHSA|PYSEC|GO|RUSTSEC|OSV)-[\w-]+$", re.IGNORECASE)


def cell(text: str, limit: int = 160) -> str:
    """Testo non fidato in una cella: una riga, niente HTML né menzioni, `|` neutralizzato."""
    return safe(text, limit).replace("|", "\\|").replace("`", "'").strip()


def cve_info(detail: str) -> tuple[str, list[str], str]:
    """(riassunto, alias, versioni corrette) dal dettaglio scritto da osv-scanner."""
    summary, aliases, fixed = "", [], ""
    for i, line in enumerate(detail.splitlines()):
        if line.startswith("Alias: "):
            aliases = [a.strip() for a in line[7:].split(",") if a.strip()]
        elif line.startswith("Versioni corrette: "):
            value = line[19:].strip()
            fixed = "" if value == "nessuna nota" else value
        elif i == 0:
            summary = line
    return summary, aliases, fixed


def _advisory(rule: str) -> str:
    if _ADVISORY.match(rule):
        return f"[{cell(rule)}](https://osv.dev/vulnerability/{quote(rule, safe='-')})"
    return cell(rule)


def findings_markdown(rows: Sequence[FindingRow], total: int | None = None) -> str:
    """Tabella dei finding (CVE con pacchetto, versione e correzione); `total` > len(rows)
    aggiunge una nota sulle righe escluse."""
    multi = len({r.project for r in rows}) > 1
    head = ["Severità", "Advisory", "Alias", "Pacchetto o file", "Versione", "Corretta in"]
    head += ["Descrizione", "Stato", "MR"]
    if multi:
        head.insert(0, "Progetto")
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for r in rows:
        if r.kind == "cve":
            summary, aliases, fixed = cve_info(r.detail)
            package, _, version = r.location.rpartition("@")
            if not package:
                package, version = version, ""
        else:
            summary, aliases, fixed = r.detail.split("\n", 1)[0], [], ""
            package, version = r.location, ""
        mr = f"[MR]({r.mr_url})" if r.mr_url else ""
        values = [
            r.severity.name.lower(),
            _advisory(r.rule),
            cell(", ".join(aliases)),
            cell(package),
            cell(version),
            cell(fixed),
            cell(summary),
            STATUS.get(r.status.value, r.status.value),
            mr,
        ]
        if multi:
            values.insert(0, cell(r.project))
        lines.append("| " + " | ".join(values) + " |")
    if total is not None and total > len(rows):
        lines += ["", f"_Prime {len(rows)} righe su {total}: restringi i filtri per le altre._"]
    return "\n".join(lines) + "\n"
