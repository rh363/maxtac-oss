"""Testo di commit e MR. Su GitLab il lessico è sempre neutro, qualunque tema usi l'operatore.

Tutto ciò che viene dal repo o dal modello (path, nomi di package, regole, motivazioni,
riassunto dell'agente, output dei test) è non fidato. GitLab esegue le quick action
(`/merge`, `/approve`...) scritte a inizio riga nella descrizione con i permessi del bot,
e notifica le menzioni `@utente`: entrambe vanno neutralizzate prima di pubblicare.
"""

from __future__ import annotations

import re

from maxtac.domain.models import Task, Verdict
from maxtac.domain.policy import truncate

ZWSP = "​"
_CONTROL = re.compile(r"[\x00-\x1f\x7f\u2028\u2029\u0085]")


def inline(text: str, limit: int = 300) -> str:
    """Campo su una riga dentro una cella o un titolo: niente a capo, `|` e backtick."""
    text = _CONTROL.sub(" ", text)[:limit]
    return text.replace("|", "\\|").replace("`", "'").replace("@", "@" + ZWSP)


def fenced(text: str) -> str:
    """Blocco di codice: il markdown, i link e le menzioni restano testo."""
    body = text.replace("```", "'''").replace("~~~", "'''").replace("@", "@" + ZWSP)
    return f"```text\n{body.rstrip()}\n```"


def defuse(text: str) -> str:
    """Ultima difesa sull'intero testo: nessuna riga può iniziare con `/` (quick action)."""
    out = []
    for line in text.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith("/"):
            line = line[: len(line) - len(stripped)] + ZWSP + stripped
        out.append(line)
    return "\n".join(out)


def commit_message(task: Task) -> str:
    rules = "\n".join(
        f"- {inline(f.tool)}: {inline(f.rule)} ({inline(f.location)})" for f in task.findings
    )
    return defuse(f"autofix: {inline(task.title)}\n\n{rules}\n")


def mr_title(task: Task) -> str:
    return defuse(f"[autofix] {inline(task.title)}")


def mr_body(
    task: Task,
    verdict: Verdict | None,
    summary: str,
    test_output: str,
    cost_usd: float,
) -> str:
    rows = "\n".join(
        f"| {f.severity.name} | `{inline(f.tool)}` | `{inline(f.rule)}` | `{inline(f.location)}` |"
        for f in task.findings
    )
    triage = (
        verdict.reason if verdict else "bug ad alta confidenza dalla revisione del codice recente"
    )
    return defuse(f"""\
Merge Request generata automaticamente da Autofix. **Richiede review umana prima del merge.**

### Finding

| Severità | Tool | Regola | Posizione |
| --- | --- | --- | --- |
{rows}

### Motivazione del triage

{fenced(truncate(triage, 2000))}

### Cosa cambia

{fenced(truncate(summary, 4000))}

### Verifica

Test e scanner rieseguiti in un sandbox pulito, indipendente dall'agente.

<details><summary>Output dei test</summary>

{fenced(truncate(test_output, 6000))}

</details>

Costo del task: ${cost_usd:.2f}
""")
