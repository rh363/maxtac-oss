"""Testo di commit e MR. Su GitLab il lessico è sempre neutro, qualunque tema usi l'operatore."""

from __future__ import annotations

from maxtac.domain.models import Task, Verdict
from maxtac.domain.policy import truncate


def commit_message(task: Task) -> str:
    rules = "\n".join(f"- {f.tool}: {f.rule} ({f.location})" for f in task.findings)
    return f"autofix: {task.title}\n\n{rules}\n"


def mr_title(task: Task) -> str:
    return f"[autofix] {task.title}"


def _quote(text: str) -> str:
    return "\n".join(f"> {line}" for line in text.strip().splitlines()) or "> (nessuno)"


def mr_body(
    task: Task,
    verdict: Verdict | None,
    summary: str,
    test_output: str,
    cost_usd: float,
) -> str:
    rows = "\n".join(
        f"| {f.severity.name} | `{f.tool}` | `{f.rule}` | `{f.location}` |" for f in task.findings
    )
    triage = (
        verdict.reason if verdict else "bug ad alta confidenza dalla revisione del codice recente"
    )
    return f"""\
Merge Request generata automaticamente da Autofix. **Richiede review umana prima del merge.**

### Finding

| Severità | Tool | Regola | Posizione |
| --- | --- | --- | --- |
{rows}

### Motivazione del triage

{_quote(triage)}

### Cosa cambia

{_quote(truncate(summary, 4000))}

### Verifica

Test e scanner rieseguiti in un sandbox pulito, indipendente dall'agente.

<details><summary>Output dei test</summary>

```
{truncate(test_output, 6000).replace("```", "'''")}
```

</details>

Costo del task: ${cost_usd:.2f}
"""
