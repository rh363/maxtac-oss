"""Regole pure: dedup, raggruppamento, priorità, rotazione, file protetti, scheduling."""

from __future__ import annotations

import fnmatch
import posixpath
from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

from .models import FileChange, Finding, FindingRecord, FindingStatus, RepoConfig, Task

SUPPRESSED = {FindingStatus.IGNORED, FindingStatus.NEEDS_HUMAN, FindingStatus.MR_OPEN}

# File di test e di CI: se il fix li modifica, la MR va rivista da un umano
# (l'agente potrebbe aver "sistemato" i test invece del codice).
TEST_PATTERNS = (
    "test_*.py",
    "*_test.py",
    "conftest.py",
    "*_test.go",
    "*.test.ts",
    "*.test.js",
    "*.spec.ts",
    "*.spec.js",
)
TEST_DIRS = ("tests", "test", "__tests__", "testdata")
CI_PATTERNS = (
    ".gitlab-ci.yml",
    ".gitlab/*",
    ".github/*",
    "Jenkinsfile",
    "pytest.ini",
    "tox.ini",
    "noxfile.py",
    "Makefile",
)


def branch_name(task: Task, prefix: str = "autofix") -> str:
    return f"{prefix}/{task.kind}/{task.fingerprint}"


def select_actionable(
    findings: Iterable[Finding],
    lookup: Callable[[str], FindingRecord | None],
    max_attempts: int,
) -> list[Finding]:
    """Scarta i finding ignorati, già passati a un umano, con MR aperta o falliti troppe volte."""
    out: list[Finding] = []
    seen: set[str] = set()
    for f in findings:
        if f.fingerprint in seen:
            continue
        seen.add(f.fingerprint)
        rec = lookup(f.fingerprint)
        if rec is not None and (rec.status in SUPPRESSED or rec.attempts >= max_attempts):
            continue
        out.append(f)
    return out


def group_into_tasks(findings: Iterable[Finding]) -> list[Task]:
    """Le CVE dello stesso package diventano un solo bump; SAST e bug restano uno per task."""
    cves: dict[str, list[Finding]] = defaultdict(list)
    tasks: list[Task] = []
    for f in findings:
        if f.kind == "cve":
            cves[f.package].append(f)
        else:
            tasks.append(Task(kind=f.kind, key=f.fingerprint, findings=(f,)))
    for pkg, group in cves.items():
        group.sort(key=lambda f: f.rule)
        tasks.append(Task(kind="cve", key=pkg, findings=tuple(group)))
    return prioritize(tasks)


def prioritize(tasks: Iterable[Task]) -> list[Task]:
    """Severità decrescente; a parità, CVE prima di SAST prima di bug, poi ordine stabile."""
    kind_rank = {"cve": 0, "sast": 1, "bug": 2}
    return sorted(tasks, key=lambda t: (-t.severity, kind_rank[t.kind], t.key))


def pick_hunting_repos(
    repos: Sequence[RepoConfig],
    last_hunted: Callable[[str], datetime | None],
    n: int,
) -> list[RepoConfig]:
    """Rotazione: prima i repo mai cacciati, poi quelli cacciati meno di recente."""

    def key(r: RepoConfig) -> tuple[int, datetime, str]:
        when = last_hunted(r.project)
        return (0, datetime.min, r.project) if when is None else (1, when, r.project)

    return sorted(repos, key=key)[: max(0, n)]


def is_test_path(path: str) -> bool:
    name = posixpath.basename(path)
    parts = path.split("/")[:-1]
    return any(fnmatch.fnmatch(name, p) for p in TEST_PATTERNS) or any(
        d in TEST_DIRS for d in parts
    )


def is_ci_path(path: str) -> bool:
    return any(fnmatch.fnmatch(path, p) for p in CI_PATTERNS)


def protected_changes(changes: Iterable[FileChange]) -> list[str]:
    """File di test esistenti o config CI toccati dal fix. Aggiungere test nuovi è ammesso."""
    out = []
    for c in changes:
        if is_ci_path(c.path) or (c.status != "added" and is_test_path(c.path)):
            out.append(c.path)
    return out


def adds_test(changes: Iterable[FileChange]) -> bool:
    """Per i bug serve un test di regressione nuovo."""
    return any(c.status == "added" and is_test_path(c.path) for c in changes)


def safe_relpath(path: str) -> str:
    """Path dei tool dell'agente: relativi alla working tree, senza uscirne."""
    p = posixpath.normpath(path.strip().lstrip("/") or ".")
    if p == ".." or p.startswith("../"):
        raise ValueError(f"path fuori dalla working tree: {path!r}")
    return p


def truncate(text: str, limit: int) -> str:
    """Tiene testa e coda: gli errori dei test stanno spesso in fondo."""
    if len(text) <= limit:
        return text
    marker = f"\n...[troncati {len(text) - limit} caratteri]...\n"
    keep = max(0, limit - len(marker))
    head = keep // 3
    return text[:head] + marker + text[len(text) - (keep - head) :]


def next_run_at(now: datetime, at: str, timezone: str) -> datetime:
    """Prossima esecuzione all'ora locale `at` (HH:MM) nel fuso indicato."""
    if now.tzinfo is None:
        raise ValueError("now deve avere un fuso orario")
    tz = ZoneInfo(timezone)
    hh, mm = (int(x) for x in at.split(":"))
    local = now.astimezone(tz)
    candidate = datetime.combine(local.date(), time(hh, mm), tzinfo=tz)
    if candidate <= local:
        candidate = datetime.combine(local.date() + timedelta(days=1), time(hh, mm), tzinfo=tz)
    return candidate
