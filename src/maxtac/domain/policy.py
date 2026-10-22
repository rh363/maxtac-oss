"""Regole pure: dedup, raggruppamento, priorità, rotazione, file protetti, scheduling."""

from __future__ import annotations

import base64
import fnmatch
import json
import posixpath
import re
import tomllib
from collections import defaultdict
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from typing import Literal
from zoneinfo import ZoneInfo

from .models import (
    FileChange,
    Finding,
    FindingRecord,
    FindingStatus,
    RepoConfig,
    RepoProposal,
    Severity,
    Task,
    TokenInfo,
)

SUPPRESSED = {FindingStatus.IGNORED, FindingStatus.NEEDS_HUMAN, FindingStatus.MR_OPEN}

# File di test: per CVE e SAST il fix non deve toccarli (nemmeno aggiungerne), per i bug
# può solo aggiungere test nuovi. L'agente potrebbe "sistemare" i test invece del codice.
TEST_PATTERNS = (
    "test_*.py",
    "*_test.py",
    "*_test.go",
    "*.test.ts",
    "*.test.js",
    "*.test.tsx",
    "*.test.jsx",
    "*.spec.ts",
    "*.spec.js",
)
TEST_DIRS = ("tests", "test", "__tests__", "testdata")
# Config di CI, dei test runner e degli scanner: protetta ovunque nel repo (basename).
PROTECTED_NAMES = (
    ".gitlab-ci.yml",
    "Jenkinsfile",
    "conftest.py",
    "pytest.ini",
    "tox.ini",
    "noxfile.py",
    "setup.cfg",
    ".coveragerc",
    "Makefile",
    "GNUmakefile",
    "jest.config.*",
    "vitest.config.*",
    "vitest.workspace.*",
    "karma.conf.*",
    ".mocharc*",
    "playwright.config.*",
    ".semgrepignore",
    ".semgrep*",
    ".bandit",
    "bandit.yaml",
    "bandit.yml",
    "osv-scanner.toml",
    ".gosec*",
    ".pre-commit-config.yaml",
)
PROTECTED_DIRS = (".gitlab", ".github")
# Manifest che un bump di CVE deve poter toccare: protetti solo se cambia la parte che
# configura test o scanner (confronto sul contenuto parsato, non sul testo).
SEMANTIC_MANIFESTS = ("pyproject.toml", "package.json")
PYPROJECT_GUARDED = ("pytest", "coverage", "bandit", "semgrep", "hatch", "tox")
PACKAGE_JSON_GUARDED = ("scripts", "jest", "vitest", "mocha", "ava", "c8", "nyc")

# Euristica sui test di regressione aggiunti: chi esce dal processo o salta la suite
# può far risultare verde qualunque cosa. Non è una prova, ma blocca i casi ovvi.
SUSPICIOUS_TEST_MARKERS = (
    "os._exit",
    "sys.exit",
    "SystemExit",
    "pytest.exit",
    "TestMain",
    "os.Exit",
    "process.exit",
    "collect_ignore",
    "pytest_collection_modifyitems",
)

Versions = Callable[[str], tuple[str | None, str | None]]


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
    hunt_count: Callable[[str], int] = lambda project: 0,
) -> list[RepoConfig]:
    """Rotazione: prima i repo mai cacciati, poi quelli cacciati meno di recente.

    I repo cacciati nella stessa notte hanno lo stesso istante (l'inizio della run): a parità
    vince chi è stato cacciato meno volte, così l'ordine nel file di config non favorisce
    sempre i primi repo.
    """

    def key(r: RepoConfig) -> tuple[int, datetime, int, str]:
        when = last_hunted(r.project)
        if when is None:
            return (0, datetime.min, 0, r.project)
        return (1, when, hunt_count(r.project), r.project)

    return sorted(repos, key=key)[: max(0, n)]


def is_test_path(path: str) -> bool:
    name = posixpath.basename(path)
    parts = path.split("/")[:-1]
    return any(fnmatch.fnmatch(name, p) for p in TEST_PATTERNS) or any(
        d in TEST_DIRS for d in parts
    )


def is_protected_config(path: str) -> bool:
    name = posixpath.basename(path)
    parts = path.split("/")[:-1]
    return any(fnmatch.fnmatch(name, p) for p in PROTECTED_NAMES) or any(
        d in PROTECTED_DIRS for d in parts
    )


def _guarded_sections(name: str, text: str | None) -> object:
    if text is None:
        return None
    if name == "pyproject.toml":
        tool = tomllib.loads(text).get("tool", {})
        return {k: tool.get(k) for k in PYPROJECT_GUARDED}
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("package.json non è un oggetto")
    return {k: data.get(k) for k in PACKAGE_JSON_GUARDED}


def manifest_guard_changed(path: str, old: str | None, new: str | None) -> bool:
    """True se cambia la config di test/scanner dentro pyproject.toml o package.json.
    Un file che non si riesce a parsare conta come cambiato."""
    name = posixpath.basename(path)
    try:
        return _guarded_sections(name, old) != _guarded_sections(name, new)
    except (ValueError, tomllib.TOMLDecodeError):
        return True


def protected_changes(
    changes: Iterable[FileChange], kind: str, versions: Versions | None = None
) -> list[str]:
    """Modifiche che il fix non può fare da solo: la MR passa a un umano.

    - symlink e gitlink, ovunque;
    - config di CI, test runner e scanner, ovunque nel repo;
    - test: per CVE e SAST qualunque modifica (anche aggiunte), per i bug solo i nuovi;
    - pyproject.toml / package.json: per SAST e bug sempre, per le CVE solo se cambiano
      le sezioni dei test o degli scanner (serve `versions`, altrimenti protetti).
    """
    out = []
    for c in changes:
        if c.kind != "file" or is_protected_config(c.path):
            out.append(c.path)
        elif is_test_path(c.path):
            if kind != "bug" or c.status != "added":
                out.append(c.path)
        elif posixpath.basename(c.path) in SEMANTIC_MANIFESTS and (
            kind != "cve" or versions is None or manifest_guard_changed(c.path, *versions(c.path))
        ):
            out.append(c.path)
    return out


def suspicious_test_content(text: str) -> list[str]:
    return [m for m in SUSPICIOUS_TEST_MARKERS if m in text]


def adds_test(changes: Iterable[FileChange]) -> bool:
    """Per i bug serve un test di regressione nuovo."""
    return bool(added_tests(changes))


def added_tests(changes: Iterable[FileChange]) -> list[str]:
    return [
        c.path for c in changes if c.status == "added" and c.kind == "file" and is_test_path(c.path)
    ]


# Un fix non deve introdurre finding nuovi dello stesso scanner. Sotto questa soglia
# (es. bandit B603 dopo aver tolto shell=True) il finding nuovo è rumore e non blocca.
NEW_FINDING_MIN_SEVERITY = Severity.MEDIUM


def introduced_findings(
    task: Task,
    found: Iterable[Finding],
    baseline: Collection[str],
    touched: Collection[str],
    min_severity: Severity = NEW_FINDING_MIN_SEVERITY,
) -> list[Finding]:
    """Finding emersi dopo il fix e assenti nello scan iniziale della notte.

    Per SAST contano solo i file toccati dal fix (il resto del repo non è cambiato); per le
    CVE conta tutto, perché la location è `package@versione` (es. un bump verso una
    versione a sua volta vulnerabile).
    """
    return [
        f
        for f in found
        if f.fingerprint not in baseline
        and f.severity >= min_severity
        and (task.kind == "cve" or f.location in touched)
    ]


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


# --- comandi proposti dall'autodiscovery (input non fidato) ---

TEST_RUNNERS = re.compile(
    r"""(?x)(^|[\s;&|(])(
        pytest | py\.test | python(3(\.\d+)?)?\s+-m\s+(pytest|unittest) | tox | nox | hatch\s+test
      | (uv|poetry|pdm|pipenv)\s+run\s+(pytest|python(3(\.\d+)?)?\s+-m\s+(pytest|unittest)|tox|nox)
      | go\s+test
      | (npm|pnpm|yarn|bun)\s+(run\s+)?test(:\S+)? | npx\s+(jest|vitest|mocha) | jest | vitest
      | make\s+(test|check)\b
    )"""
)
TRIVIAL_COMMANDS = {"", "true", ":", "/bin/true", "exit 0", "exit", "echo", "yes", "sleep"}
SWALLOW_FAILURE = re.compile(r"\|\|\s*(true|:|exit\s+0|echo\b)|;\s*(true|exit\s+0)\s*$")
NETWORK_TOOLS = re.compile(
    r"(^|[\s;&|(`$])(curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|rsync|ftp|telnet)(\s|$)"
)
PUBLISH = re.compile(
    r"(git\s+push|twine\s+upload|npm\s+publish|pnpm\s+publish|yarn\s+publish|"
    r"poetry\s+publish|uv\s+publish|docker\s+(push|login))"
)
OUTSIDE_REDIRECT = re.compile(r">>?\s*(/(?!work(/|\s|$)|tmp(/|\s|$)|dev/null)\S*|\S*\.\./\S*)")
PRIVILEGE = re.compile(r"(^|[\s;&|(])(sudo|su|doas|chmod\s+[0-7]*777|chown)(\s|$)")


def command_suspicions(setup_command: str | None, test_command: str) -> list[str]:
    """Motivi per cui una coppia setup/test scoperta automaticamente va guardata da un umano.

    È un'euristica, non un sandbox: i comandi girano comunque solo nel sandbox, e diventano
    config di fiducia solo con l'approvazione esplicita dell'operatore.
    """
    out: list[str] = []
    test = test_command.strip()
    if test.rstrip(";").strip() in TRIVIAL_COMMANDS or test.startswith(("echo ", "exit ")):
        out.append("test_command banale: non esegue alcun test")
    elif not TEST_RUNNERS.search(test):
        out.append("test_command senza un test runner noto")
    for label, cmd in (("setup_command", setup_command or ""), ("test_command", test)):
        if not cmd:
            continue
        if SWALLOW_FAILURE.search(cmd):
            out.append(f"{label} ignora i fallimenti (|| true, ; exit 0...)")
        if NETWORK_TOOLS.search(cmd):
            out.append(f"{label} usa strumenti di rete (curl, wget, ssh...)")
        if PUBLISH.search(cmd):
            out.append(f"{label} pubblica o fa push")
        if OUTSIDE_REDIRECT.search(cmd):
            out.append(f"{label} scrive fuori da /work")
        if PRIVILEGE.search(cmd):
            out.append(f"{label} chiede privilegi (sudo, chmod 777...)")
    return out


def merge_repos(manual: Sequence[RepoConfig], approved: Iterable[RepoConfig]) -> list[RepoConfig]:
    """Repo scritti a mano nel config più quelli approvati dall'autodiscovery.

    In caso di conflitto vince il config: è la fonte di fiducia scritta dall'operatore.
    """
    known = {r.project for r in manual}
    return [*manual, *(r for r in approved if r.project not in known)]


SPEND_CATEGORIES = ("triage", "fix", "hunt", "discovery")


def spend_category(scope: str) -> str:
    """Categoria di una spesa dal suo scope (`fix:<repo>:<task>`, `triage:<repo>`...)."""
    head = scope.split(":", 1)[0]
    return head if head in SPEND_CATEGORIES else "other"


def approval_blockers(p: RepoProposal) -> list[str]:
    """Motivi per cui una proposta dell'autodiscovery si approva solo con `--force`."""
    problems = []
    if p.baseline_ok is not True:
        problems.append("baseline non verde")
    problems += list(p.suspicious)
    if not p.languages:
        problems.append("nessun linguaggio")
    return problems


# --- token GitLab ---

TOKEN_EXPIRY_WARNING_DAYS = 30


def covers(prefix: str, project: str) -> bool:
    """`backend` copre `backend/x` e `backend/sub/y`, non `backend2/x`. "" copre tutto."""
    return prefix == "" or project == prefix or project.startswith(prefix + "/")


def resolve_token(project: str, scopes: Mapping[str, Sequence[str]]) -> str | None:
    """Nome del token con il prefisso più specifico che copre `project`, o None.

    I prefissi sono unici tra i token (lo garantisce la config): a parità di lunghezza due
    prefissi che coprono lo stesso progetto sarebbero identici, quindi non c'è pareggio.
    """
    best: tuple[int, str] | None = None
    for name, prefixes in scopes.items():
        for prefix in prefixes:
            if covers(prefix, project) and (best is None or len(prefix) > best[0]):
                best = (len(prefix), name)
    return best[1] if best else None


TokenState = Literal["ok", "expiring", "expired", "unknown", "error"]


def token_state(info: TokenInfo, today: date) -> TokenState:
    """ok | expiring | expired | unknown | error."""
    if info.error:
        return "error"
    if info.expires_at is None:
        return "unknown"
    days = (info.expires_at - today).days
    if days < 0:
        return "expired"
    return "expiring" if days <= TOKEN_EXPIRY_WARNING_DAYS else "ok"


# --- registry interni del sandbox ---


def registry_conflicts(domains: Iterable[str], gitlab_host: str) -> list[str]:
    """Voci dell'allowlist del proxy che lascerebbero il sandbox raggiungere GitLab: l'host
    stesso, un `.dominio` di squid o un dominio padre (per prudenza, anche senza punto)."""
    host = gitlab_host.strip().lower().rsplit("@", 1)[-1].split(":", 1)[0].rstrip(".")
    out = []
    for d in domains:
        bare = d.strip().lower().rstrip(".").lstrip(".")
        if bare and (host == bare or host.endswith("." + bare)):
            out.append(d)
    return out


@dataclass(frozen=True)
class Redactor:
    """Credenziali dei registry date al sandbox: non devono mai uscire verso GitLab, report o
    webhook. Oscura password, `utente:password` e la sua forma base64 (header Basic)."""

    secrets: tuple[str, ...] = ()

    @classmethod
    def for_credentials(cls, creds: Iterable[tuple[str, str]]) -> Redactor:
        values: set[str] = set()
        for user, password in creds:
            pair = f"{user}:{password}"
            values |= {password, pair, base64.b64encode(pair.encode()).decode()}
        # le più lunghe prima: `utente:password` sparisce intero, non solo la password
        return cls(tuple(sorted((v for v in values if v), key=len, reverse=True)))

    def redact(self, text: str) -> str:
        for s in self.secrets:
            text = text.replace(s, "***")
        return text

    def leaks(self, text: str) -> bool:
        return any(s in text for s in self.secrets)
