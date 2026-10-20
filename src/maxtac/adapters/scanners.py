"""ScannerPort: osv-scanner, semgrep, bandit e gosec eseguiti nel sandbox.

Ogni scanner scrive JSON su un file in /tmp del sandbox; l'output viene letto e normalizzato
in `Finding`. Il fingerprint non contiene la riga: la riga va in `Finding.line`.
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Iterable, Sequence
from typing import Any

from maxtac.domain.models import Finding, Severity
from maxtac.domain.ports import Sandbox

OUT_DIR = "/tmp/autofix-scan"
WORK = "/work"
# Binari per path assoluto: la working tree e la home sono scrivibili dal codice del repo,
# un `semgrep` o un `cat` finto messo lì non deve mai prendere il posto di quello vero.
BIN = "/usr/local/bin"
SH = {"mkdir": "/bin/mkdir", "rm": "/bin/rm", "cat": "/bin/cat", "touch": "/usr/bin/touch"}
# Ruleset semgrep scaricati al build dell'immagine (sandbox/Dockerfile): niente rete a runtime.
SEMGREP_RULES_DIR = "/opt/semgrep-rules"
# Config vuota per osv-scanner: mai quella del repo (potrebbe ignorare le vulnerabilità).
OSV_EMPTY_CONFIG = f"{OUT_DIR}/osv-scanner-empty.toml"
# Directory di dipendenze installate dal setup: non sono codice del repo.
EXCLUDED_DIRS = frozenset({"node_modules", ".venv", "venv", ".tox", ".nox", "site-packages"})
DETAIL_LIMIT = 4000


class ScannerError(RuntimeError):
    pass


def rel(path: str) -> str:
    p = path.strip()
    if p.startswith(WORK + "/"):
        p = p[len(WORK) + 1 :]
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def excluded(path: str) -> bool:
    return any(part in EXCLUDED_DIRS for part in rel(path).split("/"))


def cvss_severity(score: str | None) -> Severity | None:
    try:
        v = float(score or "")
    except ValueError:
        return None
    if v >= 9.0:
        return Severity.CRITICAL
    if v >= 7.0:
        return Severity.HIGH
    if v >= 4.0:
        return Severity.MEDIUM
    if v > 0:
        return Severity.LOW
    return None


def first_line(line: Any) -> int | None:
    m = re.match(r"\s*(\d+)", str(line)) if line is not None else None
    return int(m.group(1)) if m else None


class _JsonScanner:
    name: str
    kind: str
    timeout: int = 1200
    ok_codes: frozenset[int] = frozenset({0})
    empty_codes: frozenset[int] = frozenset()  # exit code che significano "niente da scansionare"

    def supports(self, languages: Sequence[str]) -> bool:
        raise NotImplementedError

    def _command(self, out: str) -> str:
        raise NotImplementedError

    def parse(self, data: dict[str, Any]) -> list[Finding]:
        raise NotImplementedError

    def scan(self, sandbox: Sandbox) -> list[Finding]:
        out = f"{OUT_DIR}/{self.name}.json"
        prepare = f"{SH['mkdir']} -p {OUT_DIR} && {SH['rm']} -f {out}"
        r = sandbox.exec(f"{prepare} && {self._command(out)}", self.timeout)
        if r.code in self.empty_codes:
            return []
        if r.code not in self.ok_codes:
            raise ScannerError(f"{self.name} exit={r.code}: {r.output[-2000:]}")
        raw = sandbox.exec(f"{SH['cat']} {out}", timeout=120)
        if not raw.ok:
            raise ScannerError(f"{self.name}: output JSON mancante")
        try:
            data = json.loads(raw.output)
        except json.JSONDecodeError as e:
            raise ScannerError(f"{self.name}: JSON non valido ({e})") from None
        if not isinstance(data, dict):
            raise ScannerError(f"{self.name}: JSON inatteso")
        return self.parse(data)


class OsvScanner(_JsonScanner):
    """CVE nelle dipendenze dai lockfile (requirements, poetry, uv, go.mod, package-lock...)."""

    name = "osv-scanner"
    kind = "cve"
    ok_codes = frozenset({0, 1})  # 1 = vulnerabilità trovate
    empty_codes = frozenset({128})  # nessun lockfile/package trovato

    def supports(self, languages: Sequence[str]) -> bool:
        return bool(languages)

    def _command(self, out: str) -> str:
        # Database offline nell'immagine (ricostruita ogni settimana) e config vuota esplicita.
        return (
            f"{SH['rm']} -f {OSV_EMPTY_CONFIG} && {SH['touch']} {OSV_EMPTY_CONFIG} && "
            f"{BIN}/osv-scanner scan source --recursive "
            f"--offline-vulnerabilities --config {OSV_EMPTY_CONFIG} "
            f"--format json --output {out} {WORK}"
        )

    def parse(self, data: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for result in data.get("results") or []:
            source = rel(str((result.get("source") or {}).get("path", "")))
            if excluded(source):
                continue
            for pkg in result.get("packages") or []:
                findings.extend(self._package(pkg, source))
        return findings

    def _package(self, pkg: dict[str, Any], source: str) -> Iterable[Finding]:
        info = pkg.get("package") or {}
        name, version = info.get("name"), info.get("version")
        if not name or not version:
            return
        vulns = {v.get("id"): v for v in pkg.get("vulnerabilities") or [] if v.get("id")}
        groups = pkg.get("groups") or [
            {"ids": [i], "aliases": [], "max_severity": ""} for i in vulns
        ]
        for g in groups:
            ids = [i for i in g.get("ids") or [] if i]
            if not ids:
                continue
            aliases = sorted(set(ids) | set(g.get("aliases") or []))
            ghsa = sorted(a for a in aliases if a.startswith("GHSA-"))
            rule = ghsa[0] if ghsa else ids[0]
            main: dict[str, Any] = next((vulns[i] for i in ids if i in vulns), {})
            severity = cvss_severity(g.get("max_severity")) or Severity.parse(
                (main.get("database_specific") or {}).get("severity")
            )
            if severity is Severity.INFO:
                severity = Severity.MEDIUM  # advisory senza punteggio: non la si scarta
            fixed = sorted(
                {
                    ev["fixed"]
                    for i in ids
                    for aff in (vulns.get(i) or {}).get("affected") or []
                    for rng in aff.get("ranges") or []
                    for ev in rng.get("events") or []
                    if "fixed" in ev
                }
            )
            detail = "\n".join(
                x
                for x in (
                    str(main.get("summary") or ""),
                    f"Alias: {', '.join(aliases)}",
                    f"Versioni corrette: {', '.join(fixed) or 'nessuna nota'}",
                    f"Ecosistema: {info.get('ecosystem', '?')}, file: {source}",
                    str(main.get("details") or "")[:1500],
                )
                if x
            )
            yield Finding(
                "cve", self.name, rule, f"{name}@{version}", severity, detail[:DETAIL_LIMIT]
            )


class Semgrep(_JsonScanner):
    name = "semgrep"
    kind = "sast"
    ok_codes = frozenset({0, 1})

    def __init__(self, rulesets: Sequence[str] = ("p/default",)) -> None:
        self.rulesets = tuple(dict.fromkeys(rulesets))

    def supports(self, languages: Sequence[str]) -> bool:
        return bool(languages)

    def _command(self, out: str) -> str:
        configs = " ".join(f"--config {shlex.quote(semgrep_rules_file(r))}" for r in self.rulesets)
        excludes = " ".join(f"--exclude {d}" for d in sorted(EXCLUDED_DIRS))
        # --disable-nosem: un `# nosemgrep` aggiunto dall'agente non fa sparire il finding
        return (
            f"cd {WORK} && {BIN}/semgrep scan --metrics=off --disable-version-check --quiet "
            f"--disable-nosem --json --output {out} {excludes} {configs} ."
        )

    def parse(self, data: dict[str, Any]) -> list[Finding]:
        out = []
        for r in data.get("results") or []:
            path, rule = rel(str(r.get("path", ""))), r.get("check_id")
            if not rule or not path or excluded(path):
                continue
            extra = r.get("extra") or {}
            meta = extra.get("metadata") or {}
            cwe = ", ".join(meta.get("cwe") or [])
            detail = "\n".join(x for x in (str(extra.get("message", "")), cwe) if x)
            out.append(
                Finding(
                    "sast",
                    self.name,
                    str(rule),
                    path,
                    Severity.parse(extra.get("severity")),
                    detail[:DETAIL_LIMIT],
                    line=first_line((r.get("start") or {}).get("line")),
                )
            )
        return out


class Bandit(_JsonScanner):
    name = "bandit"
    kind = "sast"
    ok_codes = frozenset({0, 1})  # 1 = issue trovate

    def supports(self, languages: Sequence[str]) -> bool:
        return "python" in languages

    def _command(self, out: str) -> str:
        skip = ",".join(f"*/{d}/*" for d in [*sorted(EXCLUDED_DIRS), "tests", "test"])
        return (
            f"cd {WORK} && {BIN}/bandit -r . -f json -o {out} -q --ignore-nosec "
            f"-x {shlex.quote(skip)}"
        )

    def parse(self, data: dict[str, Any]) -> list[Finding]:
        out = []
        for r in data.get("results") or []:
            path = rel(str(r.get("filename", "")))
            if not path or excluded(path) or str(r.get("issue_confidence", "")).upper() == "LOW":
                continue
            cwe = (r.get("issue_cwe") or {}).get("id")
            detail = (
                f"{r.get('issue_text', '')}\nCWE-{cwe}" if cwe else str(r.get("issue_text", ""))
            )
            out.append(
                Finding(
                    "sast",
                    self.name,
                    f"{r.get('test_id')}:{r.get('test_name')}",
                    path,
                    Severity.parse(r.get("issue_severity")),
                    detail[:DETAIL_LIMIT],
                    line=first_line(r.get("line_number")),
                )
            )
        return out


class Gosec(_JsonScanner):
    name = "gosec"
    kind = "sast"

    def supports(self, languages: Sequence[str]) -> bool:
        return "go" in languages

    def _command(self, out: str) -> str:
        return (
            f"cd {WORK} && {BIN}/gosec -quiet -no-fail -nosec -fmt=json -out={out} "
            "-exclude-dir=vendor -exclude-dir=testdata ./..."
        )

    def parse(self, data: dict[str, Any]) -> list[Finding]:
        out = []
        for r in data.get("Issues") or []:
            path = rel(str(r.get("file", "")))
            if not path or excluded(path):
                continue
            cwe = (r.get("cwe") or {}).get("id")
            detail = f"{r.get('details', '')}\nCWE-{cwe}" if cwe else str(r.get("details", ""))
            out.append(
                Finding(
                    "sast",
                    self.name,
                    str(r.get("rule_id")),
                    path,
                    Severity.parse(r.get("severity")),
                    detail[:DETAIL_LIMIT],
                    line=first_line(r.get("line")),
                )
            )
        return out


def semgrep_rules_file(ruleset: str) -> str:
    """`p/default` -> `/opt/semgrep-rules/p-default.yml`; un path assoluto resta com'è."""
    if ruleset.startswith("/"):
        return ruleset
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", ruleset).strip("-")
    return f"{SEMGREP_RULES_DIR}/{slug}.yml"


def build_scanners(semgrep_rulesets: Sequence[str]) -> list[_JsonScanner]:
    return [OsvScanner(), Semgrep(semgrep_rulesets), Bandit(), Gosec()]
