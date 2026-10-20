"""Parser e protocollo di esecuzione degli scanner, con fixture nei formati JSON reali."""

from __future__ import annotations

from pathlib import Path

import pytest

from maxtac.adapters.scanners import Bandit, Gosec, OsvScanner, ScannerError, Semgrep
from maxtac.domain.models import ExecResult, Severity

FIX = Path(__file__).parent / "fixtures"


class ScriptedSandbox:
    """Risponde al comando dello scanner e poi al `cat` del file JSON."""

    def __init__(self, code: int, payload: str | None) -> None:
        self.code = code
        self.payload = payload
        self.cmds: list[str] = []

    def exec(self, cmd: str, timeout: int) -> ExecResult:
        self.cmds.append(cmd)
        if cmd.startswith("cat "):
            return ExecResult(0, self.payload) if self.payload is not None else ExecResult(1, "")
        return ExecResult(self.code, "")

    def read(self, path: str) -> str:
        raise AssertionError

    def write(self, path: str, content: str) -> None:
        raise AssertionError

    def list_files(self, path: str) -> list[str]:
        raise AssertionError


def fixture(name: str) -> str:
    return (FIX / name).read_text()


def test_osv_groups_aliases_and_skips_node_modules() -> None:
    sb = ScriptedSandbox(1, fixture("osv.json"))
    findings = OsvScanner().scan(sb)
    by_rule = {f.rule: f for f in findings}
    assert set(by_rule) == {"GHSA-x84v-xcm2-53pg", "GHSA-9wx4-h78v-vm56", "GHSA-4v7x-pqxf-cx7m"}
    req = by_rule["GHSA-x84v-xcm2-53pg"]
    assert req.kind == "cve" and req.location == "requests@2.19.0"
    assert req.severity is Severity.HIGH  # max_severity 7.5
    assert "2.20.0" in req.detail and "CVE-2018-18074" in req.detail
    assert by_rule["GHSA-9wx4-h78v-vm56"].severity is Severity.MEDIUM  # da database_specific
    assert by_rule["GHSA-4v7x-pqxf-cx7m"].location == "golang.org/x/net@0.17.0"
    assert all("minimist" not in f.location for f in findings)
    assert "osv-scanner scan source --recursive" in sb.cmds[0]


def test_osv_no_packages_is_empty_and_errors_raise() -> None:
    assert OsvScanner().scan(ScriptedSandbox(128, None)) == []
    with pytest.raises(ScannerError):
        OsvScanner().scan(ScriptedSandbox(127, None))  # comando non trovato
    with pytest.raises(ScannerError):
        OsvScanner().scan(ScriptedSandbox(0, "{not json"))


def test_semgrep_normalizes_paths_and_severity() -> None:
    sb = ScriptedSandbox(0, fixture("semgrep.json"))
    findings = Semgrep(["p/default", "p/python", "p/python"]).scan(sb)
    assert [(f.location, f.severity, f.line) for f in findings] == [
        ("app/runner.py", Severity.HIGH, 12),
        ("internal/token/token.go", Severity.MEDIUM, 7),
    ]
    assert findings[0].rule.endswith("subprocess-shell-true")
    assert "CWE-78" in findings[0].detail
    cmd = sb.cmds[0]
    assert cmd.count("--config p/python") == 1 and "--metrics=off" in cmd
    assert "--exclude node_modules" in cmd


def test_semgrep_fingerprint_ignores_line() -> None:
    a = Semgrep().parse({"results": [{"check_id": "r", "path": "a.py", "start": {"line": 3}}]})
    b = Semgrep().parse({"results": [{"check_id": "r", "path": "./a.py", "start": {"line": 9}}]})
    assert a[0].fingerprint == b[0].fingerprint and a[0].line != b[0].line


def test_bandit_drops_low_confidence() -> None:
    findings = Bandit().scan(ScriptedSandbox(1, fixture("bandit.json")))
    assert [(f.rule, f.severity) for f in findings] == [
        ("B602:subprocess_popen_with_shell_equals_true", Severity.HIGH),
        ("B404:blacklist", Severity.LOW),
    ]
    assert findings[0].location == "app/runner.py" and findings[0].line == 12
    assert Bandit().supports(["python"]) and not Bandit().supports(["go"])


def test_gosec_skips_nosec_and_parses_ranges() -> None:
    findings = Gosec().scan(ScriptedSandbox(0, fixture("gosec.json")))
    assert [(f.rule, f.location, f.line, f.severity) for f in findings] == [
        ("G304", "cmd/fwagent/main.go", 41, Severity.MEDIUM),
        ("G204", "internal/exec/run.go", 18, Severity.HIGH),
    ]
    with pytest.raises(ScannerError):
        Gosec().scan(ScriptedSandbox(1, None))  # con -no-fail, exit 1 è un errore vero
    assert Gosec().supports(["go"]) and not Gosec().supports(["python"])
