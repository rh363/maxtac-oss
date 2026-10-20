"""`run --scan-only`: checkout e scan con adapter finti, nessuna scrittura sullo store."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from maxtac import cli
from maxtac.container import Container
from maxtac.services.scan import ScanService

from .fakes import FakeGitLab, FakeSandboxes, FakeScanner, FakeVCS, eval_sast, requests_cve

EXAMPLE = Path(__file__).parent.parent / "config.example.yaml"


def _config(tmp_path: Path) -> Path:
    data = yaml.safe_load(EXAMPLE.read_text())
    data["workdir"] = str(tmp_path / "work")
    data["db_path"] = str(tmp_path / "db.sqlite3")
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def test_scan_only_lists_normalized_findings(tmp_path: Path, monkeypatch: Any, capsys: Any) -> None:
    gl = FakeGitLab(
        repos={
            "alex/ecs2": {"requirements.txt": "requests==2.19.0\n", "app.py": "eval(x)\n"},
            "alex/fwagent": {"go.mod": "module x\n"},
        }
    )
    gl.broken.add("alex/fwagent")
    vcs = FakeVCS(gl)

    def scan_service(self: Container) -> ScanService:
        return ScanService(
            vcs=vcs,
            sandboxes=FakeSandboxes(vcs),
            scanners=[
                FakeScanner("osv-scanner", "cve", requests_cve, ["python", "go"]),
                FakeScanner("semgrep", "sast", eval_sast, ["python", "go"]),
            ],
            kinds=frozenset({"cve", "sast"}),
            workdir=self.config.workdir,
        )

    monkeypatch.setattr(Container, "scan_service", scan_service)
    code = cli.main(["--config", str(_config(tmp_path)), "--as", "capo", "run", "--scan-only"])
    out = capsys.readouterr().out
    assert code == 1  # fwagent esplode, ecs2 viene comunque scansionato
    assert "GHSA-x84v-xcm2-53pg @ requests@2.19.0" in out
    assert "python.lang.security.audit.eval" in out
    files = list((tmp_path / "work").glob("*/findings.json"))
    data = json.loads(files[0].read_text())
    ecs2 = next(r for r in data["repos"] if r["project"] == "alex/ecs2")
    assert {f["kind"] for f in ecs2["findings"]} == {"cve", "sast"}
    assert all(f["status"] == "new" for f in ecs2["findings"])
    fw = next(r for r in data["repos"] if r["project"] == "alex/fwagent")
    assert fw["errors"]
    assert not gl.pushed and not gl.mrs


def test_scan_only_without_token_fails_clearly(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    code = cli.main(["--config", str(_config(tmp_path)), "run", "--scan-only"])
    assert code == 2 and "token GitLab mancante" in capsys.readouterr().err
