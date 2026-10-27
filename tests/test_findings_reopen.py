"""`autofix findings reopen`: un finding ignorato (MR chiusa senza merge, triage) o con la MR
da rifare torna `new`, così la run successiva riapre la MR con il config attuale."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from maxtac import cli
from maxtac.config import load_config
from maxtac.container import Container
from maxtac.domain.models import Finding, FindingStatus, Severity
from maxtac.domain.policy import select_actionable

EXAMPLE = Path(__file__).parent.parent / "config.example.yaml"
NOW = datetime(2026, 10, 27, tzinfo=UTC)


def cve(rule: str, pkg: str = "requests@2.19.0") -> Finding:
    return Finding("cve", "osv-scanner", rule, pkg, Severity.HIGH, "detail")


IGN, IGN2, OPEN, HUMAN = cve("CVE-1"), cve("CVE-2"), cve("CVE-3"), cve("CVE-4")
OTHER = cve("CVE-9")


@pytest.fixture
def cfg(tmp_path):
    data = yaml.safe_load(EXAMPLE.read_text())
    data["workdir"] = str(tmp_path / "work")
    data["db_path"] = str(tmp_path / "db.sqlite3")
    data["web"] = None
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(data))
    c = Container.build(load_config(p))
    try:
        s = c.store
        s.observe("team/api", [IGN, IGN2, OPEN, HUMAN], NOW)
        s.observe("team/agent", [OTHER], NOW)
        s.set_status("team/api", IGN.fingerprint, FindingStatus.IGNORED, "MR chiusa senza merge")
        s.set_status("team/api", IGN2.fingerprint, FindingStatus.IGNORED, "falso positivo")
        s.set_status(
            "team/api", OPEN.fingerprint, FindingStatus.MR_OPEN, "MR aperta", branch="autofix/x"
        )
        s.set_status("team/api", HUMAN.fingerprint, FindingStatus.NEEDS_HUMAN, "test rossi")
        s.record_failed_attempt("team/api", HUMAN.fingerprint, "test rossi")
        s.set_status("team/agent", OTHER.fingerprint, FindingStatus.IGNORED, "MR chiusa")
    finally:
        c.close()
    return p


def status(cfg: Path, project: str, f: Finding):
    c = Container.build(load_config(cfg))
    try:
        return c.store.get(project, f.fingerprint)
    finally:
        c.close()


def reopen(cfg: Path, *args: str) -> int:
    return cli.main(["--config", str(cfg), "findings", "reopen", *args])


def test_reopen_ignored_and_mr_open_of_one_repo(cfg, capsys):
    assert reopen(cfg, "--repo", "team/api") == 0
    assert "3 finding" in capsys.readouterr().out  # due ignorati e la MR da rifare
    for f in (IGN, IGN2, OPEN):
        rec = status(cfg, "team/api", f)
        assert rec.status is FindingStatus.NEW and rec.branch is None and rec.mr_url is None
    # i fix falliti restano un problema da guardare: si riaprono solo se chiesti
    assert status(cfg, "team/api", HUMAN).status is FindingStatus.NEEDS_HUMAN
    assert status(cfg, "team/agent", OTHER).status is FindingStatus.IGNORED  # altro repo


def test_reopened_findings_are_actionable_again(cfg):
    assert reopen(cfg, "--repo", "team/api", "--status", "needs_human") == 0
    rec = status(cfg, "team/api", HUMAN)
    assert rec.status is FindingStatus.NEW and rec.attempts == 0
    assert select_actionable([HUMAN], lambda fp: rec, max_attempts=2) == [HUMAN]
    assert status(cfg, "team/api", IGN).status is FindingStatus.IGNORED  # solo lo stato chiesto


def test_reopen_by_rule(cfg, capsys):
    assert reopen(cfg, "--repo", "team/api", "--rule", "CVE-2") == 0
    assert "1 finding" in capsys.readouterr().out
    assert status(cfg, "team/api", IGN2).status is FindingStatus.NEW
    assert status(cfg, "team/api", IGN).status is FindingStatus.IGNORED


def test_reopen_needs_a_repo_and_reports_nothing_to_do(cfg, capsys):
    assert reopen(cfg) == 2
    assert "serve --repo" in capsys.readouterr().err
    assert reopen(cfg, "--repo", "team/api", "--status", "new") == 2
    assert reopen(cfg, "--repo", "team/nope") == 1
    assert "nessun finding" in capsys.readouterr().err


def test_findings_export_still_works_without_action(cfg, capsys):
    assert cli.main(["--config", str(cfg), "findings", "--repo", "team/api"]) == 0
    assert "CVE-1" in capsys.readouterr().out
