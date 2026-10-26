"""CLI `maxtac repos`: discovery, approvazione e unione con il config."""

import argparse
from pathlib import Path

import pytest
import yaml

from maxtac import cli, cli_repos
from maxtac.config import load_config
from maxtac.container import Container
from maxtac.domain.models import ExecResult, RepoProposal
from maxtac.services.discovery import Discovery, DiscoverySettings

from .conftest import PRICING
from .fakes import FakeClock, FakeGitLab, FakeSandboxes, FakeVCS

EXAMPLE = Path(__file__).parent.parent / "config.example.yaml"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    data = yaml.safe_load(EXAMPLE.read_text())
    data["workdir"] = str(tmp_path / "work")
    data["db_path"] = str(tmp_path / "db.sqlite3")
    data["web"] = None
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump(data))
    gl = FakeGitLab(
        repos={
            "team/api": {"requirements.txt": "x\n"},  # già nel config
            "team/new": {"go.mod": "module x\n"},
            "team/red": {"requirements.txt": "x\n"},
        }
    )
    vcs = FakeVCS(gl)

    def handler(cmd, files):
        return (
            ExecResult(1, "fail")
            if "pytest" in cmd and "requirements.txt" in files
            else ExecResult(0, "ok")
        )

    def fake_discovery(self, *, use_llm):
        return Discovery(
            vcs=vcs,
            sandboxes=FakeSandboxes(vcs, handler),
            llm=None,
            registry=self.registry,
            budget=self.budget,
            pricing=PRICING,
            settings=DiscoverySettings("claude-haiku-5-5", 0.15, 4, tmp_path / "work"),
            clock=FakeClock(),
        )

    monkeypatch.setattr(Container, "discovery", fake_discovery)
    return cfg_path


def main(cfg_path, *args):
    return cli.main(["--config", str(cfg_path), "repos", *args])


def test_discover_list_show_approve_flow(setup, capsys):
    assert main(setup, "discover", "--project", "team/new", "--project", "team/api") == 0
    out = capsys.readouterr().out
    assert "go test ./..." in out and "autofix repos approve team/new" in out
    assert "team/api: è nel config.yaml" in out

    assert main(setup, "list") == 0
    out = capsys.readouterr().out
    assert "team/api" in out and "config" in out and "in attesa (baseline verde)" in out

    assert main(setup, "show", "team/new") == 0
    assert "baseline:       verde" in capsys.readouterr().out

    assert main(setup, "approve", "team/new") == 0
    c = Container.build(load_config(setup))
    try:
        assert [r.project for r in c.repos()] == ["team/api", "team/agent", "team/new"]
    finally:
        c.close()


def test_red_baseline_needs_force(setup, capsys):
    assert main(setup, "discover", "--project", "team/red") == 0
    assert main(setup, "approve", "team/red") == 1
    assert "baseline non verde" in capsys.readouterr().err
    assert main(setup, "approve", "team/red", "--force") == 0


def test_discover_all_skips_known_projects(setup, capsys):
    assert main(setup, "discover", "--all") == 0
    out = capsys.readouterr().out
    assert "2 progetti da esaminare" in out  # team/api è nel config
    assert main(setup, "approve", "team/new") == 0
    assert main(setup, "discover", "--all") == 0
    # team/new approvato e team/red in attesa: niente da esaminare
    assert "0 progetti da esaminare" in capsys.readouterr().out


def test_approve_with_edit_rechecks_commands(setup, capsys):
    assert main(setup, "discover", "--project", "team/new") == 0
    c = Container.build(load_config(setup))

    def editor(path):
        data = yaml.safe_load(path.read_text())
        data["test_command"] = "go test ./... || true"
        path.write_text(yaml.safe_dump(data))

    def fixed(path):
        data = yaml.safe_load(path.read_text())
        data["test_command"] = "go test -race ./..."
        path.write_text(yaml.safe_dump(data))

    try:
        args = argparse.Namespace(project="team/new", edit=True, force=False)
        assert cli_repos.cmd_approve(c, args, editor=editor) == 1
        assert "ignora i fallimenti" in capsys.readouterr().err
        assert c.registry.approved("team/new") is None
        assert cli_repos.cmd_approve(c, args, editor=fixed) == 0
        approved = c.registry.approved("team/new")
        assert approved is not None and approved.repo.test_command == "go test -race ./..."
    finally:
        c.close()


def test_reject_and_remove(setup, capsys):
    assert main(setup, "discover", "--project", "team/new") == 0
    assert main(setup, "reject", "team/new") == 0
    assert main(setup, "approve", "team/new") == 1
    assert main(setup, "remove", "team/api") == 1  # sta nel config
    assert "config.yaml" in capsys.readouterr().err
    assert main(setup, "discover", "--project", "team/new") == 0
    assert main(setup, "approve", "team/new") == 0
    assert main(setup, "remove", "team/new") == 0
    assert main(setup, "remove", "team/new") == 1


def test_approve_scan_only_needs_no_green_baseline(setup, capsys):
    """Solo scan: setup e test non girano mai, quindi la baseline rossa non blocca."""
    assert main(setup, "discover", "--project", "team/red") == 0
    assert main(setup, "approve", "team/red", "--scan-only") == 0
    assert "solo scan" in capsys.readouterr().out
    c = Container.build(load_config(setup))
    try:
        [red] = [r for r in c.repos() if r.project == "team/red"]
        assert red.scan_only
    finally:
        c.close()
    assert main(setup, "list") == 0
    assert "solo scan" in capsys.readouterr().out


def test_scan_only_in_config(tmp_path):
    data = yaml.safe_load(EXAMPLE.read_text())
    data["repos"][0]["scan_only"] = True
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(data))
    repos = load_config(p).to_repos()
    assert repos[0].scan_only and not repos[1].scan_only


def test_export_writes_approved_repos_as_config(setup, capsys, tmp_path):
    """Gli approvati escono nel formato di `repos:`, pronti da spostare nel config.yaml."""
    assert main(setup, "discover", "--project", "team/new", "--project", "team/red") == 0
    assert main(setup, "approve", "team/new") == 0
    assert main(setup, "approve", "team/red", "--scan-only") == 0
    capsys.readouterr()

    assert main(setup, "export") == 0
    out = capsys.readouterr().out
    assert out.startswith("# ") and "default_branch" in out  # il commento spiega come usarlo
    repos = yaml.safe_load(out)["repos"]
    assert [r["project"] for r in repos] == ["team/new", "team/red"]  # team/api è già nel config
    assert repos[0] == {
        "project": "team/new",
        "languages": ["go"],
        "setup_command": "go mod download",
        "test_command": "go test ./...",
    }
    assert repos[1]["scan_only"] is True

    # incollati sotto `repos:` il config li carica uguali
    data = yaml.safe_load(setup.read_text())
    data["repos"] += repos
    p = tmp_path / "merged.yaml"
    p.write_text(yaml.safe_dump(data))
    loaded = {r.project: r for r in load_config(p).to_repos()}
    assert loaded["team/new"].test_command == "go test ./..." and loaded["team/red"].scan_only

    out_file = tmp_path / "export.yaml"
    assert main(setup, "export", "--project", "team/red", "-o", str(out_file)) == 0
    assert [r["project"] for r in yaml.safe_load(out_file.read_text())["repos"]] == ["team/red"]
    assert main(setup, "export", "--project", "team/nope") == 1
    assert "team/nope" in capsys.readouterr().err


def test_export_keeps_long_commands_on_one_line(setup, capsys):
    assert main(setup, "discover", "--project", "team/new") == 0
    c = Container.build(load_config(setup))
    long_cmd = "go test " + " ".join(f"./pkg{i}/..." for i in range(40))

    def editor(path):
        data = yaml.safe_load(path.read_text())
        data["test_command"] = long_cmd
        path.write_text(yaml.safe_dump(data))

    try:
        args = argparse.Namespace(project="team/new", edit=True, force=True)
        assert cli_repos.cmd_approve(c, args, editor=editor) == 0
    finally:
        c.close()
    capsys.readouterr()
    assert main(setup, "export") == 0
    out = capsys.readouterr().out
    assert f"test_command: {long_cmd}\n" in out
    assert yaml.safe_load(out)["repos"][0]["test_command"] == long_cmd


def test_remove_drops_approved_shadowed_by_config(setup, capsys):
    """Dopo averlo spostato nel config.yaml, l'approvato (ignorato) si può togliere."""
    c = Container.build(load_config(setup))
    try:
        p = RepoProposal(
            project="team/api",
            languages=("python",),
            setup_command=None,
            test_command="pytest",
            rationale="",
            baseline_ok=True,
            baseline_output="",
            duration_s=0,
            cost_usd=0,
            created_at=c.clock(),
        )
        c.registry.approve(p, p.to_repo(), "op", c.clock())
        assert c.registry.approved("team/api") is not None
    finally:
        c.close()
    assert main(setup, "remove", "team/api") == 0
    assert "config.yaml" in capsys.readouterr().out
    assert main(setup, "remove", "team/api") == 1
