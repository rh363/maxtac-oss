"""Reviewer delle MR per prefisso di progetto (`vcs.reviewers`): vince il più specifico."""

from __future__ import annotations

import argparse
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from maxtac import cli
from maxtac.adapters.gitlab_vcs import GitLabVCS
from maxtac.config import VCSConf, load_config
from maxtac.container import Container
from maxtac.domain.policy import resolve_reviewers
from maxtac.presentation.lexicon import NEUTRAL

from .test_gitlab_vcs import REPO, TOKEN, FakeProjects

EXAMPLE = Path(__file__).parent.parent / "config.example.yaml"


def test_most_specific_prefix_wins_and_empty_list_clears():
    reviewers = {"": ["lead"], "team": ["anna", "bruno"], "team/legacy": []}
    assert resolve_reviewers("other/x", reviewers) == ("lead",)
    assert resolve_reviewers("team/api", reviewers) == ("anna", "bruno")
    assert resolve_reviewers("team/legacy", reviewers) == ()  # nessuno per questo repo
    assert resolve_reviewers("team2/x", reviewers) == ("lead",)
    assert resolve_reviewers("x/y", {}) == ()


@pytest.mark.parametrize(
    "reviewers",
    [{"team/": ["anna"]}, {"team": ["@anna"]}, {"team": ["anna bruno"]}, {"team": ["a,b"]}],
)
def test_invalid_reviewers_rejected(reviewers):
    with pytest.raises(ValidationError):
        VCSConf(reviewers=reviewers)


def _config(tmp_path: Path, reviewers: dict[str, list[str]]) -> Path:
    data = yaml.safe_load(EXAMPLE.read_text())
    data["workdir"] = str(tmp_path / "work")
    data["db_path"] = str(tmp_path / "db.sqlite3")
    data["web"] = None
    data.setdefault("vcs", {})["reviewers"] = reviewers
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def test_container_repos_carry_reviewers(tmp_path):
    cfg = load_config(_config(tmp_path, {"team": ["anna"], "team/agent": ["bruno", "carla"]}))
    c = Container.build(cfg)
    try:
        by = {r.project: r.reviewers for r in c.repos()}
    finally:
        c.close()
    assert by == {"team/api": ("anna",), "team/agent": ("bruno", "carla")}


def test_status_shows_reviewers(tmp_path, capsys):
    c = Container.build(load_config(_config(tmp_path, {"team/api": ["anna", "bruno"]})))
    try:
        assert cli.cmd_status(c, argparse.Namespace(), NEUTRAL) == 0
    finally:
        c.close()
    assert "reviewer delle MR per team/api: anna, bruno" in capsys.readouterr().out


class FakeUsers:
    def __init__(self, known: dict[str, int]) -> None:
        self.known = known
        self.calls: list[str] = []

    def list(self, **kw: Any) -> list[Any]:
        self.calls.append(kw["username"])
        uid = self.known.get(kw["username"])
        return [SimpleNamespace(id=uid, username=kw["username"])] if uid else []


def test_open_mr_sets_reviewer_ids_and_skips_unknown(tmp_path, caplog):
    gl = SimpleNamespace(projects=FakeProjects(), users=FakeUsers({"anna": 7, "bruno": 9}))
    vcs = GitLabVCS(
        url="https://gitlab.example.it",
        token=TOKEN,
        bot_name="autofix-bot",
        bot_email="autofix@example.it",
        client=gl,
        remote_url=lambda project: str(tmp_path),
    )
    repo = replace(REPO, reviewers=("anna", "ghost", "bruno"))
    vcs.open_mr(repo, "autofix/cve/a", "t", "b", ["autofix"])
    vcs.open_mr(repo, "autofix/cve/b", "t", "b", ["autofix"])
    first, second = gl.projects.project.mergerequests.opened
    assert first["reviewer_ids"] == [7, 9] and second["reviewer_ids"] == [7, 9]
    assert gl.users.calls == ["anna", "ghost", "bruno"]  # una ricerca per utente, poi cache
    assert "ghost" in caplog.text

    vcs.open_mr(REPO, "autofix/cve/c", "t", "b", ["autofix"])  # senza reviewer
    assert "reviewer_ids" not in gl.projects.project.mergerequests.opened[2]
