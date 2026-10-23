"""Immagine dei sandbox per repo (sandbox.images): solo dal config, mai per scan e rescan."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from maxtac.adapters.docker_sandbox import DockerSandbox, SandboxImageMissing
from maxtac.config import load_config
from maxtac.domain.models import Outcome
from maxtac.domain.policy import resolve_sandbox_image

from .test_docker_sandbox import SPEC, FakeDocker
from .test_pipeline import bump_turns, repo

ROOT = Path(__file__).parent.parent
MYSQL = "autofix-sandbox-mysql:local"


def test_most_specific_prefix_wins() -> None:
    images = {"team": "a:1", "team/api": "b:1"}
    assert resolve_sandbox_image("team/api", images) == "b:1"
    assert resolve_sandbox_image("team/api/sub", images) == "b:1"
    assert resolve_sandbox_image("team/web", images) == "a:1"
    assert resolve_sandbox_image("team2/x", images) is None
    assert resolve_sandbox_image("x/y", {}) is None


def test_docker_sandbox_uses_requested_image_with_same_hardening(tmp_path: Path) -> None:
    client = FakeDocker()
    sb = DockerSandbox(SPEC, client=client)
    with sb.open(tmp_path):
        standard = dict(client.containers.kwargs)
    with sb.open(tmp_path, MYSQL):
        custom = dict(client.containers.kwargs)
    assert standard["image"] == SPEC.image and custom["image"] == MYSQL
    same = ("user", "read_only", "cap_drop", "security_opt", "network", "tmpfs", "environment")
    assert all(standard[k] == custom[k] for k in same)


def test_missing_custom_image_points_to_sandbox_local(tmp_path: Path) -> None:
    sb = DockerSandbox(SPEC, client=FakeDocker(image=False))
    with pytest.raises(SandboxImageMissing, match="sandbox/local"), sb.open(tmp_path, MYSQL):
        pass


@pytest.fixture
def world(tmp_path: Path, store: Any, budget_port: Any, clock: Any) -> Any:
    from .test_pipeline import World

    return lambda **kw: World(tmp_path, store, budget_port, clock, **kw)


def test_fix_and_tests_use_repo_image_scan_and_rescan_the_standard(world: Any) -> None:
    w = world(turns=bump_turns(), repos=[replace(repo(), sandbox_image=MYSQL)])
    [fx] = w.run().repos[0].fixes
    assert fx.outcome is Outcome.MR_OPENED, fx.detail
    # scan, fix, test, rescan
    assert w.sandboxes.images == [None, MYSQL, MYSQL, None]


def config(tmp_path: Path, images: dict[str, str]) -> Path:
    data = yaml.safe_load((ROOT / "config.example.yaml").read_text())
    data["db_path"] = str(tmp_path / "db.sqlite3")
    data["workdir"] = str(tmp_path / "work")
    data["sandbox"]["images"] = images
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


@pytest.mark.parametrize(
    "images",
    [{"team/": "a:1"}, {"/team": "a:1"}, {"team api": "a:1"}, {"team": "a:1; rm -rf /"}],
)
def test_invalid_images_rejected(tmp_path: Path, images: dict[str, str]) -> None:
    with pytest.raises(ValidationError, match=r"sandbox\.images"):
        load_config(config(tmp_path, images))


def test_container_assigns_images_to_repos(tmp_path: Path) -> None:
    from maxtac.container import Container

    c = Container.build(load_config(config(tmp_path, {"": "base:2", "team/api": MYSQL})))
    try:
        assert {r.project: r.sandbox_image for r in c.repos()} == {
            "team/api": MYSQL,
            "team/agent": "base:2",
        }
    finally:
        c.close()


def test_discovery_explores_and_runs_baseline_in_repo_image(
    tmp_path: Path, conn: Any, budget_port: Any, clock: Any
) -> None:
    from .fakes import FakeGitLab, FakeVCS, ScriptedLLM
    from .test_discovery import PY_REPO, make, submit

    vcs = FakeVCS(FakeGitLab(repos={"team/api": dict(PY_REPO)}))
    llm = ScriptedLLM([submit(["python"], "", "python -m pytest -q")])
    svc, sandboxes, _ = make(
        (None, vcs), conn, budget_port, clock, tmp_path, llm, sandbox_images={"team": MYSQL}
    )
    svc.discover("team/api")
    assert sandboxes.images == [MYSQL, MYSQL]
