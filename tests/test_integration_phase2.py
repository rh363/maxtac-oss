"""Criterio della Fase 2 riprodotto in locale.

GitLabVCS vero su repo git reali (remoto bare), sandbox che esegue i comandi in una tmp dir,
LLM scriptato e API GitLab finte: un repo con `requests==2.19.0` porta a una MR con il bump
pushato sul remoto.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from maxtac.adapters.gitlab_vcs import GitLabVCS
from maxtac.adapters.sqlite_store import SqliteBudget, SqliteStore, connect
from maxtac.domain.models import ExecResult, Outcome, RepoConfig
from maxtac.domain.policy import safe_relpath
from maxtac.services.pipeline import Limits, Models, Pipeline, PipelineSettings

from .conftest import PRICING
from .fakes import (
    FakeClock,
    FakeScanner,
    ScriptedLLM,
    call,
    end_turn,
    fix_all,
    requests_cve,
    tool_turn,
)
from .test_gitlab_vcs import TOKEN, sh

REPO = RepoConfig("alex/ecs2", ("python",), "python -m check", setup_command="true")


class LocalSandbox:
    """Solo per i test: esegue i comandi sull'host nella working tree. Mai in produzione."""

    def __init__(self, worktree: Path) -> None:
        self.root = worktree
        self.commands: list[str] = []

    def exec(self, cmd: str, timeout: int) -> ExecResult:
        self.commands.append(cmd)
        r = subprocess.run(
            cmd, shell=True, cwd=self.root, capture_output=True, text=True, timeout=timeout
        )
        return ExecResult(r.returncode, r.stdout + r.stderr)

    def read(self, path: str) -> str:
        return (self.root / safe_relpath(path)).read_text()

    def write(self, path: str, content: str) -> None:
        p = self.root / safe_relpath(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    def list_files(self, path: str) -> list[str]:
        base = self.root / safe_relpath(path)
        return sorted(str(p.relative_to(self.root)) for p in base.rglob("*") if p.is_file())

    @property
    def files(self) -> dict[str, str]:
        out = {}
        for f in self.list_files("."):
            try:
                out[f] = self.read(f)
            except UnicodeDecodeError:  # .pyc e simili
                continue
        return out


class LocalSandboxes:
    def __init__(self) -> None:
        self.opened: list[LocalSandbox] = []

    @contextmanager
    def open(self, worktree: Path, image: str | None = None) -> Iterator[LocalSandbox]:
        sb = LocalSandbox(worktree)
        self.opened.append(sb)
        yield sb


def seed_remote(tmp_path: Path) -> Path:
    bare = tmp_path / "remote.git"
    sh("init", "-q", "--bare", "-b", "main", str(bare))
    seed = tmp_path / "seed"
    sh("clone", "-q", str(bare), str(seed))
    sh("checkout", "-q", "-b", "main", cwd=seed)
    (seed / "requirements.txt").write_text("requests==2.19.0\n")
    # "test suite": verde solo se requests è aggiornato
    (seed / "check.py").write_text(
        "import sys\n"
        "ok = '2.19.0' not in open('requirements.txt').read()\n"
        "sys.exit(0 if ok else 1)\n"
    )
    sh("add", "-A", cwd=seed)
    sh("-c", "user.name=dev", "-c", "user.email=dev@x", "commit", "-qm", "init", cwd=seed)
    sh("push", "-q", "origin", "main", cwd=seed)
    return bare


def test_vulnerable_dependency_becomes_verified_mr(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from .test_gitlab_vcs import FakeProjects

    bare = seed_remote(tmp_path)
    gl = SimpleNamespace(projects=FakeProjects())
    vcs = GitLabVCS(
        url="https://gitlab.example.it",
        token=TOKEN,
        bot_name="autofix-bot",
        bot_email="autofix@example.it",
        client=gl,
        remote_url=lambda project: str(bare),
        allow_file_protocol=True,
    )
    llm = ScriptedLLM(
        [
            tool_turn(call("read_file", path="requirements.txt")),
            tool_turn(
                call("write_file", path="requirements.txt", content="requests==2.32.3\n"),
                call("run", cmd="python -m check"),
            ),
            end_turn("requests 2.19.0 -> 2.32.3"),
        ],
        fix_all,
    )
    conn = connect(":memory:")
    sandboxes = LocalSandboxes()
    pipeline = Pipeline(
        vcs=vcs,
        sandboxes=sandboxes,
        scanners=[FakeScanner("osv-scanner", "cve", requests_cve)],
        llm=llm,
        store=SqliteStore(conn),
        budget=SqliteBudget(conn),
        pricing=PRICING,
        settings=PipelineSettings(
            limits=Limits(),
            models=Models("claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5"),
            workdir=tmp_path / "work",
            enabled_kinds=frozenset({"cve"}),
        ),
        clock=FakeClock(),
    )

    report = pipeline.run_night([REPO], run_id="n1")

    [fx] = report.repos[0].fixes
    assert fx.outcome is Outcome.MR_OPENED, fx.detail
    [mr] = gl.projects.project.mergerequests.opened
    assert mr["source_branch"] == fx.branch and mr["target_branch"] == "main"
    assert "autofix" in mr["labels"]
    # il branch pushato sul remoto contiene il bump, committato dal bot
    pushed = sh("--git-dir", str(bare), "show", f"{fx.branch}:requirements.txt")
    assert pushed == "requests==2.32.3\n"
    author = sh("--git-dir", str(bare), "log", "-1", "--format=%an <%ae>", fx.branch)
    assert author.strip() == "autofix-bot <autofix@example.it>"
    # nel commit solo il bump: niente __pycache__ o altri residui dei test
    tree = sh("--git-dir", str(bare), "diff", "--name-only", "main", fx.branch).split()
    assert tree == ["requirements.txt"]
    # main sul remoto non è stato toccato
    assert sh("--git-dir", str(bare), "show", "main:requirements.txt") == "requests==2.19.0\n"
    # verifica indipendente in un sandbox nuovo: setup, test e rescan
    verify = sandboxes.opened[2]
    assert verify.commands == ["true", "python -m check"]
    conn.close()
