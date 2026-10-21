"""GitLabVCS con repo git reali in tmp_path (remoto bare locale) e API GitLab finte."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from maxtac.adapters.gitlab_vcs import GitError, GitLabVCS
from maxtac.domain.models import FileChange, RepoConfig

TOKEN = "glpat-supersecret-token-123"
REPO = RepoConfig("alex/ecs2", ("python",), "pytest -q")


def sh(*args: str, cwd: Path | None = None) -> str:
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True, env=env
    ).stdout


def commit(work: Path, files: dict[str, str], msg: str, date: str | None = None) -> None:
    for name, body in files.items():
        p = work / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    sh("add", "-A", cwd=work)
    extra = {"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date} if date else {}
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", **extra}
    subprocess.run(
        ["git", "-c", "user.name=dev", "-c", "user.email=dev@x", "commit", "-qm", msg],
        cwd=work,
        check=True,
        env=env,
    )


class FakeMRs:
    def __init__(self) -> None:
        self.opened: list[dict[str, Any]] = []
        self.list_calls: list[dict[str, Any]] = []

    def list(self, **kw: Any) -> list[Any]:
        self.list_calls.append(kw)
        return [m for m in self.opened if m["source_branch"] == kw["source_branch"]]

    def create(self, data: dict[str, Any]) -> Any:
        self.opened.append(data)
        return SimpleNamespace(
            web_url=f"https://gitlab.example.it/alex/ecs2/-/merge_requests/{len(self.opened)}"
        )


class FakeProjects:
    def __init__(self) -> None:
        self.project = SimpleNamespace(default_branch="main", mergerequests=FakeMRs())
        self.gets: list[str] = []

    def get(self, path: str) -> Any:
        self.gets.append(path)
        return self.project


@pytest.fixture
def remote(tmp_path: Path) -> Path:
    bare = tmp_path / "remote.git"
    sh("init", "-q", "--bare", "-b", "main", str(bare))
    seed = tmp_path / "seed"
    sh("clone", "-q", str(bare), str(seed))
    sh("checkout", "-q", "-b", "main", cwd=seed)
    commit(seed, {"old.py": "x = 1\n"}, "old", date="2020-01-01T00:00:00")
    commit(
        seed,
        {
            "requirements.txt": "requests==2.19.0\n",
            "app/main.py": "print('hi')\n",
            "tests/test_main.py": "def test_ok():\n    assert True\n",
        },
        "init",
    )
    # Un hook malevolo versionato nel repo: non deve girare mai.
    (seed / ".githooks").mkdir()
    (seed / ".githooks" / "post-checkout").write_text(f"#!/bin/sh\ntouch {tmp_path}/PWNED\n")
    (seed / ".githooks" / "post-checkout").chmod(0o755)
    commit(seed, {}, "hooks")
    sh("push", "-q", "origin", "main", cwd=seed)
    return bare


@pytest.fixture
def gl() -> Any:
    return SimpleNamespace(projects=FakeProjects())


@pytest.fixture
def vcs(remote: Path, gl: Any) -> GitLabVCS:
    return GitLabVCS(
        url="https://gitlab.example.it",
        token=TOKEN,
        bot_name="autofix-bot",
        bot_email="autofix@example.it",
        client=gl,
        remote_url=lambda project: str(remote),
        allow_file_protocol=True,
    )


def test_checkout_separates_gitdir_and_removes_dotgit(vcs: GitLabVCS, tmp_path: Path) -> None:
    co = vcs.checkout(REPO, tmp_path / "work")
    assert co.base_branch == "main"
    assert len(co.base_sha) == 40
    assert (co.worktree / "requirements.txt").read_text() == "requests==2.19.0\n"
    assert not (co.worktree / ".git").exists()
    assert co.gitdir.is_dir() and not co.gitdir.is_relative_to(co.worktree)


def test_repo_hooks_never_run(vcs: GitLabVCS, tmp_path: Path) -> None:
    co = vcs.checkout(REPO, tmp_path / "work")
    # Anche se l'agente scrive un hook dentro la git dir, hooksPath=/dev/null lo ignora.
    hooks = co.gitdir / "hooks"
    hooks.mkdir(exist_ok=True)
    for name in ("post-checkout", "pre-commit", "pre-push"):
        (hooks / name).write_text(f"#!/bin/sh\ntouch {tmp_path}/PWNED-{name}\n")
        (hooks / name).chmod(0o755)
    vcs.start_branch(co, "autofix/cve/abc")
    (co.worktree / "app" / "main.py").write_text("print('fixed')\n")
    vcs.push_branch(co, "autofix/cve/abc", "autofix: fix\n")
    assert not list(tmp_path.glob("PWNED*"))


def test_changes_and_diff_include_new_files(vcs: GitLabVCS, tmp_path: Path) -> None:
    co = vcs.checkout(REPO, tmp_path / "work")
    vcs.start_branch(co, "autofix/cve/abc")
    (co.worktree / "requirements.txt").write_text("requests==2.32.3\n")
    (co.worktree / "tests" / "test_new.py").write_text("def test_new():\n    pass\n")
    (co.worktree / "old.py").unlink()
    (co.worktree / "app" / "__pycache__").mkdir()
    (co.worktree / "app" / "__pycache__" / "main.cpython-313.pyc").write_bytes(b"\0junk")
    changes = sorted(vcs.changes(co), key=lambda c: c.path)
    assert changes == [
        FileChange("old.py", "deleted"),
        FileChange("requirements.txt", "modified"),
        FileChange("tests/test_new.py", "added"),
    ]
    diff = vcs.diff(co)
    assert "+requests==2.32.3" in diff and "tests/test_new.py" in diff
    assert "__pycache__" not in diff


def test_agent_created_dotgit_is_ignored(vcs: GitLabVCS, tmp_path: Path) -> None:
    co = vcs.checkout(REPO, tmp_path / "work")
    vcs.start_branch(co, "b")
    (co.worktree / ".git").write_text("gitdir: /etc\n")
    (co.worktree / "app" / "main.py").write_text("print('x')\n")
    assert [c.path for c in vcs.changes(co)] == ["app/main.py"]


def test_reset_restores_base(vcs: GitLabVCS, tmp_path: Path) -> None:
    co = vcs.checkout(REPO, tmp_path / "work")
    vcs.start_branch(co, "b1")
    (co.worktree / "requirements.txt").write_text("changed\n")
    (co.worktree / "junk.txt").write_text("x")
    vcs.start_branch(co, "b2")
    assert vcs.changes(co) == []
    assert not (co.worktree / "junk.txt").exists()


def test_push_and_open_mr(vcs: GitLabVCS, gl: Any, remote: Path, tmp_path: Path) -> None:
    co = vcs.checkout(REPO, tmp_path / "work")
    vcs.start_branch(co, "autofix/cve/abc")
    (co.worktree / "requirements.txt").write_text("requests==2.32.3\n")
    vcs.push_branch(co, "autofix/cve/abc", "autofix: Aggiorna requests\n\n- dettagli\n")
    log = sh("--git-dir", str(remote), "log", "-1", "--format=%an <%ae>%n%s", "autofix/cve/abc")
    assert log.splitlines() == ["autofix-bot <autofix@example.it>", "autofix: Aggiorna requests"]

    url = vcs.open_mr(REPO, "autofix/cve/abc", "[autofix] t", "body", ["autofix", "security"])
    assert url.endswith("/merge_requests/1")
    mr = gl.projects.project.mergerequests.opened[0]
    assert mr["target_branch"] == "main" and mr["labels"] == "autofix,security"
    assert mr["remove_source_branch"] is True
    assert vcs.has_open_mr(REPO, "autofix/cve/abc")
    assert not vcs.has_open_mr(REPO, "autofix/cve/other")


def test_recent_diff_only_recent_commits(vcs: GitLabVCS, tmp_path: Path) -> None:
    co = vcs.checkout(REPO, tmp_path / "work")
    diff, files = vcs.recent_diff(co, 7)
    assert "requests==2.19.0" in diff and "x = 1" not in diff
    assert sorted(files) == [
        ".githooks/post-checkout",
        "app/main.py",
        "requirements.txt",
        "tests/test_main.py",
    ]


def test_file_protocol_refused_by_default(remote: Path, gl: Any, tmp_path: Path) -> None:
    vcs = GitLabVCS(
        url="https://gitlab.example.it",
        token=TOKEN,
        bot_name="b",
        bot_email="b@x",
        client=gl,
        remote_url=lambda p: str(remote),
    )
    with pytest.raises(GitError):
        vcs.checkout(REPO, tmp_path / "work")


def test_token_never_in_errors_or_argv(gl: Any, tmp_path: Path, monkeypatch: Any) -> None:
    seen: list[list[str]] = []
    real = subprocess.run

    def spy(cmd: list[str], **kw: Any) -> Any:
        seen.append(cmd)
        return real(cmd, **kw)

    monkeypatch.setattr(subprocess, "run", spy)
    vcs = GitLabVCS(
        url="https://gitlab.example.it",
        token=TOKEN,
        bot_name="b",
        bot_email="b@x",
        client=gl,
        # remoto che ripete il token nell'errore: deve essere redatto
        remote_url=lambda p: f"/nonexistent/{TOKEN}",
        allow_file_protocol=True,
    )
    with pytest.raises(GitError) as e:
        vcs.checkout(REPO, tmp_path / "work")
    assert TOKEN not in str(e.value) and "***" in str(e.value)
    assert all(TOKEN not in " ".join(c) for c in seen if "nonexistent" not in " ".join(c))


def test_auth_header_scoped_to_gitlab_via_env(vcs: GitLabVCS) -> None:
    env = vcs._auth_env()
    assert env["GIT_CONFIG_KEY_0"] == "http.https://gitlab.example.it/.extraHeader"
    assert env["GIT_CONFIG_VALUE_0"].startswith("Authorization: Basic ")
    assert TOKEN not in env["GIT_CONFIG_VALUE_0"]


def test_default_branch_from_config_wins(vcs: GitLabVCS, gl: Any, tmp_path: Path) -> None:
    gl.projects.project.default_branch = "develop"
    repo = RepoConfig("alex/ecs2", ("python",), "pytest", default_branch="main")
    co = vcs.checkout(repo, tmp_path / "work")
    assert co.base_branch == "main"


def test_list_projects_asks_for_developer_access_and_skips_archived() -> None:
    calls: list[dict[str, Any]] = []

    class Projects:
        def list(self, **kw: Any) -> list[Any]:
            calls.append(kw)
            return [
                SimpleNamespace(path_with_namespace="team/b"),
                SimpleNamespace(path_with_namespace="team/a"),
            ]

    vcs = GitLabVCS(
        url="https://gitlab.example.it",
        token=TOKEN,
        bot_name="b",
        bot_email="b@example.it",
        client=SimpleNamespace(projects=Projects()),
    )
    assert vcs.list_projects() == ["team/a", "team/b"]
    assert calls == [
        {"membership": True, "archived": False, "min_access_level": 30, "iterator": True}
    ]


def test_ca_bundle_goes_to_git_and_api_client(tmp_path: Path) -> None:
    ca = tmp_path / "gitlab-ca.pem"
    vcs = GitLabVCS(
        url="https://gitlab.example.it",
        token=TOKEN,
        bot_name="b",
        bot_email="b@example.it",
        ca_bundle=ca,
    )
    env = vcs._auth_env()
    pairs = {
        env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
        for i in range(int(env["GIT_CONFIG_COUNT"]))
    }
    assert pairs["http.https://gitlab.example.it/.sslCAInfo"] == str(ca)
    assert vcs._gl.ssl_verify == str(ca)  # python-gitlab
    plain = GitLabVCS(url="https://gitlab.example.it", token=TOKEN, bot_name="b", bot_email="b@x")
    assert plain._auth_env()["GIT_CONFIG_COUNT"] == "1" and plain._gl.ssl_verify is True
