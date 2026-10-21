"""Regressioni della security review: ogni test riproduce un attacco concreto."""

from __future__ import annotations

import json
import os
import subprocess
import threading
from pathlib import Path
from typing import Any

import pytest

from maxtac.adapters.docker_sandbox import DockerSandbox, SandboxSpec, run_kwargs
from maxtac.adapters.gitlab_vcs import GitLabVCS
from maxtac.adapters.notifier import payload
from maxtac.adapters.scanners import Bandit, Gosec, OsvScanner, Semgrep
from maxtac.domain.models import (
    Decision,
    ExecResult,
    FileChange,
    Finding,
    FixResult,
    Outcome,
    RepoConfig,
    RepoReport,
    RunReport,
    Severity,
    Task,
    Usage,
    Verdict,
)
from maxtac.domain.policy import protected_changes, suspicious_test_content
from maxtac.domain.ports import StructuredOutputError
from maxtac.presentation.lexicon import NEUTRAL
from maxtac.presentation.report import render_run
from maxtac.services.merge_request import commit_message, mr_body, mr_title
from maxtac.services.pipeline import Limits
from maxtac.services.trauma import Triage

from .fakes import (
    FakeGitLab,
    FakeScanner,
    Files,
    ScriptedLLM,
    call,
    end_turn,
    fix_all,
    requests_cve,
    tool_turn,
)
from .test_gitlab_vcs import REPO, TOKEN, commit, sh
from .test_phase3_4 import make_pipeline, repo, shell_sast

ROOT = Path(__file__).resolve().parent.parent


# --- 1. quick action e mention nella MR ---


def evil_task() -> Task:
    f = Finding(
        "sast",
        "semgrep",
        "rule|x`y`",
        "x\n/merge\n/approve\r\n@all [click](https://evil.example)",
        Severity.HIGH,
        "d",
    )
    return Task("sast", f.fingerprint, (f,))


def _no_quick_actions(text: str) -> None:
    for line in text.splitlines():
        assert not line.lstrip().startswith("/"), line


def test_mr_body_neutralizes_quick_actions_and_mentions() -> None:
    task = evil_task()
    body = mr_body(
        task,
        Verdict(Decision.FIX, "ok\n/merge\n@group ping"),
        "fatto\n  /assign_reviewer @boss\n```\n/approve",
        "/work/app.py:3: AssertionError\n/unlabel ~x",
        0.1,
    )
    _no_quick_actions(body)
    assert "@all" not in body and "@group" not in body and "@boss" not in body
    # i campi della tabella restano su una riga e non rompono le colonne
    row = next(line for line in body.splitlines() if "semgrep" in line)
    assert row.count(" | ") == 3 and "\\|" in row
    _no_quick_actions(commit_message(task))
    _no_quick_actions(mr_title(task))
    assert "\n" not in mr_title(task)


# --- 2. agente che bara sui test e sulla config ---


@pytest.mark.parametrize(
    ("path", "status", "kind", "protected"),
    [
        ("tests/test_zz.py", "added", "sast", True),
        ("tests/test_zz.py", "added", "cve", True),
        ("tests/test_regr.py", "added", "bug", False),
        ("conftest.py", "added", "bug", True),
        ("pkg/sub/conftest.py", "added", "bug", True),
        ("services/api/pytest.ini", "added", "sast", True),
        ("services/api/tox.ini", "modified", "cve", True),
        ("sub/Makefile", "modified", "cve", True),
        ("web/jest.config.js", "added", "cve", True),
        ("web/vitest.config.ts", "modified", "sast", True),
        (".semgrepignore", "added", "sast", True),
        ("src/.semgrep.yml", "added", "sast", True),
        (".bandit", "added", "sast", True),
        ("bandit.yaml", "added", "sast", True),
        ("osv-scanner.toml", "added", "cve", True),
        ("sub/osv-scanner.toml", "added", "cve", True),
        (".gosec.json", "added", "sast", True),
        ("svc/.gitlab-ci.yml", "added", "cve", True),
        ("pyproject.toml", "modified", "sast", True),
        ("app.py", "modified", "sast", False),
    ],
)
def test_protected_paths(path: str, status: Any, kind: str, protected: bool) -> None:
    assert bool(protected_changes([FileChange(path, status)], kind)) is protected


def test_cve_may_bump_pyproject_but_not_pytest_config() -> None:
    old = (
        '[project]\ndependencies = ["requests==2.19.0"]\n'
        '[tool.pytest.ini_options]\naddopts = "-q"\n'
    )
    bump = old.replace("2.19.0", "2.32.3")
    cheat = bump.replace('"-q"', '"-q -k nothing"')
    ch = [FileChange("pyproject.toml", "modified")]
    assert protected_changes(ch, "cve", lambda p: (old, bump)) == []
    assert protected_changes(ch, "cve", lambda p: (old, cheat)) == ["pyproject.toml"]
    assert protected_changes(ch, "cve", lambda p: (old, "not = valid = toml")) == ["pyproject.toml"]


def test_cve_may_bump_package_json_but_not_scripts() -> None:
    old = json.dumps({"dependencies": {"lodash": "4.17.0"}, "scripts": {"test": "jest"}})
    bump = old.replace("4.17.0", "4.17.21")
    cheat = bump.replace('"jest"', '"exit 0"')
    ch = [FileChange("web/package.json", "modified")]
    assert protected_changes(ch, "cve", lambda p: (old, bump)) == []
    assert protected_changes(ch, "cve", lambda p: (old, cheat)) == ["web/package.json"]


def test_gitlinks_and_symlinks_are_protected() -> None:
    assert protected_changes([FileChange("vendor/lib", "added", "gitlink")], "bug")
    assert protected_changes([FileChange("link", "added", "symlink")], "sast")


def test_suspicious_test_content() -> None:
    assert suspicious_test_content("import os\nos._exit(0)\n")
    assert suspicious_test_content("import sys\nsys.exit(0)")
    assert suspicious_test_content("func TestMain(m *testing.M) { os.Exit(0) }")
    assert suspicious_test_content("import pytest\npytest.exit('x')")
    assert not suspicious_test_content("def test_zero():\n    assert div(1, 0) == 0\n")


def test_sast_fix_adding_a_test_file_needs_human(tmp_path, store, budget_port, clock) -> None:
    from .test_phase3_4 import SHELL_APP

    gl = FakeGitLab(repos={"alex/ecs2": dict(SHELL_APP)})
    bandit = FakeScanner("bandit", "sast", shell_sast)
    llm = ScriptedLLM(
        [
            tool_turn(
                call("write_file", path="app.py", content="def ls(p):\n    return p\n"),
                call("write_file", path="tests/test_zz.py", content="import os\nos._exit(0)\n"),
            ),
            end_turn(),
        ],
        fix_all,
    )
    p, _ = make_pipeline(tmp_path, store, budget_port, clock, gl, llm, [bandit])
    [fx] = p.run_night([repo()], run_id="n1").repos[0].fixes
    assert fx.outcome is Outcome.NEEDS_HUMAN and "tests/test_zz.py" in fx.detail
    assert gl.mrs == []


BUGGY = {"app.py": "def f(): return 'BUG'\n", "tests/test_app.py": "def test_ok(): pass\n"}


def masking_tests(cmd: str, files: Files) -> ExecResult:
    """Suite finta: il test aggiunto "maschera" la suite quando il fix è presente."""
    if cmd != "pytest -q":
        return ExecResult(0, "ok")
    app = files.get("app.py", "")
    if "tests/test_regr.py" in files:
        return ExecResult(0 if "FIXED" in app else 1, "regr")
    return ExecResult(1 if "BROKEN" in app else 0, "suite")


def bug_llm(app: str, test: str) -> ScriptedLLM:
    def structured(model: str, prompt: str, tool: Any) -> dict[str, Any]:
        if tool.name != "report_bugs":
            return fix_all(model, prompt, tool)
        return {
            "bugs": [
                {
                    "file": "app.py",
                    "symbol": "f",
                    "title": "bug",
                    "detail": "d",
                    "severity": "high",
                    "confidence": "high",
                }
            ]
        }

    return ScriptedLLM(
        [
            tool_turn(
                call("write_file", path="app.py", content=app),
                call("write_file", path="tests/test_regr.py", content=test),
            ),
            end_turn(),
        ],
        structured,
    )


def _hunt(tmp_path, store, budget_port, clock, llm, handler):
    gl = FakeGitLab(
        repos={"alex/ecs2": dict(BUGGY)}, recent={"alex/ecs2": ("diff --git a/app.py", ["app.py"])}
    )
    p, vcs = make_pipeline(
        tmp_path, store, budget_port, clock, gl, llm, [], handler=handler, kinds=("bug",)
    )
    return p.run_night([repo()], run_id="n1").repos[0], gl, vcs


def test_bug_fix_breaking_the_suite_is_caught_without_added_tests(
    tmp_path, store, budget_port, clock
) -> None:
    llm = bug_llm("def f(): return 'FIXED BROKEN'\n", "def test_regr(): ...\n")
    rr, gl, _ = _hunt(tmp_path, store, budget_port, clock, llm, masking_tests)
    [fx] = rr.fixes
    assert fx.outcome is Outcome.VERIFY_FAILED, fx.detail
    assert "senza i test aggiunti" in fx.detail
    assert gl.mrs == []


def test_bug_regression_test_with_exit_is_rejected(tmp_path, store, budget_port, clock) -> None:
    llm = bug_llm("def f(): return 'FIXED'\n", "import os\nos._exit(0)\n")
    rr, gl, _ = _hunt(tmp_path, store, budget_port, clock, llm, masking_tests)
    [fx] = rr.fixes
    assert fx.outcome is Outcome.VERIFY_FAILED and "sospett" in fx.detail
    assert gl.mrs == []


def test_good_bug_fix_still_opens_mr_and_restores_tree(tmp_path, store, budget_port, clock) -> None:
    llm = bug_llm("def f(): return 'FIXED'\n", "def test_regr(): ...\n")
    rr, gl, _ = _hunt(tmp_path, store, budget_port, clock, llm, masking_tests)
    [fx] = rr.fixes
    assert fx.outcome is Outcome.MR_OPENED, fx.detail
    [(_, _, pushed)] = gl.pushed
    assert pushed["app.py"] == "def f(): return 'FIXED'\n" and "tests/test_regr.py" in pushed


# --- 3. soppressioni negli scanner ---


class RecordingSandbox:
    def __init__(self, outputs: dict[str, str] | None = None) -> None:
        self.commands: list[str] = []
        self.outputs = outputs or {}

    def exec(self, cmd: str, timeout: int) -> ExecResult:
        self.commands.append(cmd)
        for key, out in self.outputs.items():
            if key in cmd:
                return ExecResult(0, out)
        return ExecResult(0, "{}")


def test_scanners_ignore_inline_suppressions_and_repo_config() -> None:
    cmds = {}
    for sc in (Semgrep(), Bandit(), Gosec(), OsvScanner()):
        sb = RecordingSandbox()
        sc.scan(sb)  # type: ignore[arg-type]
        cmds[sc.name] = " ".join(sb.commands)
    assert "--disable-nosem" in cmds["semgrep"]
    assert "--ignore-nosec" in cmds["bandit"]
    assert "-nosec" in cmds["gosec"].replace("-nosec=", "-nosec ")
    osv = cmds["osv-scanner"]
    assert "--config /tmp/" in osv and "--offline-vulnerabilities" in osv


def test_scanners_use_absolute_paths() -> None:
    for sc in (Semgrep(), Bandit(), Gosec(), OsvScanner()):
        sb = RecordingSandbox()
        sc.scan(sb)  # type: ignore[arg-type]
        joined = " && ".join(sb.commands)
        for part in joined.split("&&"):
            word = part.strip().split(" ")[0]
            assert word in ("cd",) or word.startswith("/"), (sc.name, word)


def test_semgrep_uses_offline_rules() -> None:
    sb = RecordingSandbox()
    Semgrep(("p/default", "p/python")).scan(sb)  # type: ignore[arg-type]
    cmd = sb.commands[0]
    assert "/opt/semgrep-rules/p-default.yml" in cmd and "/opt/semgrep-rules/p-python.yml" in cmd
    assert "p/default" not in cmd.replace("/opt/semgrep-rules/p-default.yml", "")


# --- 4. rescan in un sandbox pulito ---


def test_rescan_runs_in_fresh_sandbox_without_repo_code(tmp_path, store, budget_port, clock):
    gl = FakeGitLab(repos={"alex/ecs2": {"requirements.txt": "requests==2.19.0\n"}})
    seen: list[list[str]] = []

    def rule(files: Files) -> list[Finding]:
        return requests_cve(files)

    class Spy(FakeScanner):
        def scan(self, sandbox: Any) -> list[Finding]:
            seen.append(list(sandbox.commands))
            return super().scan(sandbox)

    osv = Spy("osv-scanner", "cve", rule)
    llm = ScriptedLLM(
        [
            tool_turn(call("write_file", path="requirements.txt", content="requests==2.32.3\n")),
            end_turn(),
        ],
        fix_all,
    )
    p, _ = make_pipeline(tmp_path, store, budget_port, clock, gl, llm, [osv])
    [fx] = p.run_night([repo()], run_id="n1").repos[0].fixes
    assert fx.outcome is Outcome.MR_OPENED, fx.detail
    assert len(seen) == 2
    rescan_cmds = seen[1]
    assert not any("pip install" in c or "pytest" in c for c in rescan_cmds), rescan_cmds


def test_sandbox_path_puts_system_dirs_first(tmp_path: Path) -> None:
    path = run_kwargs(SandboxSpec(), tmp_path)["environment"]["PATH"].split(":")
    first_user = min(i for i, d in enumerate(path) if d.startswith("/home/"))
    assert path.index("/usr/bin") < first_user and path.index("/bin") < first_user


def test_sandbox_go_and_registry_env(tmp_path: Path) -> None:
    env = run_kwargs(SandboxSpec(), tmp_path)["environment"]
    assert env["GOPROXY"] == "https://proxy.golang.org"
    assert "direct" not in env["GOPROXY"]
    assert env["GONOSUMDB"] == "" and env["GOPRIVATE"] == ""


# --- 5. file ignorati scritti dall'agente ---


def test_ignored_files_from_agent_do_not_reach_verification(tmp_path, store, budget_port, clock):
    gl = FakeGitLab(repos={"alex/ecs2": {"requirements.txt": "requests==2.19.0\n"}})

    def tests_only_pass_with_cheat(cmd: str, files: Files) -> ExecResult:
        if cmd == "pytest -q":
            return ExecResult(0 if ".venv/bin/pytest" in files else 1, "suite")
        return ExecResult(0, "ok")

    llm = ScriptedLLM(
        [
            tool_turn(
                call("write_file", path="requirements.txt", content="requests==2.32.3\n"),
                call("write_file", path=".venv/bin/pytest", content="#!/bin/sh\nexit 0\n"),
            ),
            end_turn(),
        ],
        fix_all,
    )
    osv = FakeScanner("osv-scanner", "cve", requests_cve)
    p, _ = make_pipeline(
        tmp_path, store, budget_port, clock, gl, llm, [osv], handler=tests_only_pass_with_cheat
    )
    [fx] = p.run_night([repo()], run_id="n1").repos[0].fixes
    assert fx.outcome is Outcome.VERIFY_FAILED, fx.detail


# --- 6. snapshot e ripristino su git (binari, symlink, cancellazioni) ---


@pytest.fixture
def real_vcs(tmp_path: Path) -> GitLabVCS:
    from types import SimpleNamespace

    from .test_gitlab_vcs import FakeProjects

    bare = tmp_path / "remote.git"
    sh("init", "-q", "--bare", "-b", "main", str(bare))
    seed = tmp_path / "seed"
    sh("clone", "-q", str(bare), str(seed))
    sh("checkout", "-q", "-b", "main", cwd=seed)
    commit(
        seed, {"app.py": "x = 1\n", "old.py": "y\n", "tests/test_a.py": "def test(): pass\n"}, "i"
    )
    sh("push", "-q", "origin", "main", cwd=seed)
    return GitLabVCS(
        url="https://gitlab.example.it",
        token=TOKEN,
        bot_name="b",
        bot_email="b@x",
        client=SimpleNamespace(projects=FakeProjects()),
        remote_url=lambda project: str(bare),
        allow_file_protocol=True,
    )


def test_snapshot_and_materialize_roundtrip(real_vcs: GitLabVCS, tmp_path: Path) -> None:
    co = real_vcs.checkout(REPO, tmp_path / "work")
    wt = co.worktree
    blob = os.urandom(3_000_000)
    (wt / "app.py").write_text("x = 2\n")
    (wt / "data.bin").write_bytes(blob)
    (wt / "old.py").unlink()
    (wt / "link").symlink_to("app.py")
    (wt / "tests" / "test_new.py").write_text("def test_new(): ...\n")
    tree = real_vcs.snapshot(co)

    real_vcs.materialize(co, tree, include=["tests/test_new.py"])
    assert (wt / "app.py").read_text() == "x = 1\n" and (wt / "old.py").exists()
    assert (wt / "tests" / "test_new.py").exists() and not (wt / "data.bin").exists()

    real_vcs.materialize(co, tree, exclude=["tests/test_new.py"])
    assert not (wt / "tests" / "test_new.py").exists() and (wt / "data.bin").exists()

    real_vcs.materialize(co, tree)
    assert real_vcs.snapshot(co) == tree
    assert (wt / "data.bin").read_bytes() == blob
    assert (wt / "link").is_symlink() and not (wt / "old.py").exists()


def test_discard_untracked_removes_ignored_but_keeps_changes(real_vcs, tmp_path) -> None:
    co = real_vcs.checkout(REPO, tmp_path / "work")
    (co.worktree / ".venv" / "bin").mkdir(parents=True)
    (co.worktree / ".venv" / "bin" / "pytest").write_text("#!/bin/sh\nexit 0\n")
    (co.worktree / "new.py").write_text("z\n")
    real_vcs.changes(co)
    real_vcs.discard_untracked(co)
    assert not (co.worktree / ".venv").exists()
    assert (co.worktree / "new.py").exists()


# --- 13. .git directory e gitlink ---


def test_dotgit_directory_in_worktree_is_removed(real_vcs, tmp_path) -> None:
    co = real_vcs.checkout(REPO, tmp_path / "work")
    (co.worktree / ".git").mkdir()
    (co.worktree / ".git" / "config").write_text("[core]\n\tfsmonitor = touch /tmp/x\n")
    (co.worktree / "app.py").write_text("x = 3\n")
    changes = real_vcs.changes(co)
    assert [c.path for c in changes] == ["app.py"]
    assert not (co.worktree / ".git").exists()


def test_gitlink_and_symlink_are_reported(real_vcs, tmp_path) -> None:
    co = real_vcs.checkout(REPO, tmp_path / "work")
    sub = co.worktree / "vendor" / "lib"
    sub.mkdir(parents=True)
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null"}
    subprocess.run(["git", "init", "-q", str(sub)], check=True, env=env)
    (sub / "f").write_text("x")
    subprocess.run(
        ["git", "-c", "user.name=a", "-c", "user.email=a@b", "-C", str(sub), "commit", "-qm",
         "x", "--allow-empty"],
        check=True,
        env=env,
    )  # fmt: skip
    (co.worktree / "link").symlink_to("/etc/passwd")
    kinds = {c.path: c.kind for c in real_vcs.changes(co)}
    assert kinds.get("link") == "symlink"
    assert kinds.get("vendor/lib") == "gitlink"


# --- 7. injection nel report e nel webhook ---


def test_report_and_webhook_escape_untrusted_text() -> None:
    task = evil_task()
    rr = RepoReport("alex/ecs2")
    rr.fixes.append(FixResult(task, Outcome.VERIFY_FAILED, 0.1, "<!channel> <https://evil|ok>"))
    rr.needs_human.append((task, "@here guarda"))
    rr.errors.append("<script>")
    report = RunReport("n1", False, [rr])
    for text in (render_run(report, NEUTRAL), payload(report)["text"]):
        assert "<!channel>" not in text and "<https://" not in text and "<script>" not in text
        assert "@here" not in text and "@all" not in text
        _no_quick_actions(text)


# --- 8. watchdog del sandbox ---


class HangingAPI:
    def __init__(self) -> None:
        self.released = threading.Event()

    def exec_create(self, cid: str, argv: list[str], **kw: Any) -> dict[str, str]:
        self.argv = argv
        return {"Id": "e1"}

    def exec_start(self, eid: str, stream: bool) -> Any:
        def gen() -> Any:
            yield b"start "
            self.released.wait(5)  # stdout tenuto aperto da un processo in background

        return gen()

    def exec_inspect(self, eid: str) -> dict[str, Any]:
        return {"ExitCode": None}


class KillableContainer:
    id = "c1"

    def __init__(self, api: HangingAPI) -> None:
        self.api = api
        self.killed = False

    def kill(self) -> None:
        self.killed = True
        self.api.released.set()

    def remove(self, force: bool) -> None:
        pass


def test_exec_watchdog_kills_hung_container(tmp_path: Path, monkeypatch: Any) -> None:
    import maxtac.adapters.docker_sandbox as mod

    monkeypatch.setattr(mod, "KILL_GRACE", 0)
    monkeypatch.setattr(mod, "WATCHDOG_SLACK", 0.2)
    api = HangingAPI()
    container = KillableContainer(api)
    client = type("C", (), {})()
    client.api = api
    client.containers = type("Cs", (), {"run": lambda self, **kw: container})()
    client.images = type("Is", (), {"get": lambda self, name: object()})()
    with DockerSandbox(SandboxSpec(), client).open(tmp_path) as s:
        r = s.exec("setsid sleep inf &", timeout=0)
    assert container.killed
    assert not r.ok and "watchdog" in r.output
    assert api.argv[0] == "/usr/bin/timeout"


# --- 9. allowlist del proxy ---


def test_proxy_allowlist_has_no_code_hosting_or_upload_hosts() -> None:
    conf = (ROOT / "proxy" / "squid.conf").read_text()
    allowed = " ".join(
        line for line in conf.splitlines() if line.startswith("acl allowed dstdomain")
    )
    for host in ("github.com", "githubusercontent", "codeload", "semgrep.dev", "api.osv.dev"):
        assert host not in allowed, host
    assert "pypi.org" in allowed and "proxy.golang.org" in allowed


# --- 10. pulizia della working tree ---


def test_workdir_is_cleaned_after_each_repo(tmp_path, store, budget_port, clock) -> None:
    gl = FakeGitLab(repos={"alex/ecs2": {"a.py": "x"}, "alex/b": {"a.py": "x"}})
    gl.broken.add("alex/b")
    p, vcs = make_pipeline(tmp_path, store, budget_port, clock, gl, ScriptedLLM(), [])
    p.run_night([repo(), repo("alex/b")], run_id="n1")
    assert len(vcs.cleaned) == 1 and not vcs.trees


def test_gitlab_cleanup_removes_workdir(real_vcs, tmp_path) -> None:
    co = real_vcs.checkout(REPO, tmp_path / "work")
    real_vcs.cleanup(co)
    assert not co.worktree.exists() and not co.gitdir.exists()


# --- 11. spesa non registrata e crediti del mese ---


def test_structured_error_still_charges_usage(night) -> None:
    class Failing:
        def structured(self, **kw: Any) -> Any:
            raise StructuredOutputError(
                "max_tokens", Usage(input_tokens=100_000), "claude-haiku-5-5"
            )

    meter = night.meter("triage:x", 1.0)
    t = evil_task()
    with pytest.raises(StructuredOutputError):
        Triage(Failing(), "claude-haiku-5-5").assess(
            RepoConfig("a/b", ("python",), "t"), [t], meter
        )  # type: ignore[arg-type]
    assert meter.spent == pytest.approx(0.01)


def test_run_does_not_start_when_monthly_credits_are_spent(
    tmp_path, store, budget_port, clock
) -> None:
    budget_port.record("old-run", "fix:x", "claude-sonnet-5-5", 99.5, clock())
    gl = FakeGitLab(repos={"alex/ecs2": {"requirements.txt": "requests==2.19.0\n"}})
    osv = FakeScanner("osv-scanner", "cve", requests_cve)
    p, _ = make_pipeline(
        tmp_path,
        store,
        budget_port,
        clock,
        gl,
        ScriptedLLM(),
        [osv],
        limits=Limits(monthly_credits_usd=100.0),
    )
    report = p.run_night([repo()], run_id="n1")
    assert not report.aborted
    assert report.night_cap_usd == pytest.approx(0.5)  # tetto ridotto ai crediti rimasti
    osv2 = FakeScanner("osv-scanner", "cve", requests_cve)
    p2, _ = make_pipeline(
        tmp_path, store, budget_port, clock, gl, ScriptedLLM(), [osv2],
        limits=Limits(monthly_credits_usd=99.5),
    )  # fmt: skip
    r2 = p2.run_night([repo()], run_id="n2")
    assert r2.aborted and "crediti" in r2.aborted
    assert osv2.calls == 0


def test_sast_task_with_unchanged_tests_still_works(tmp_path, store, budget_port, clock) -> None:
    """Controllo di non regressione: un fix SAST pulito apre ancora la MR."""
    from .test_phase3_4 import SHELL_APP

    gl = FakeGitLab(repos={"alex/ecs2": dict(SHELL_APP)})
    llm = ScriptedLLM(
        [
            tool_turn(
                call(
                    "write_file",
                    path="app.py",
                    content="import subprocess\n\ndef ls(p):\n"
                    "    return subprocess.run(['ls', p])\n",
                )
            ),
            end_turn(),
        ],
        fix_all,
    )
    p, _ = make_pipeline(
        tmp_path, store, budget_port, clock, gl, llm, [FakeScanner("bandit", "sast", shell_sast)]
    )
    [fx] = p.run_night([repo()], run_id="n1").repos[0].fixes
    assert fx.outcome is Outcome.MR_OPENED, fx.detail
