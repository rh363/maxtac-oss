"""Criterio della Fase 3 riprodotto in locale, con bandit vero.

GitLabVCS su repo git reali, sandbox locale che mappa /work sulla working tree, adapter Bandit
reale, LLM scriptato e API GitLab finte. Notte 1: `shell=True` diventa una MR verificata, un
falso positivo noto viene ignorato dal triage. Notte 2: il codice si sposta di qualche riga,
i fingerprint restano gli stessi, nessun nuovo triage e nessuna MR doppia.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from maxtac.adapters.gitlab_vcs import GitLabVCS
from maxtac.adapters.scanners import BIN as SANDBOX_BIN
from maxtac.adapters.scanners import OUT_DIR, WORK, Bandit
from maxtac.adapters.sqlite_store import SqliteBudget, SqliteStore, connect
from maxtac.domain.models import ExecResult, FindingStatus, Outcome, RepoConfig, ToolSpec
from maxtac.services.pipeline import Limits, Models, Pipeline, PipelineSettings

from .conftest import PRICING
from .fakes import FakeClock, ScriptedLLM, call, end_turn, tool_turn
from .test_gitlab_vcs import TOKEN, FakeProjects, commit, sh
from .test_integration_phase2 import LocalSandbox

BIN = str(Path(sys.executable).parent)
pytestmark = pytest.mark.skipif(
    shutil.which("bandit", path=BIN + os.pathsep + os.environ.get("PATH", "")) is None,
    reason="bandit non installato",
)

REPO = RepoConfig("alex/ecs2", ("python",), "python -m check")

APP = (
    "import subprocess\n"
    "\n"
    "\n"
    "def ls(path):\n"
    "    return subprocess.run('ls ' + path, shell=True, capture_output=True).returncode\n"
)
FIXED = (
    "import subprocess\n"
    "\n"
    "\n"
    "def ls(path):\n"
    "    return subprocess.run(['ls', path], capture_output=True).returncode\n"
)
CHECK = "import sys\nimport app\nsys.exit(app.ls('.'))\n"


class MappedSandbox(LocalSandbox):
    """Come il sandbox vero: /work è la working tree, l'output degli scanner va in /tmp."""

    def __init__(self, worktree: Path, scratch: Path) -> None:
        super().__init__(worktree)
        self.scratch = scratch

    def exec(self, cmd: str, timeout: int) -> ExecResult:
        mapped = cmd.replace(OUT_DIR, str(self.scratch)).replace(WORK, str(self.root))
        # gli scanner sono invocati per path assoluto: qui stanno nel venv dei test
        mapped = mapped.replace(f"{SANDBOX_BIN}/", f"{BIN}/")
        return super().exec(f'export PATH="{BIN}:$PATH"; {mapped}', timeout)


class MappedSandboxes:
    def __init__(self, scratch: Path) -> None:
        self.scratch = scratch
        self.opened: list[MappedSandbox] = []

    def open(self, worktree: Path, image: str | None = None) -> Any:
        from contextlib import contextmanager

        @contextmanager
        def cm() -> Any:
            sb = MappedSandbox(worktree, self.scratch)
            self.opened.append(sb)
            yield sb

        return cm()


def triage(model: str, prompt: str, tool: ToolSpec) -> dict[str, Any]:
    """`import subprocess` (B404) è un falso positivo noto; shell=True (B602) va corretto."""
    import json
    import re

    body = re.search(r"<findings>\n(.*)\n</findings>", prompt, re.S)
    assert body
    verdicts = []
    for t in json.loads(body.group(1)):
        rule = t["findings"][0]["rule"]
        if rule.startswith("B404"):
            verdicts.append({"id": t["id"], "decision": "ignore", "reason": "import innocuo"})
        else:
            verdicts.append({"id": t["id"], "decision": "fix", "reason": "input in shell"})
    return {"verdicts": verdicts}


def test_sast_finding_fixed_and_false_positive_ignored_across_two_nights(tmp_path: Path) -> None:
    bare = tmp_path / "remote.git"
    sh("init", "-q", "--bare", "-b", "main", str(bare))
    seed = tmp_path / "seed"
    sh("clone", "-q", str(bare), str(seed))
    sh("checkout", "-q", "-b", "main", cwd=seed)
    commit(seed, {"app.py": APP, "check.py": CHECK}, "init")
    sh("push", "-q", "origin", "main", cwd=seed)

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
            tool_turn(call("read_file", path="app.py")),
            tool_turn(call("write_file", path="app.py", content=FIXED)),
            end_turn("argomenti in lista, niente shell"),
        ],
        triage,
    )
    conn = connect(":memory:")
    store = SqliteStore(conn)
    clock = FakeClock()
    bandit = Bandit()

    def pipeline() -> Pipeline:
        return Pipeline(
            vcs=vcs,
            sandboxes=MappedSandboxes(tmp_path / "scan"),
            scanners=[bandit],
            llm=llm,
            store=store,
            budget=SqliteBudget(conn),
            pricing=PRICING,
            settings=PipelineSettings(
                limits=Limits(),
                models=Models("claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5"),
                workdir=tmp_path / "work",
                enabled_kinds=frozenset({"sast"}),
            ),
            clock=clock,
        )

    # --- notte 1 ---
    rr = pipeline().run_night([REPO], run_id="n1").repos[0]
    assert not rr.errors, rr.errors
    rules = sorted(t.findings[0].rule.split(":")[0] for t, _ in rr.ignored)
    assert rules == ["B404"]
    [fx] = rr.fixes
    assert fx.outcome is Outcome.MR_OPENED, fx.detail
    assert fx.task.findings[0].rule.startswith("B602")
    [mr] = gl.projects.project.mergerequests.opened
    assert mr["source_branch"] == fx.branch
    assert sh("--git-dir", str(bare), "show", f"{fx.branch}:app.py") == FIXED
    ignored_fp = rr.ignored[0][0].findings[0].fingerprint
    rec = store.get(REPO.project, ignored_fp)
    assert rec is not None and rec.status is FindingStatus.IGNORED
    triage_calls = len(llm.structured_calls)

    # --- notte 2: qualcuno sposta il codice più in basso ---
    commit(seed, {"app.py": "# intestazione\n# aggiunta dopo\n\n" + APP}, "header")
    sh("push", "-q", "origin", "main", cwd=seed)
    clock.advance(days=1)
    rr2 = pipeline().run_night([REPO], run_id="n2").repos[0]
    assert not rr2.errors, rr2.errors
    # stessi fingerprint nonostante le righe diverse: B404 resta ignorato, B602 ha la sua MR
    assert rr2.findings_total == 2 and rr2.findings_new == 0 and rr2.fixes == []
    fixed_rec = store.get(REPO.project, fx.task.findings[0].fingerprint)
    assert fixed_rec is not None and fixed_rec.status is FindingStatus.MR_OPEN
    rec = store.get(REPO.project, ignored_fp)
    assert rec is not None and rec.status is FindingStatus.IGNORED
    assert len(llm.structured_calls) == triage_calls  # nessun nuovo triage
    assert len(gl.projects.project.mergerequests.opened) == 1
    conn.close()
