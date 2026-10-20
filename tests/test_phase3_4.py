"""Fasi 3 e 4: verifica SAST più severa, bug hunting stabile, storico run, notifiche, settimana."""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from maxtac.adapters.notifier import NoopNotifier, NotifyError, WebhookNotifier, payload
from maxtac.adapters.sqlite_store import SqliteRunStore
from maxtac.domain.models import (
    AssistantTurn,
    ExecResult,
    FileChange,
    Finding,
    FindingStatus,
    Message,
    Outcome,
    RepoConfig,
    RunReport,
    Severity,
    StructuredResult,
    Task,
    ToolResults,
    ToolSpec,
    Usage,
    UserText,
)
from maxtac.domain.policy import introduced_findings
from maxtac.presentation.lexicon import CYBERPUNK, NEUTRAL
from maxtac.presentation.report import render_status
from maxtac.services.hunter import bug_rule
from maxtac.services.pipeline import Limits, Models, Pipeline, PipelineSettings

from .conftest import PRICING
from .fakes import (
    FakeGitLab,
    FakeSandboxes,
    FakeScanner,
    FakeVCS,
    Files,
    ScriptedLLM,
    call,
    end_turn,
    eval_sast,
    fix_all,
    requests_cve,
    tool_turn,
)

MODELS = Models("claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5")


def repo(project: str = "alex/ecs2") -> RepoConfig:
    return RepoConfig(project, ("python",), "pytest -q", setup_command="pip install -e .")


def make_pipeline(
    tmp_path: Path,
    store: Any,
    budget_port: Any,
    clock: Any,
    gl: FakeGitLab,
    llm: Any,
    scanners: Sequence[FakeScanner],
    *,
    handler: Any = None,
    kinds: Sequence[str] = ("cve", "sast"),
    limits: Limits = Limits(),
    hunting_repos_per_night: int = 2,
    runs: Any = None,
    notifier: Any = None,
) -> tuple[Pipeline, FakeVCS]:
    vcs = FakeVCS(gl)
    sandboxes = FakeSandboxes(vcs) if handler is None else FakeSandboxes(vcs, handler)
    settings = PipelineSettings(
        limits=limits,
        models=MODELS,
        workdir=tmp_path,
        enabled_kinds=frozenset(kinds),
        hunting_repos_per_night=hunting_repos_per_night,
    )
    p = Pipeline(
        vcs,
        sandboxes,
        list(scanners),
        llm,
        store,
        budget_port,
        PRICING,
        settings,
        clock,
        runs=runs,
        notifier=notifier,
    )
    return p, vcs


# --- regola "nessun finding nuovo" (unit) ---


def sast(rule: str, path: str, sev: Severity = Severity.HIGH, tool: str = "bandit") -> Finding:
    return Finding("sast", tool, rule, path, sev, "x")


def test_introduced_findings_only_new_in_touched_files_above_threshold() -> None:
    fixed = sast("B602", "app.py")
    task = Task("sast", fixed.fingerprint, (fixed,))
    baseline = {fixed.fingerprint, sast("B404", "app.py", Severity.LOW).fingerprint}
    found = [
        sast("B404", "app.py", Severity.LOW),  # già presente stanotte
        sast("B603", "app.py", Severity.LOW),  # nuovo ma sotto soglia
        sast("B506", "app.py", Severity.MEDIUM),  # nuovo, nel file toccato: blocca
        sast("B307", "other.py", Severity.HIGH),  # nuovo ma in un file non toccato
    ]
    new = introduced_findings(task, found, baseline, {"app.py"})
    assert [f.rule for f in new] == ["B506"]


def test_introduced_findings_cve_counts_everywhere() -> None:
    old = Finding("cve", "osv-scanner", "GHSA-a", "requests@2.19.0", Severity.HIGH, "")
    task = Task("cve", "requests", (old,))
    bumped = Finding("cve", "osv-scanner", "GHSA-b", "requests@2.31.0", Severity.HIGH, "")
    assert introduced_findings(task, [bumped], {old.fingerprint}, {"requirements.txt"}) == [bumped]


# --- SAST end-to-end con fake ---

SHELL_APP = {
    "app.py": "import subprocess\n\ndef ls(p):\n    return subprocess.run('ls ' + p, shell=True)\n",
    "tests/test_app.py": "def test_ok(): pass\n",
}


def shell_sast(files: Files) -> list[Finding]:
    """Bandit finto: B602 con shell=True, B506 con yaml.load."""
    out = []
    for path, body in files.items():
        if not path.endswith(".py") or path.startswith("tests/"):
            continue
        if "shell=True" in body:
            out.append(sast("B602:subprocess_popen_with_shell_equals_true", path))
        if "yaml.load(" in body:
            out.append(sast("B506:yaml_load", path, Severity.MEDIUM))
    return out


def test_sast_rescan_runs_only_the_producing_scanner(tmp_path, store, budget_port, clock):
    gl = FakeGitLab(repos={"alex/ecs2": dict(SHELL_APP)})
    bandit = FakeScanner("bandit", "sast", shell_sast)
    semgrep = FakeScanner("semgrep", "sast", eval_sast)
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
            end_turn("shell=False con argomenti in lista"),
        ],
        fix_all,
    )
    p, _ = make_pipeline(tmp_path, store, budget_port, clock, gl, llm, [bandit, semgrep])
    [fx] = p.run_night([repo()], run_id="n1").repos[0].fixes
    assert fx.outcome is Outcome.MR_OPENED, fx.detail
    assert bandit.calls == 2  # scan iniziale + rescan di verifica
    assert semgrep.calls == 1  # solo lo scan iniziale


def test_fix_introducing_a_new_finding_fails_verification(tmp_path, store, budget_port, clock):
    gl = FakeGitLab(repos={"alex/ecs2": dict(SHELL_APP)})
    bandit = FakeScanner("bandit", "sast", shell_sast)
    llm = ScriptedLLM(
        [
            tool_turn(
                call(
                    "write_file",
                    path="app.py",
                    content="import subprocess, yaml\n\ndef ls(p):\n"
                    "    return subprocess.run(['ls', yaml.load(p)])\n",
                )
            ),
            end_turn(),
        ],
        fix_all,
    )
    p, _ = make_pipeline(tmp_path, store, budget_port, clock, gl, llm, [bandit])
    [fx] = p.run_night([repo()], run_id="n1").repos[0].fixes
    assert fx.outcome is Outcome.VERIFY_FAILED
    assert "introduce finding nuovi" in fx.detail and "B506" in fx.detail
    assert gl.mrs == []


# --- bug hunting: dedup stabile ---


def test_bug_rule_uses_symbol_when_present() -> None:
    assert bug_rule("Parser.parse_header", "Off by one") == "symbol:parser.parse_header"
    assert bug_rule("", "Off by one!") == "title:off-by-one"


CLEAN = {
    "app.py": "def div(a, b):\n    return a / b\n",
    "tests/test_app.py": "def test_ok(): pass\n",
}


def div_tests(cmd: str, files: Files) -> ExecResult:
    for path in files:
        m = re.match(r"tests/test_regr_(\w+)\.py$", path)
        if cmd == "pytest -q" and m and "if b" not in files.get("app.py", ""):
            return ExecResult(1, f"FAILED {path}")
    return ExecResult(0, "ok")


class HuntLLM(ScriptedLLM):
    """Hunter che a ogni notte riformula lo stesso bug con un titolo diverso."""

    def __init__(self, turns: Sequence[AssistantTurn], symbol: str = "div") -> None:
        self.nights = 0
        self.symbol = symbol
        super().__init__(turns, self._structured)

    def _structured(self, model: str, prompt: str, tool: ToolSpec) -> dict[str, Any]:
        if tool.name != "report_bugs":
            return fix_all(model, prompt, tool)
        self.nights += 1
        return {
            "bugs": [
                {
                    "file": "app.py",
                    "line": 2,
                    "symbol": self.symbol,
                    "title": f"Division by zero (formulazione {self.nights})",
                    "detail": "b può essere 0",
                    "severity": "high",
                    "confidence": "high",
                }
            ]
        }


def bug_fix_turns() -> list[AssistantTurn]:
    return [
        tool_turn(
            call(
                "write_file",
                path="app.py",
                content="def div(a, b):\n    return a / b if b else 0\n",
            ),
            call("write_file", path="tests/test_regr_div.py", content="def test_zero(): ...\n"),
        ),
        end_turn("gestito b == 0"),
    ]


def test_same_bug_with_different_title_is_not_reproposed(tmp_path, store, budget_port, clock):
    gl = FakeGitLab(repos={"alex/ecs2": dict(CLEAN)}, recent={"alex/ecs2": ("+x", ["app.py"])})
    llm = HuntLLM(bug_fix_turns())
    p, _ = make_pipeline(
        tmp_path, store, budget_port, clock, gl, llm, [], handler=div_tests, kinds=("bug",)
    )
    first = p.run_night([repo()], run_id="n1").repos[0]
    assert [fx.outcome for fx in first.fixes] == [Outcome.MR_OPENED]
    clock.advance(days=1)
    second = p.run_night([repo()], run_id="n2").repos[0]
    assert second.hunted and second.fixes == [] and second.bugs_found == 0
    assert len(gl.mrs) == 1


def test_ignored_bug_on_same_symbol_stays_ignored(tmp_path, store, budget_port, clock):
    gl = FakeGitLab(repos={"alex/ecs2": dict(CLEAN)}, recent={"alex/ecs2": ("+x", ["app.py"])})
    llm = HuntLLM([])
    p, _ = make_pipeline(
        tmp_path, store, budget_port, clock, gl, llm, [], handler=div_tests, kinds=("bug",)
    )
    # un umano ha chiuso la MR di questo bug: è ignorato per file + simbolo
    from maxtac.services.hunter import Hunter

    known = Finding("bug", "hunter", bug_rule("div", "x"), "app.py", Severity.HIGH, "")
    assert Hunter  # import usato solo per chiarezza del contratto
    store.observe("alex/ecs2", [known], clock())
    store.set_status("alex/ecs2", known.fingerprint, FindingStatus.IGNORED, "MR chiusa senza merge")
    rr = p.run_night([repo()], run_id="n1").repos[0]
    assert rr.hunted and rr.bugs_found == 0 and rr.fixes == []


def test_hunting_rotation_breaks_same_night_ties_by_count(store, clock) -> None:
    from maxtac.domain.policy import pick_hunting_repos

    repos = [repo(p) for p in ("alex/a", "alex/b", "alex/c")]
    seen: Counter[str] = Counter()
    for _ in range(6):
        picked = pick_hunting_repos(repos, store.last_hunted, 2, store.hunt_count)
        for r in picked:
            store.mark_hunted(r.project, clock())
            seen[r.project] += 1
        clock.advance(days=1)
    assert seen == {"alex/a": 4, "alex/b": 4, "alex/c": 4}
    assert store.hunt_count("alex/a") == 4 and store.hunt_count("alex/zzz") == 0


# --- storico run e notifiche ---


class RecordingNotifier:
    def __init__(self, fail: bool = False) -> None:
        self.reports: list[RunReport] = []
        self.fail = fail

    def notify(self, report: RunReport) -> None:
        self.reports.append(report)
        if self.fail:
            raise RuntimeError("webhook giù")


VULNERABLE = {
    "requirements.txt": "requests==2.19.0\n",
    "tests/test_app.py": "def test_ok(): pass\n",
}


def bump_turns() -> list[AssistantTurn]:
    return [
        tool_turn(call("write_file", path="requirements.txt", content="requests==2.32.3\n")),
        end_turn("bump"),
    ]


def test_run_is_persisted_and_notified(tmp_path, conn, store, budget_port, clock):
    gl = FakeGitLab(repos={"alex/ecs2": dict(VULNERABLE)})
    runs, notifier = SqliteRunStore(conn), RecordingNotifier()
    osv = FakeScanner("osv-scanner", "cve", requests_cve)
    p, _ = make_pipeline(
        tmp_path,
        store,
        budget_port,
        clock,
        gl,
        ScriptedLLM(bump_turns(), fix_all),
        [osv],
        runs=runs,
        notifier=notifier,
    )
    report = p.run_night([repo()], run_id="n1")
    [summary] = runs.recent_runs(5)
    assert summary.run_id == "n1" and summary.mrs_opened == 1 and not summary.dry_run
    assert summary.spent_usd == pytest.approx(report.spent_usd)
    assert summary.started_at is not None and summary.finished_at is not None
    data = runs.get_run("n1")
    assert data is not None
    [fx] = data["repos"][0]["fixes"]
    assert fx["outcome"] == "mr_opened" and fx["mr_url"] and "requirements.txt" in fx["diff"]
    assert fx["task"]["findings"][0]["rule"].startswith("GHSA-")
    assert runs.get_run("missing") is None
    assert notifier.reports == [report]


def test_notifier_failure_does_not_lose_the_run(tmp_path, conn, store, budget_port, clock):
    gl = FakeGitLab(repos={"alex/ecs2": dict(VULNERABLE)})
    runs = SqliteRunStore(conn)
    p, _ = make_pipeline(
        tmp_path,
        store,
        budget_port,
        clock,
        gl,
        ScriptedLLM(bump_turns(), fix_all),
        [FakeScanner("osv-scanner", "cve", requests_cve)],
        runs=runs,
        notifier=RecordingNotifier(fail=True),
    )
    report = p.run_night([repo()], run_id="n1")
    assert len(report.mrs_opened) == 1 and runs.get_run("n1") is not None


def test_status_lists_recent_runs(conn, store, budget_port, clock):
    runs = SqliteRunStore(conn)
    r = RunReport("20261020T013000Z", dry_run=True, spent_usd=0.42, started_at=clock())
    runs.save_run(r)
    runs.save_run(r)  # idempotente
    text = render_status(
        NEUTRAL,
        month_spent=0.42,
        month_label="2026-10",
        counts={},
        open_mrs=[],
        next_run="-",
        runs=runs.recent_runs(5),
    )
    assert "20261020T013000Z: $0.42, 0 MR dry-run" in text


def test_webhook_payload_is_neutral_and_errors_hide_url() -> None:
    sent: list[tuple[str, bytes]] = []

    def post(url: str, body: bytes, headers: dict[str, str], timeout: float) -> int:
        sent.append((url, body))
        return 200

    url = "https://hooks.slack.com/services/T000/B000/SEGRETO"
    WebhookNotifier(url, post=post).notify(RunReport("n1", dry_run=False, night_cap_usd=3.0))
    [(got, body)] = sent
    data = json.loads(body)
    assert got == url and data["run_id"] == "n1" and data["text"].startswith("# Autofix")
    for word in (CYBERPUNK.product, CYBERPUNK.tagline, "Blackwall", "eddies", "€$"):
        assert word not in data["text"]

    def boom(*a: Any) -> int:
        raise OSError(f"connessione a {url} rifiutata")

    with pytest.raises(NotifyError) as e:
        WebhookNotifier(url, post=boom).notify(RunReport("n1", dry_run=False))
    assert "SEGRETO" not in str(e.value)
    with pytest.raises(NotifyError, match="500"):
        WebhookNotifier(url, post=lambda *a: 500).notify(RunReport("n1", dry_run=False))
    with pytest.raises(ValueError):
        WebhookNotifier("http://insecure.example")
    assert NoopNotifier().notify(RunReport("n1", dry_run=False)) is None
    assert payload(RunReport("n1", dry_run=True))["dry_run"] is True


# --- una settimana di notti ---

WEEK_FILES = {
    "requirements.txt": "requests==2.19.0\n",
    "app.py": "def div(a, b):\n    return a / b\n",
    "calc.py": "def run(expr):\n    return eval(expr)\n",
    "tests/test_app.py": "def test_ok(): pass\n",
}

TURN = Usage(input_tokens=100_000, output_tokens=5_000)  # 0,25$ con Sonnet 5.5
HUNT = Usage(input_tokens=100_000, output_tokens=5_000)  # 0,50$ con Opus 5.5
TRIAGE = Usage(input_tokens=5_000, output_tokens=500)


class WeekLLM:
    """Modello finto ma "ragionevole": legge il task e scrive il fix giusto."""

    def __init__(self) -> None:
        self.hunts = 0

    def structured(
        self, *, model: str, system: str, prompt: str, tool: ToolSpec, max_tokens: int
    ) -> StructuredResult:
        if tool.name == "report_bugs":
            self.hunts += 1
            data = HuntLLM([])._structured(model, prompt, tool)
            data["bugs"][0]["title"] = f"Divisione per zero #{self.hunts}"
            return StructuredResult(data, HUNT, model)
        return StructuredResult(fix_all(model, prompt, tool), TRIAGE, model)

    def turn(
        self,
        *,
        model: str,
        system: str,
        messages: Sequence[Message],
        tools: Sequence[ToolSpec],
        max_tokens: int,
    ) -> AssistantTurn:
        first = messages[0]
        assert isinstance(first, UserText)
        body = re.search(r"<findings>\n(.*)\n</findings>", first.text, re.S)
        assert body
        f = json.loads(body.group(1))[0]
        last = messages[-1]
        if len(messages) == 1:
            if "Task (cve)" in first.text:
                return tool_turn(
                    call("write_file", path="requirements.txt", content="requests==2.32.3\n"),
                    usage=TURN,
                )
            if "Task (bug)" in first.text:
                return tool_turn(*bug_fix_turns()[0].tool_calls, usage=TURN)
            return tool_turn(call("read_file", path=f["location"]), usage=TURN)
        if isinstance(last, ToolResults) and "Task (sast)" in first.text and len(messages) == 3:
            fixed = last.results[0].content.replace("eval(expr)", "int(expr)")
            return tool_turn(
                call("write_file", path=f["location"], content=fixed),
                usage=TURN,
            )
        return end_turn("fatto", usage=TURN)


def week_tests(cmd: str, files: Files) -> ExecResult:
    return div_tests(cmd, files)


def test_a_week_of_nights_respects_caps_rotation_and_dedup(
    tmp_path, conn, store, budget_port, clock
):
    projects = ["alex/a", "alex/b", "alex/c"]
    repos = [repo(p) for p in projects]
    gl = FakeGitLab(
        repos={p: dict(WEEK_FILES) for p in projects},
        recent={p: ("+ return a / b", ["app.py"]) for p in projects},
    )
    limits = Limits(
        per_night_usd=3.0,
        per_task_usd=0.80,
        hunting_per_night_usd=1.0,
        max_mrs_per_night=3,
    )
    osv = FakeScanner("osv-scanner", "cve", requests_cve)
    semgrep = FakeScanner("semgrep", "sast", eval_sast)
    runs = SqliteRunStore(conn)
    p, _ = make_pipeline(
        tmp_path,
        store,
        budget_port,
        clock,
        gl,
        WeekLLM(),
        [osv, semgrep],
        handler=week_tests,
        kinds=("cve", "sast", "bug"),
        limits=limits,
        runs=runs,
    )
    max_call = 0.50  # la chiamata più cara: i tetti si controllano prima di ogni chiamata
    hunted: Counter[str] = Counter()
    for night in range(1, 8):
        clock.advance(days=1)
        run_id = f"n{night}"
        report = p.run_night(repos, run_id=run_id)
        assert not report.aborted
        by_scope = dict(
            conn.execute(
                "SELECT scope, SUM(usd) FROM spend WHERE run_id = ? GROUP BY scope", (run_id,)
            ).fetchall()
        )
        assert report.spent_usd <= limits.per_night_usd + max_call
        fix_scopes = [v for k, v in by_scope.items() if k.startswith("fix:")]
        assert all(v <= limits.per_task_usd + 0.25 for v in fix_scopes)
        hunt_spend = sum(v for k, v in by_scope.items() if k.startswith("hunt:"))
        assert hunt_spend <= limits.hunting_per_night_usd + max_call
        assert len(report.mrs_opened) <= limits.max_mrs_per_night
        hunted.update(r.project for r in report.repos if r.hunted)
        if night == 2:  # un umano fa il merge delle MR di alex/a: si applicano i soli diff
            base = dict(WEEK_FILES)
            for project, branch, tree in list(gl.pushed):
                if project == "alex/a" and (project, branch) in gl.open_branches:
                    merged = gl.repos[project]
                    merged.update({k: v for k, v in tree.items() if base.get(k) != v})
                    for gone in set(base) - set(tree):
                        merged.pop(gone, None)
                    gl.open_branches.discard((project, branch))

    branches = [(m["project"], m["branch"]) for m in gl.mrs]
    assert len(branches) == len(set(branches)), "MR duplicata"
    # ogni repo ha avuto CVE, SAST e bug sistemati entro la settimana
    for project in projects:
        kinds = {b.split("/")[1] for pr, b in branches if pr == project}
        assert kinds == {"cve", "sast", "bug"}, (project, kinds)
    # rotazione: 2 repo a notte su 3, distribuiti in modo uniforme
    assert sum(hunted.values()) == 14 and max(hunted.values()) - min(hunted.values()) <= 1
    # dopo il merge, i finding di alex/a sono spariti dallo scan
    last = runs.get_run("n7")
    assert last is not None
    a = next(r for r in last["repos"] if r["project"] == "alex/a")
    assert a["findings_total"] == 0
    assert len(runs.recent_runs(10)) == 7


def test_changes_identity_after_regression_restore_handles_deletions(
    tmp_path, store, budget_port, clock
):
    """Il ripristino del fix dopo il controllo sul base rimette anche le cancellazioni."""
    files = {**CLEAN, "legacy.py": "x = 1\n"}
    gl = FakeGitLab(repos={"alex/ecs2": files}, recent={"alex/ecs2": ("+x", ["app.py"])})
    turns = bug_fix_turns()
    turns[0] = tool_turn(*turns[0].tool_calls, call("run", cmd="rm legacy.py"))

    def handler(cmd: str, fs: Files) -> ExecResult:
        if cmd == "rm legacy.py" or cmd == "rm -f -- legacy.py":
            fs.pop("legacy.py", None)
            return ExecResult(0, "")
        return div_tests(cmd, fs)

    p, _ = make_pipeline(
        tmp_path,
        store,
        budget_port,
        clock,
        gl,
        HuntLLM(turns),
        [],
        handler=handler,
        kinds=("bug",),
    )
    [fx] = p.run_night([repo()], run_id="n1").repos[0].fixes
    assert fx.outcome is Outcome.MR_OPENED, fx.detail
    [(_, _, pushed)] = gl.pushed
    assert "legacy.py" not in pushed and "tests/test_regr_div.py" in pushed


def test_file_change_type_is_hashable_for_sorting() -> None:
    assert sorted([FileChange("b", "added"), FileChange("a", "deleted")], key=lambda c: c.path)
