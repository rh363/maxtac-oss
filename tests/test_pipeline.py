"""Pipeline end-to-end con adapter finti: nessuna rete, nessun container."""

from dataclasses import replace
from pathlib import Path

import pytest

from maxtac.domain.models import ExecResult, FindingStatus, Outcome, RepoConfig
from maxtac.domain.policy import branch_name, group_into_tasks
from maxtac.services.pipeline import Limits, Models, Pipeline, PipelineSettings

from .conftest import PRICING
from .fakes import (
    FakeGitLab,
    FakeSandboxes,
    FakeScanner,
    FakeVCS,
    ScriptedLLM,
    call,
    end_turn,
    eval_sast,
    fix_all,
    requests_cve,
    tool_turn,
)

VULNERABLE = {
    "requirements.txt": "requests==2.19.0\n",
    "app.py": "import requests\n",
    "tests/test_app.py": "def test_ok(): pass\n",
}


def repo(project: str = "alex/ecs2") -> RepoConfig:
    return RepoConfig(
        project, ("python",), "pytest -q", setup_command="pip install -r requirements.txt"
    )


def bump_turns():
    return [
        tool_turn(
            call("write_file", path="requirements.txt", content="requests==2.32.3\n"),
            call("run", cmd="pytest -q"),
        ),
        end_turn("requests 2.19.0 -> 2.32.3"),
    ]


class World:
    def __init__(
        self,
        tmp_path: Path,
        store,
        budget_port,
        clock,
        *,
        files=None,
        repos=None,
        turns=(),
        structured_fn=fix_all,
        handler=None,
        limits=Limits(),
        kinds=("cve",),
        dry_run=False,
    ):
        self.gl = FakeGitLab(
            repos={r.project: dict(files or VULNERABLE) for r in (repos or [repo()])}
        )
        self.repos = repos or [repo()]
        self.vcs = FakeVCS(self.gl)
        self.sandboxes = (
            FakeSandboxes(self.vcs) if handler is None else FakeSandboxes(self.vcs, handler)
        )
        self.llm = ScriptedLLM(list(turns), structured_fn)
        self.osv = FakeScanner("osv-scanner", "cve", requests_cve)
        self.semgrep = FakeScanner("semgrep", "sast", eval_sast)
        self.store, self.clock = store, clock
        self.settings = PipelineSettings(
            limits=limits,
            models=Models("claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5"),
            workdir=tmp_path,
            enabled_kinds=frozenset(kinds),
            dry_run=dry_run,
        )
        self.pipeline = Pipeline(
            self.vcs,
            self.sandboxes,
            [self.osv, self.semgrep],
            self.llm,
            store,
            budget_port,
            PRICING,
            self.settings,
            clock,
        )
        self.nights = 0

    def run(self, **kw):
        self.nights += 1
        self.clock.advance(days=1)
        return self.pipeline.run_night(self.repos, run_id=f"night-{self.nights}", **kw)

    def status(self, finding):
        rec = self.store.get("alex/ecs2", finding.fingerprint)
        return rec.status if rec else None


@pytest.fixture
def world(tmp_path, store, budget_port, clock):
    def make(**kw):
        return World(tmp_path, store, budget_port, clock, **kw)

    return make


def cve_findings():
    return requests_cve(VULNERABLE)


def test_cve_fixed_verified_and_mr_opened(world):
    w = world(turns=bump_turns())
    report = w.run()

    [fx] = report.repos[0].fixes
    assert fx.outcome is Outcome.MR_OPENED, fx.detail
    assert fx.mr_url and fx.mr_url.endswith("/merge_requests/1")
    [mr] = w.gl.mrs
    task = group_into_tasks(cve_findings())[0]
    assert mr["branch"] == branch_name(task) == fx.branch
    assert mr["labels"] == ["autofix"]
    assert mr["title"].startswith("[autofix] Aggiorna requests")
    assert "GHSA-x84v-xcm2-53pg" in mr["body"] and "raggiungibile" in mr["body"]
    [(_, branch, tree)] = w.gl.pushed
    assert tree["requirements.txt"] == "requests==2.32.3\n"
    for f in cve_findings():
        rec = w.store.get("alex/ecs2", f.fingerprint)
        assert (
            rec.status is FindingStatus.MR_OPEN and rec.branch == branch and rec.mr_url == fx.mr_url
        )
    # scan, fix e verifica in tre sandbox distinti; rescan dell'osv-scanner nella verifica
    assert len(w.sandboxes.opened) == 3
    assert w.osv.calls == 2
    verify_sb = w.sandboxes.opened[2]
    assert verify_sb.commands == ["pip install -r requirements.txt", "pytest -q"]
    # una sola chiamata di triage, e la spesa è registrata
    assert len(w.llm.structured_calls) == 1
    assert 0 < report.spent_usd < 0.1 and fx.cost_usd > 0
    assert report.repos[0].findings_total == 2 and report.repos[0].findings_new == 2


def test_dry_run_no_push_no_mr_no_state_change(world):
    w = world(turns=bump_turns(), dry_run=True)
    report = w.run()
    [fx] = report.repos[0].fixes
    assert fx.outcome is Outcome.DRY_RUN
    assert "modified requirements.txt" in fx.diff
    assert w.gl.pushed == [] and w.gl.mrs == []
    assert all(w.status(f) is FindingStatus.NEW for f in cve_findings())
    assert report.spent_usd > 0  # i crediti si spendono anche in dry-run


def red_tests(cmd, files):
    return (
        ExecResult(1, "FAILED tests/test_app.py") if cmd.startswith("pytest") else ExecResult(0, "")
    )


def test_red_tests_count_attempts_then_needs_human(world):
    w = world(turns=bump_turns() * 2, handler=red_tests)
    first = w.run()
    assert first.repos[0].fixes[0].outcome is Outcome.VERIFY_FAILED
    assert "test rossi" in first.repos[0].fixes[0].detail
    assert {w.store.get("alex/ecs2", f.fingerprint).attempts for f in cve_findings()} == {1}
    assert w.gl.mrs == []

    w.run()
    assert all(w.status(f) is FindingStatus.NEEDS_HUMAN for f in cve_findings())

    calls = len(w.llm.turn_calls)
    third = w.run()
    assert third.repos[0].findings_new == 0 and len(w.llm.turn_calls) == calls


def test_agent_touching_existing_tests_goes_to_human(world):
    turns = [
        tool_turn(
            call("write_file", path="requirements.txt", content="requests==2.32.3\n"),
            call("write_file", path="tests/test_app.py", content=""),
        ),
        end_turn(),
    ]
    w = world(turns=turns)
    [fx] = w.run().repos[0].fixes
    assert fx.outcome is Outcome.NEEDS_HUMAN and "tests/test_app.py" in fx.detail
    assert w.gl.mrs == [] and w.gl.pushed == []
    assert all(w.status(f) is FindingStatus.NEEDS_HUMAN for f in cve_findings())


def test_empty_diff_is_failure(world):
    w = world(turns=[end_turn("tutto ok, niente da fare")])
    [fx] = w.run().repos[0].fixes
    assert fx.outcome is Outcome.AGENT_FAILED and fx.detail == "diff vuoto"


def test_finding_still_present_after_fix_fails_verification(world):
    w = world(turns=[tool_turn(call("write_file", path="NOTES.md", content="x")), end_turn()])
    [fx] = w.run().repos[0].fixes
    assert fx.outcome is Outcome.VERIFY_FAILED and "ancora presente" in fx.detail


def test_open_mr_is_skipped(world):
    w = world()
    task = group_into_tasks(cve_findings())[0]
    w.gl.open_branches.add(("alex/ecs2", branch_name(task)))
    report = w.run()
    assert report.repos[0].skipped_open_mr == 1 and report.repos[0].fixes == []
    assert w.llm.structured_calls == []
    assert all(w.status(f) is FindingStatus.MR_OPEN for f in cve_findings())


def test_mr_closed_without_merge_becomes_ignored(world):
    w = world(turns=bump_turns())
    w.run()
    assert len(w.gl.mrs) == 1
    w.gl.open_branches.clear()  # qualcuno chiude la MR senza merge
    second = w.run()
    assert all(w.status(f) is FindingStatus.IGNORED for f in cve_findings())
    assert second.repos[0].fixes == [] and len(w.gl.mrs) == 1


def test_triage_ignore_and_needs_human_are_persisted(world):
    def verdicts(model, prompt, tool):
        out = fix_all(model, prompt, tool)
        out["verdicts"][0]["decision"] = "ignore"
        return out

    w = world(structured_fn=verdicts)
    report = w.run()
    assert len(report.repos[0].ignored) == 1 and report.repos[0].fixes == []
    assert all(w.status(f) is FindingStatus.IGNORED for f in cve_findings())


def test_max_mrs_per_night(world):
    w = world(
        turns=bump_turns() * 2,
        repos=[repo("alex/a"), repo("alex/b")],
        limits=Limits(max_mrs_per_night=1),
    )
    report = w.run()
    assert len(w.gl.mrs) == 1
    assert report.repos[1].fixes == []


def test_night_budget_exhausted_stops_next_tasks(world):
    files = {"a.py": "eval(x)\n", "b.py": "eval(y)\n"}
    turns = [tool_turn(call("write_file", path="a.py", content="int(x)\n")), end_turn()]
    w = world(files=files, turns=turns, kinds=("sast",), limits=Limits(per_night_usd=0.05))
    report = w.run()
    first, second = report.repos[0].fixes
    assert first.outcome is Outcome.MR_OPENED
    assert second.outcome is Outcome.BUDGET_EXHAUSTED and second.detail == "tetto della notte"
    assert w.store.get("alex/ecs2", second.task.findings[0].fingerprint).attempts == 0
    assert len(w.llm.turn_calls) == 2


def test_task_budget_counts_as_attempt(world):
    from maxtac.domain.models import Usage

    big = Usage(input_tokens=500_000)  # 1$ a turno con Sonnet
    w = world(turns=[tool_turn(call("list_files"), usage=big)])
    [fx] = w.run().repos[0].fixes
    assert fx.outcome is Outcome.BUDGET_EXHAUSTED and fx.detail == "tetto del task"
    assert {w.store.get("alex/ecs2", f.fingerprint).attempts for f in cve_findings()} == {1}


def test_broken_repo_does_not_block_others(world):
    w = world(turns=bump_turns(), repos=[repo("alex/rotto"), repo("alex/ok")])
    w.gl.broken.add("alex/rotto")
    report = w.run()
    assert report.repos[0].errors and "clone fallito" in report.repos[0].errors[0]
    assert report.repos[1].fixes[0].outcome is Outcome.MR_OPENED


def test_scanner_crash_is_reported_and_others_continue(world):
    w = world(kinds=("cve", "sast"))
    w.semgrep._rule = lambda files: 1 / 0
    report = w.run()
    del report
    # osv ha trovato le CVE comunque: il triage le ha viste
    assert len(w.llm.structured_calls) == 1


def test_setup_failure_is_error_without_attempt(world):
    def handler(cmd, files):
        return ExecResult(1, "pip esploso") if cmd.startswith("pip") else ExecResult(0, "")

    w = world(handler=handler)
    [fx] = w.run().repos[0].fixes
    assert fx.outcome is Outcome.ERROR and "setup fallito" in fx.detail
    assert {w.store.get("alex/ecs2", f.fingerprint).attempts for f in cve_findings()} == {0}
    assert w.llm.turn_calls == []


# --- bug hunting ---

CLEAN = {
    "app.py": "def div(a, b):\n    return a / b\n",
    "tests/test_app.py": "def test_ok(): pass\n",
}


def hunter_says(bugs):
    def fn(model, prompt, tool):
        if tool.name == "report_bugs":
            return {"bugs": bugs}
        return fix_all(model, prompt, tool)

    return fn


BUG = {
    "file": "app.py",
    "line": 2,
    "title": "Division by zero",
    "detail": "b può essere 0",
    "severity": "high",
    "confidence": "high",
}
MAYBE = {**BUG, "title": "Forse", "confidence": "medium"}


def div_zero_tests(cmd, files):
    """Il test di regressione fallisce se c'è ma il codice non gestisce b == 0."""
    if cmd == "pytest -q" and "tests/test_div_zero.py" in files and "if b" not in files["app.py"]:
        return ExecResult(1, "FAILED tests/test_div_zero.py::test_zero - ZeroDivisionError")
    return ExecResult(0, "ok")


def hunting_world(world, turns, bugs=(BUG, MAYBE), **kw):
    w = world(
        files=CLEAN, turns=turns, kinds=("cve", "bug"), structured_fn=hunter_says(list(bugs)), **kw
    )
    for r in w.repos:
        w.gl.recent[r.project] = ("+ return a / b", ["app.py", "gone.py"])
    return w


def test_hunting_bug_without_regression_test_fails(world, store):
    w = hunting_world(
        world,
        [
            tool_turn(
                call(
                    "write_file",
                    path="app.py",
                    content="def div(a, b):\n    return a / b if b else 0\n",
                )
            ),
            end_turn(),
        ],
    )
    report = w.run()
    rr = report.repos[0]
    assert rr.hunted and rr.bugs_found == 1
    [fx] = rr.fixes
    assert fx.task.kind == "bug" and fx.outcome is Outcome.VERIFY_FAILED
    assert "test di regressione" in fx.detail
    assert store.last_hunted("alex/ecs2") is not None
    [(model, tool, prompt)] = w.llm.structured_calls  # niente CVE: nessun triage
    assert model == "claude-opus-5-5" and tool == "report_bugs"
    assert '<file path="app.py">' in prompt and "gone.py" not in prompt


def test_hunting_bug_with_regression_test_opens_mr(world):
    turns = [
        tool_turn(
            call(
                "write_file",
                path="app.py",
                content="def div(a, b):\n    return a / b if b else 0\n",
            ),
            call("write_file", path="tests/test_div_zero.py", content="def test_zero(): ...\n"),
        ),
        end_turn("gestito b == 0"),
    ]
    w = hunting_world(world, turns, bugs=[BUG], handler=div_zero_tests)
    [fx] = w.run().repos[0].fixes
    assert fx.outcome is Outcome.MR_OPENED and fx.branch.startswith("autofix/bug/")
    assert "bug ad alta confidenza" in w.gl.mrs[0]["body"]
    # il controllo sul base ha ripristinato il fix: il push contiene fix e test
    [(_, _, pushed)] = w.gl.pushed
    assert "if b" in pushed["app.py"] and "tests/test_div_zero.py" in pushed


def test_regression_test_passing_on_base_is_rejected(world, store):
    turns = [
        tool_turn(
            call(
                "write_file",
                path="app.py",
                content="def div(a, b):\n    return a / b if b else 0\n",
            ),
            call("write_file", path="tests/test_div_zero.py", content="def test_zero(): ...\n"),
        ),
        end_turn(),
    ]
    w = hunting_world(world, turns, bugs=[BUG])  # i test passano sempre, anche sul base
    [fx] = w.run().repos[0].fixes
    assert fx.outcome is Outcome.VERIFY_FAILED and "passa anche senza il fix" in fx.detail
    assert w.gl.mrs == []
    assert store.get("alex/ecs2", fx.task.findings[0].fingerprint).attempts == 1


def test_hunting_rotation(world):
    repos = [repo("alex/a"), repo("alex/b"), repo("alex/c")]
    w = hunting_world(world, [], bugs=[], repos=repos)
    w.settings = replace(w.settings, hunting_repos_per_night=1)
    w.pipeline.settings = w.settings
    hunted = []
    for _ in range(3):
        r = w.run()
        hunted += [x.project for x in r.repos if x.hunted]
    assert sorted(hunted) == ["alex/a", "alex/b", "alex/c"]


def test_hunting_cap_shared_across_repos(world):
    w = hunting_world(
        world,
        [],
        bugs=[],
        repos=[repo("alex/a"), repo("alex/b")],
        limits=Limits(hunting_per_night_usd=0.02),
    )
    report = w.run()
    a, b = report.repos
    assert a.hunted and not a.errors
    assert b.errors and "bug hunting saltato" in b.errors[0]
    assert len(w.llm.structured_calls) == 1


def test_llm_unavailable_stops_the_night_without_attempts(world):
    from maxtac.domain.ports import LLMUnavailable

    w = world(
        turns=[LLMUnavailable("crediti API esauriti")],
        repos=[repo("alex/ecs2"), repo("alex/fwagent")],
    )
    report = w.run()
    assert report.aborted and "crediti" in report.aborted
    first, second = report.repos
    assert first.fixes == [] and any("crediti" in e for e in first.errors)
    assert second.findings_total == 0 and second.errors[0].startswith("non eseguito")
    # nessun tentativo contato: i finding restano nuovi e riprovabili la notte dopo
    for f in cve_findings():
        rec = w.store.get("alex/ecs2", f.fingerprint)
        assert rec.status is FindingStatus.NEW and rec.attempts == 0
    assert w.gl.mrs == []


def test_unpriced_fallback_model_is_charged_at_highest_price(world):
    from maxtac.domain.models import AssistantTurn, Usage

    turns = bump_turns()
    turns[-1] = AssistantTurn("ok", (), "end_turn", Usage(input_tokens=100_000), "claude-nuovo")
    w = world(turns=turns)
    report = w.run()
    [fx] = report.repos[0].fixes
    assert fx.outcome is Outcome.MR_OPENED
    # 100k token al prezzo più alto noto (Opus: 4$/MTok) = 0,40$
    assert fx.cost_usd >= 0.40
