import pytest

from maxtac.domain.models import Finding, RepoConfig, Severity, ToolResults, Usage
from maxtac.domain.policy import group_into_tasks
from maxtac.services.ripperdoc import Ripperdoc

from .fakes import FakeSandbox, ScriptedLLM, call, default_exec, end_turn, tool_turn

REPO = RepoConfig(
    "alex/ecs2", ("python",), "pytest -q", setup_command="pip install -r requirements.txt"
)
TASK = group_into_tasks([Finding("sast", "semgrep", "eval", "app.py", Severity.HIGH, "eval")])[0]


def sandbox(files=None):
    return FakeSandbox(dict(files or {"app.py": "eval(x)\n"}), default_exec)


def test_tools_run_in_sandbox_and_loop_ends(night):
    sb = sandbox()
    llm = ScriptedLLM(
        [
            tool_turn(call("list_files"), call("read_file", path="app.py")),
            tool_turn(
                call("write_file", path="app.py", content="int(x)\n"), call("run", cmd="pytest -q")
            ),
            end_turn("sostituito eval con int"),
        ]
    )
    out = Ripperdoc(llm, "claude-sonnet-5-5").fix(REPO, TASK, sb, night.meter("fix", 0.8))
    assert out.finished and out.stop == "end_turn" and out.iterations == 3
    assert out.summary == "sostituito eval con int"
    assert sb.files["app.py"] == "int(x)\n"
    assert sb.commands == ["pytest -q"]
    results = [m for m in llm.turn_calls[-1] if isinstance(m, ToolResults)]
    first = results[0].results
    assert first[0].content == "app.py" and first[1].content == "eval(x)\n"
    assert results[1].results[1].content.startswith("exit=0")


def test_traversal_and_unknown_tool_return_errors_to_model(night):
    sb = sandbox()
    llm = ScriptedLLM(
        [
            tool_turn(
                call("read_file", path="../../etc/passwd"),
                call("rm_rf"),
                call("read_file", path="nope.py"),
            ),
            end_turn(),
        ]
    )
    Ripperdoc(llm, "claude-sonnet-5-5").fix(REPO, TASK, sb, night.meter("fix", 0.8))
    results = next(m for m in llm.turn_calls[-1] if isinstance(m, ToolResults)).results
    assert all(r.is_error for r in results)
    assert "fuori dalla working tree" in results[0].content
    assert "tool sconosciuto" in results[1].content


def test_stops_at_max_iterations(night):
    llm = ScriptedLLM([tool_turn(call("list_files")) for _ in range(5)])
    out = Ripperdoc(llm, "claude-sonnet-5-5", max_iterations=3).fix(
        REPO, TASK, sandbox(), night.meter("fix", 0.8)
    )
    assert not out.finished and out.stop == "max_iterations" and len(llm.turn_calls) == 3


def test_stops_at_task_budget(night):
    big = Usage(input_tokens=200_000)  # 0,40$ a turno
    llm = ScriptedLLM([tool_turn(call("list_files"), usage=big) for _ in range(5)])
    m = night.meter("fix", 0.80)
    out = Ripperdoc(llm, "claude-sonnet-5-5").fix(REPO, TASK, sandbox(), m)
    assert not out.finished and out.stop == "budget"
    assert len(llm.turn_calls) == 2 and m.spent == pytest.approx(0.80)


def test_max_tokens_is_failure(night):
    from maxtac.domain.models import AssistantTurn

    llm = ScriptedLLM([AssistantTurn("...", (), "max_tokens", Usage(1, 1), "claude-sonnet-5-5")])
    out = Ripperdoc(llm, "claude-sonnet-5-5").fix(REPO, TASK, sandbox(), night.meter("fix", 0.8))
    assert not out.finished and out.stop == "max_tokens"


def test_prompt_contains_task_and_commands(night):
    llm = ScriptedLLM([end_turn()])
    Ripperdoc(llm, "claude-sonnet-5-5").fix(REPO, TASK, sandbox(), night.meter("fix", 0.8))
    first = llm.turn_calls[0][0].text
    assert "pytest -q" in first and "pip install" in first and "<findings>" in first
