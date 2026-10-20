import json
from typing import Any

import anthropic
import httpx2
import pytest

from maxtac.adapters.anthropic_llm import AnthropicLLM, LLMResponseError, strict_schema
from maxtac.domain.models import ToolResult, ToolResults, ToolSpec, UserText
from maxtac.domain.ports import LLMUnavailable
from maxtac.services.ripperdoc import TOOLS
from maxtac.services.trauma import VERDICT_TOOL

USAGE = {
    "input_tokens": 120,
    "output_tokens": 30,
    "cache_read_input_tokens": 900,
    "cache_creation_input_tokens": 50,
}


def message(content: list[dict[str, Any]], stop: str = "end_turn", model: str = "m") -> dict:
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop,
        "stop_sequence": None,
        "usage": USAGE,
    }


class Recorder:
    def __init__(self, *responses: httpx2.Response) -> None:
        self.responses = list(responses)
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        return self.responses.pop(0)

    def body(self, i: int = -1) -> dict[str, Any]:
        return json.loads(self.requests[i].content)


def make_llm(rec: Recorder, **kwargs: Any) -> AnthropicLLM:
    client = anthropic.Anthropic(
        api_key="sk-test",
        max_retries=0,
        http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(rec)),
    )
    return AnthropicLLM(client, **kwargs)


def ok(content: list[dict[str, Any]], **kw: Any) -> httpx2.Response:
    return httpx2.Response(200, json=message(content, **kw))


def error(status: int, kind: str, msg: str) -> httpx2.Response:
    return httpx2.Response(status, json={"type": "error", "error": {"type": kind, "message": msg}})


def test_strict_schema_closes_objects_and_drops_defaults():
    s = strict_schema(
        {
            "type": "object",
            "properties": {
                "a": {"type": "array", "items": {"type": "object", "properties": {}}},
                "p": {"type": "string", "default": "."},
            },
        }
    )
    assert s["additionalProperties"] is False
    assert s["properties"]["a"]["items"]["additionalProperties"] is False
    assert "default" not in s["properties"]["p"]


def test_structured_uses_json_schema_output_not_forced_tool():
    rec = Recorder(ok([{"type": "text", "text": '{"verdicts": []}'}], model="claude-haiku-5-5"))
    llm = make_llm(rec, effort={"claude-haiku-5-5": "low"})
    res = llm.structured(
        model="claude-haiku-5-5", system="S", prompt="P", tool=VERDICT_TOOL, max_tokens=100
    )
    body = rec.body()
    assert "tool_choice" not in body and "tools" not in body
    assert body["output_config"]["format"]["type"] == "json_schema"
    assert body["output_config"]["effort"] == "low"
    assert body["output_config"]["format"]["schema"]["additionalProperties"] is False
    assert body["system"][0]["cache_control"] == {"type": "ephemeral"}
    # Haiku 5.5 non ha fallback lato server: endpoint normale, niente beta
    assert "fallbacks" not in body and "beta=true" not in str(rec.requests[0].url)
    assert res.data == {"verdicts": []}
    assert res.model == "claude-haiku-5-5"
    assert res.usage.cache_read_tokens == 900 and res.usage.cache_write_tokens == 50


@pytest.mark.parametrize("stop", ["refusal", "max_tokens"])
def test_structured_unusable_stop_raises(stop):
    rec = Recorder(ok([{"type": "text", "text": "{"}], stop=stop))
    with pytest.raises(LLMResponseError):
        make_llm(rec).structured(
            model="claude-haiku-5-5", system="S", prompt="P", tool=VERDICT_TOOL, max_tokens=10
        )


def test_structured_invalid_json_raises():
    rec = Recorder(ok([{"type": "text", "text": "non json"}]))
    with pytest.raises(LLMResponseError):
        make_llm(rec).structured(
            model="claude-haiku-5-5", system="S", prompt="P", tool=VERDICT_TOOL, max_tokens=10
        )


def test_turn_round_trip_with_tools_cache_and_fallback():
    thinking = {"type": "thinking", "thinking": "", "signature": "sig123"}
    tool_use = {"type": "tool_use", "id": "toolu_1", "name": "run", "input": {"cmd": "ls"}}
    rec = Recorder(
        ok(
            [thinking, {"type": "text", "text": "guardo"}, tool_use],
            stop="tool_use",
            model="claude-sonnet-5-5",
        ),
        ok([{"type": "text", "text": "fatto"}], model="claude-sonnet-5-5"),
    )
    llm = make_llm(rec)
    first = llm.turn(
        model="claude-sonnet-5-5",
        system="S",
        messages=[UserText("fix")],
        tools=TOOLS,
        max_tokens=1000,
    )
    assert first.stop_reason == "tool_use"
    assert first.text == "guardo"
    assert first.tool_calls[0].name == "run" and first.tool_calls[0].args == {"cmd": "ls"}

    body = rec.body(0)
    assert "beta=true" in str(rec.requests[0].url)
    assert rec.requests[0].headers["anthropic-beta"] == "server-side-fallback-2026-07-01"
    assert body["fallbacks"] == "default"
    assert body["tools"][-1]["cache_control"] == {"type": "ephemeral"}
    assert all("cache_control" not in t for t in body["tools"][:-1])
    assert body["messages"][-1]["content"][-1]["cache_control"] == {"type": "ephemeral"}

    history = [UserText("fix"), first, ToolResults((ToolResult("toolu_1", "boom", True),))]
    second = llm.turn(
        model="claude-sonnet-5-5", system="S", messages=history, tools=TOOLS, max_tokens=1000
    )
    assert second.stop_reason == "end_turn" and second.text == "fatto"
    msgs = rec.body(1)["messages"]
    # il turno dell'assistente torna identico, thinking e firma compresi
    assert msgs[1] == {"role": "assistant", "content": [thinking, msgs[1]["content"][1], tool_use]}
    assert msgs[1]["content"][0]["signature"] == "sig123"
    result = msgs[2]["content"][0]
    assert result["type"] == "tool_result" and result["tool_use_id"] == "toolu_1"
    assert result["is_error"] is True and result["content"] == "boom"
    # breakpoint solo sull'ultimo messaggio utente
    assert result["cache_control"] == {"type": "ephemeral"}
    assert "cache_control" not in msgs[0]["content"][-1]
    # i blocchi raw del primo turno non sono stati modificati dal secondo invio
    assert "cache_control" not in first.raw[-1]


def test_fallback_can_be_disabled():
    rec = Recorder(ok([{"type": "text", "text": "x"}]))
    make_llm(rec, refusal_fallback=False).turn(
        model="claude-sonnet-5-5",
        system="S",
        messages=[UserText("x")],
        tools=TOOLS,
        max_tokens=10,
    )
    assert "fallbacks" not in rec.body()


@pytest.mark.parametrize(
    ("stop", "expected"),
    [("stop_sequence", "end_turn"), ("pause_turn", "other"), ("refusal", "refusal")],
)
def test_stop_reason_mapping(stop, expected):
    rec = Recorder(ok([{"type": "text", "text": "x"}], stop=stop))
    t = make_llm(rec).turn(
        model="claude-haiku-5-5",
        system="S",
        messages=[UserText("x")],
        tools=[ToolSpec("t", "d", {"type": "object", "properties": {}})],
        max_tokens=10,
    )
    assert t.stop_reason == expected


@pytest.mark.parametrize(
    "resp",
    [
        error(400, "invalid_request_error", "Your credit balance is too low to access the API."),
        error(401, "authentication_error", "invalid x-api-key"),
        error(403, "permission_error", "nope"),
        error(404, "not_found_error", "model: claude-x"),
    ],
)
def test_unrecoverable_errors_become_llm_unavailable(resp):
    rec = Recorder(resp)
    with pytest.raises(LLMUnavailable) as exc:
        make_llm(rec).turn(
            model="claude-haiku-5-5",
            system="S",
            messages=[UserText("x")],
            tools=TOOLS,
            max_tokens=10,
        )
    assert "sk-test" not in str(exc.value)


def test_other_bad_request_is_not_unavailable():
    rec = Recorder(error(400, "invalid_request_error", "messages: bad shape"))
    with pytest.raises(anthropic.BadRequestError):
        make_llm(rec).turn(
            model="claude-haiku-5-5",
            system="S",
            messages=[UserText("x")],
            tools=TOOLS,
            max_tokens=10,
        )


def test_overloaded_is_retried_by_sdk():
    rec = Recorder(
        error(529, "overloaded_error", "Overloaded"),
        ok([{"type": "text", "text": "x"}]),
    )
    client = anthropic.Anthropic(
        api_key="sk-test",
        max_retries=2,
        http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(rec)),
    )
    llm = AnthropicLLM(client.with_options(max_retries=2))
    t = llm.turn(
        model="claude-haiku-5-5", system="S", messages=[UserText("x")], tools=TOOLS, max_tokens=10
    )
    assert t.text == "x" and len(rec.requests) == 2
