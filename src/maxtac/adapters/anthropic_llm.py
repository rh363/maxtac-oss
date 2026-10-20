"""LLMPort sulla Messages API di Anthropic. Un passo alla volta: il loop resta nel dominio."""

from __future__ import annotations

import copy
import json
import logging
from collections.abc import Collection, Mapping, Sequence
from typing import Any, Literal

import anthropic

from maxtac.domain.models import (
    AssistantTurn,
    Message,
    StructuredResult,
    ToolCall,
    ToolResults,
    ToolSpec,
    Usage,
    UserText,
)
from maxtac.domain.ports import LLMUnavailable

log = logging.getLogger(__name__)

EPHEMERAL: dict[str, str] = {"type": "ephemeral"}
FALLBACK_BETA = "server-side-fallback-2026-07-01"
# Modelli per cui esiste il fallback lato server sul rifiuto (Haiku 5.5 non ce l'ha).
DEFAULT_FALLBACK_MODELS = frozenset({"claude-opus-5-5", "claude-sonnet-5-5"})

StopReason = Literal["end_turn", "tool_use", "max_tokens", "refusal", "other"]
_STOP: dict[str, StopReason] = {
    "end_turn": "end_turn",
    "stop_sequence": "end_turn",
    "tool_use": "tool_use",
    "max_tokens": "max_tokens",
    "refusal": "refusal",
}


class LLMResponseError(RuntimeError):
    """Risposta inutilizzabile per questa chiamata (rifiuto, JSON troncato o non valido)."""


def strict_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    """Adatta uno schema ai vincoli degli structured output.

    Ogni oggetto deve avere `additionalProperties: false`; `default` non è supportato.
    """

    def fix(node: Any) -> Any:
        if isinstance(node, dict):
            out = {k: fix(v) for k, v in node.items() if k != "default"}
            if out.get("type") == "object":
                out["additionalProperties"] = False
            return out
        if isinstance(node, list):
            return [fix(v) for v in node]
        return node

    result: dict[str, Any] = fix(dict(schema))
    return result


def _is_credit_error(e: anthropic.APIStatusError) -> bool:
    text = f"{e.message} {getattr(e, 'body', '')}".lower()
    return "credit balance" in text or "billing" in text


class AnthropicLLM:
    def __init__(
        self,
        client: anthropic.Anthropic,
        *,
        effort: Mapping[str, str] | None = None,
        refusal_fallback: bool = True,
        fallback_models: Collection[str] = DEFAULT_FALLBACK_MODELS,
    ) -> None:
        self._client = client
        self._effort = dict(effort or {})
        self._fallback = refusal_fallback
        self._fallback_models = frozenset(fallback_models)

    @classmethod
    def from_api_key(
        cls, api_key: str, *, timeout_s: float, max_retries: int, **kwargs: Any
    ) -> AnthropicLLM:
        client = anthropic.Anthropic(api_key=api_key, timeout=timeout_s, max_retries=max_retries)
        return cls(client, **kwargs)

    # --- LLMPort ---

    def structured(
        self,
        *,
        model: str,
        system: str,
        prompt: str,
        tool: ToolSpec,
        max_tokens: int,
    ) -> StructuredResult:
        # Niente tool_choice forzato (400 su Opus/Sonnet 5.5): structured output con lo
        # schema del tool, che garantisce JSON valido su tutti i modelli in uso.
        params = self._base(model, system, max_tokens)
        params["messages"] = [
            {"role": "user", "content": f"{prompt}\n\nRispondi con JSON: {tool.description}"}
        ]
        params["output_config"] = {
            **params.get("output_config", {}),
            "format": {"type": "json_schema", "schema": strict_schema(tool.input_schema)},
        }
        resp = self._create(params)
        stop = getattr(resp, "stop_reason", None)
        if stop in ("refusal", "max_tokens"):
            raise LLMResponseError(f"risposta strutturata non valida: stop_reason={stop}")
        text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise LLMResponseError(f"JSON non valido dal modello: {e}") from e
        if not isinstance(data, dict):
            raise LLMResponseError("il modello non ha restituito un oggetto JSON")
        return StructuredResult(data, _usage(resp), str(resp.model))

    def turn(
        self,
        *,
        model: str,
        system: str,
        messages: Sequence[Message],
        tools: Sequence[ToolSpec],
        max_tokens: int,
    ) -> AssistantTurn:
        params = self._base(model, system, max_tokens)
        params["tools"] = _tools(tools)
        params["messages"] = to_api_messages(messages)
        resp = self._create(params)
        text_parts, calls = [], []
        for b in resp.content:
            kind = getattr(b, "type", None)
            if kind == "text":
                text_parts.append(b.text)
            elif kind == "tool_use":
                args = b.input if isinstance(b.input, dict) else {}
                calls.append(ToolCall(id=b.id, name=b.name, args=dict(args)))
        stop = _STOP.get(str(getattr(resp, "stop_reason", "")), "other")
        return AssistantTurn(
            text="\n".join(text_parts),
            tool_calls=tuple(calls),
            stop_reason=stop,
            usage=_usage(resp),
            model=str(resp.model),
            raw=tuple(_block_dict(b) for b in resp.content),
        )

    # --- interni ---

    def _base(self, model: str, system: str, max_tokens: int) -> dict[str, Any]:
        params: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            # system identico tra task: breakpoint di cache dopo tools + system
            "system": [{"type": "text", "text": system, "cache_control": EPHEMERAL}],
        }
        if effort := self._effort.get(model):
            params["output_config"] = {"effort": effort}
        return params

    def _create(self, params: dict[str, Any]) -> Any:
        try:
            if self._fallback and params["model"] in self._fallback_models:
                return self._client.beta.messages.create(
                    **params, betas=[FALLBACK_BETA], fallbacks="default"
                )
            return self._client.messages.create(**params)
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as e:
            raise LLMUnavailable(f"chiave rifiutata ({e.status_code})") from None
        except anthropic.NotFoundError as e:
            raise LLMUnavailable(
                f"modello {params['model']} non trovato ({e.status_code})"
            ) from None
        except anthropic.BadRequestError as e:
            if _is_credit_error(e):
                raise LLMUnavailable("crediti API esauriti") from None
            raise


def _tools(tools: Sequence[ToolSpec]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = [
        {"name": t.name, "description": t.description, "input_schema": t.input_schema}
        for t in tools
    ]
    if out:
        out[-1]["cache_control"] = EPHEMERAL  # le definizioni non cambiano tra task
    return out


def to_api_messages(messages: Sequence[Message]) -> list[dict[str, Any]]:
    """Messaggi di dominio → payload della Messages API.

    I turni dell'assistente si rimandano con i blocchi originali (thinking compresi), così la
    storia resta append-only. Un breakpoint di cache sull'ultimo blocco utente rende
    incrementale la cache del loop agentico.
    """
    out: list[dict[str, Any]] = []
    for m in messages:
        if isinstance(m, UserText):
            out.append({"role": "user", "content": [{"type": "text", "text": m.text}]})
        elif isinstance(m, ToolResults):
            out.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": r.call_id,
                            "content": r.content,
                            "is_error": r.is_error,
                        }
                        for r in m.results
                    ],
                }
            )
        else:
            content = [copy.deepcopy(b) for b in m.raw] if m.raw else _rebuild(m)
            out.append({"role": "assistant", "content": content})
    for msg in reversed(out):
        if msg["role"] == "user" and msg["content"]:
            msg["content"][-1]["cache_control"] = EPHEMERAL
            break
    return out


def _rebuild(turn: AssistantTurn) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    if turn.text:
        blocks.append({"type": "text", "text": turn.text})
    blocks += [
        {"type": "tool_use", "id": c.id, "name": c.name, "input": c.args} for c in turn.tool_calls
    ]
    return blocks


def _block_dict(block: Any) -> dict[str, Any]:
    if isinstance(block, dict):
        return dict(block)
    d: dict[str, Any] = block.to_dict()
    return d


def _usage(resp: Any) -> Usage:
    u = resp.usage
    return Usage(
        input_tokens=int(getattr(u, "input_tokens", 0) or 0),
        output_tokens=int(getattr(u, "output_tokens", 0) or 0),
        cache_read_tokens=int(getattr(u, "cache_read_input_tokens", 0) or 0),
        cache_write_tokens=int(getattr(u, "cache_creation_input_tokens", 0) or 0),
    )
