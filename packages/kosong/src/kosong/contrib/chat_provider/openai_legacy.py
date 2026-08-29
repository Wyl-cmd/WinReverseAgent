"""OpenAI Chat Completions Provider（OpenAI SDK，对齐 kimi-cli / kxns-cli）。"""

from __future__ import annotations

import copy
import uuid
from typing import Any

import httpx
from openai import AsyncStream, Omit, OpenAIError, omit
from openai.types.chat import ChatCompletion, ChatCompletionChunk

from kosong.contrib.chat_provider.openai_common import (
    ThinkingEffort,
    convert_openai_error,
    create_openai_client,
    extract_reasoning_from_delta,
    thinking_effort_to_reasoning_effort,
)
from kosong.providers.reasoning import (
    ReasoningKeyDetect,
    extract_reasoning_from_openai_message,
    extract_reasoning_from_openai_stream,
)
from kosong.types import StreamedMessagePart, TextPart, ThinkPart, ToolCall, ToolCallPart


class OpenAILegacy:
    """OpenAI 兼容 Chat Completions（DeepSeek / 火山方舟等通过 reasoning_key 解析 thinking）。"""

    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: str,
        reasoning_key: str | None = None,
        default_max_tokens: int = 4096,
        metadata: dict[str, Any] | None = None,
        default_headers: dict[str, str] | None = None,
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._reasoning_key = reasoning_key
        self._original_reasoning_key = reasoning_key
        self._default_max_tokens = default_max_tokens
        self._metadata = metadata
        self._default_headers = default_headers or {}
        self._reasoning_effort: ReasoningEffort | Omit = omit
        self._extra_body: dict[str, Any] | None = None
        self._generation_kwargs: dict[str, Any] = {}
        self.client = create_openai_client(
            api_key=self._api_key,
            base_url=self._base_url,
            default_headers=self._default_headers or None,
        )

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def thinking_effort(self) -> str | None:
        if isinstance(self._reasoning_effort, Omit):
            return None
        return str(self._reasoning_effort)

    def with_thinking(self, effort: str) -> OpenAILegacy:
        """对齐 kxns-cli：off 时关闭 reasoning_key；否则映射 reasoning_effort。"""
        clone = copy.copy(self)
        teffort: ThinkingEffort
        if effort == "off":
            teffort = "off"
        elif effort in ("low", "medium", "high"):
            teffort = effort  # type: ignore[assignment]
        else:
            teffort = "high"
        if teffort == "off":
            clone._reasoning_effort = omit
            clone._reasoning_key = None
        else:
            clone._reasoning_effort = thinking_effort_to_reasoning_effort(teffort)
            if clone._reasoning_key is None:
                clone._reasoning_key = clone._original_reasoning_key
        return clone

    def with_extra_body(self, extra_body: dict[str, Any]) -> OpenAILegacy:
        clone = copy.copy(self)
        clone._extra_body = dict(extra_body)
        return clone

    def with_generation_kwargs(self, **kwargs: Any) -> OpenAILegacy:
        clone = copy.copy(self)
        clone._generation_kwargs = {**clone._generation_kwargs, **kwargs}
        return clone

    async def generate(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        try:
            response = await self._create_completion(messages, tools, stream=False, **kwargs)
            if isinstance(response, ChatCompletion):
                return response.model_dump()
            return dict(response)
        except (OpenAIError, httpx.HTTPError) as exc:
            raise convert_openai_error(exc) from exc

    async def generate_stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ):
        async for part in self.generate_stream_parts(messages, tools, **kwargs):
            for chunk in _openai_part_to_legacy_chunks(part):
                yield chunk

    async def generate_stream_parts(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ):
        """OpenAI Chat Completions 流式 → ThinkPart / TextPart / ToolCall（SDK delta 解析）。"""
        detect = ReasoningKeyDetect(configured_key=self._reasoning_key)
        tool_states: dict[int, ToolCall] = {}
        accumulated_reasoning = ""
        accumulated_content = ""
        finish_reason_emitted = False

        if self._reasoning_key and not isinstance(self._reasoning_effort, Omit):
            yield ThinkPart(think="")

        try:
            response = await self._create_completion(messages, tools, stream=True, **kwargs)
        except (OpenAIError, httpx.HTTPError) as exc:
            raise convert_openai_error(exc) from exc

        if not isinstance(response, AsyncStream):
            return

        try:
            async for chunk in response:
                if not chunk.choices:
                    if chunk.usage:
                        yield {"usage": chunk.usage.model_dump()}
                    continue

                choice = chunk.choices[0]
                delta = choice.delta

                reasoning = extract_reasoning_from_delta(delta, self._reasoning_key)
                if not reasoning:
                    reasoning = extract_reasoning_from_openai_stream(
                        choice={"delta": delta.model_dump(exclude_none=True)},
                        delta=delta.model_dump(exclude_none=True),
                        message={},
                        detect=detect,
                    )
                if reasoning:
                    if accumulated_reasoning and reasoning.startswith(accumulated_reasoning):
                        reasoning = reasoning[len(accumulated_reasoning):]
                    if reasoning:
                        accumulated_reasoning += reasoning
                        yield ThinkPart(think=reasoning)

                content = delta.content
                if isinstance(content, str) and content:
                    if accumulated_content and content.startswith(accumulated_content):
                        content = content[len(accumulated_content):]
                    if content:
                        accumulated_content += content
                        yield TextPart(text=content)

                for tc_delta in delta.tool_calls or []:
                    if not tc_delta.function:
                        continue
                    index = tc_delta.index or 0
                    if tc_delta.function.name:
                        tool_call = ToolCall(
                            id=tc_delta.id or str(uuid.uuid4()),
                            function=ToolCall.FunctionBody(
                                name=tc_delta.function.name,
                                arguments=tc_delta.function.arguments or None,
                            ),
                        )
                        tool_states[index] = tool_call
                        yield tool_call
                    elif tc_delta.function.arguments:
                        yield ToolCallPart(arguments_part=tc_delta.function.arguments)

                finish_reason = choice.finish_reason
                if finish_reason and not finish_reason_emitted:
                    finish_reason_emitted = True
                    yield {"finish_reason": finish_reason}

                if chunk.usage:
                    yield {"usage": chunk.usage.model_dump()}
        except (OpenAIError, httpx.HTTPError) as exc:
            raise convert_openai_error(exc) from exc

    async def _create_completion(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        *,
        stream: bool,
        **kwargs: Any,
    ) -> ChatCompletion | AsyncStream[ChatCompletionChunk]:
        reasoning_effort = self._reasoning_effort
        # 历史含 reasoning 字段时自动补 reasoning_effort（对齐 kimi-cli #1616）
        if isinstance(reasoning_effort, Omit) and self._reasoning_key:
            for msg in messages:
                if isinstance(msg, dict) and msg.get(self._reasoning_key):
                    reasoning_effort = "medium"
                    break

        call_kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "stream": stream,
        }
        max_tokens = kwargs.get("max_tokens", self._default_max_tokens)
        if max_tokens is not None:
            call_kwargs["max_tokens"] = max_tokens
        if "temperature" in kwargs and kwargs["temperature"] is not None:
            call_kwargs["temperature"] = kwargs["temperature"]
        call_kwargs.update(self._generation_kwargs)

        if not isinstance(reasoning_effort, Omit):
            call_kwargs["reasoning_effort"] = reasoning_effort

        # 允许调用方显式传入 extra_body / reasoning_effort（manager 不再注入 thinking 对象）
        for key in ("reasoning_effort", "extra_body"):
            if key in kwargs and kwargs[key] is not None:
                call_kwargs[key] = kwargs[key]

        if self._extra_body:
            existing = call_kwargs.get("extra_body")
            if isinstance(existing, dict):
                merged = {**existing, **self._extra_body}
            else:
                merged = dict(self._extra_body)
            call_kwargs["extra_body"] = merged

        if stream:
            call_kwargs["stream_options"] = {"include_usage": True}

        if tools:
            call_kwargs["tools"] = tools

        return await self.client.chat.completions.create(**call_kwargs)


def extract_reasoning_from_message(
    message: dict[str, Any],
    reasoning_key: str | None = None,
) -> str:
    """从非流式 message 对象提取 reasoning 正文。"""
    return extract_reasoning_from_openai_message(message, reasoning_key)


def _openai_part_to_legacy_chunks(part: StreamedMessagePart | ToolCall | dict[str, Any]):
    if isinstance(part, ThinkPart):
        yield {"choices": [{"delta": {"reasoning_content": part.think}}]}
    elif isinstance(part, TextPart):
        yield {"choices": [{"delta": {"content": part.text}}]}
    elif isinstance(part, ToolCall):
        yield {
            "choices": [{
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "id": part.id,
                        "function": {
                            "name": part.function.name,
                            "arguments": part.function.arguments or "",
                        },
                    }],
                },
            }],
        }
    elif isinstance(part, ToolCallPart):
        yield {
            "choices": [{
                "delta": {
                    "tool_calls": [{"index": 0, "function": {"arguments": part.arguments_part}}],
                },
            }],
        }
    elif isinstance(part, dict):
        if "usage" in part:
            yield part
        elif part.get("finish_reason"):
            yield {"choices": [{"finish_reason": part["finish_reason"]}]}
