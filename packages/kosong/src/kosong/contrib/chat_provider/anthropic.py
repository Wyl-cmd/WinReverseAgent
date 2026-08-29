from __future__ import annotations

import json
import logging
from typing import Any

from anthropic import AsyncAnthropic, AsyncStream, omit
from anthropic.types import (
    Message as AnthropicMessage,
    MessageDeltaEvent,
    MessageStartEvent,
    MessageParam,
    RawContentBlockDeltaEvent,
    RawContentBlockStartEvent,
    RawMessageStreamEvent,
    TextBlockParam,
    ToolParam,
    ToolResultBlockParam,
    ToolUseBlockParam,
    CacheControlEphemeralParam,
)
from anthropic.lib.streaming import MessageStopEvent

from kosong.types import (
    GenerateResult,
    Message,
    StreamedMessagePart,
    TextPart,
    ThinkPart,
    Tool,
    ToolCall,
    ToolCallPart,
    Usage,
)
from kosong.providers.shim import OpenAIShim

_logger = logging.getLogger("kosong.anthropic")


class Anthropic:
    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: str,
        default_max_tokens: int = 4096,
        metadata: dict[str, Any] | None = None,
        default_headers: dict[str, str] | None = None,
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key.strip()
        self._default_max_tokens = default_max_tokens
        self._metadata = metadata
        self._default_headers = default_headers or {}
        self._shim = OpenAIShim()
        self.thinking_effort: str | None = None
        self._thinking_config: dict[str, Any] | None = None
        self._beta_features: list[str] = []
        self._client = AsyncAnthropic(
            api_key=self._api_key,
            base_url=self._base_url,
            default_headers=self._default_headers if self._default_headers else None,
            timeout=300.0,
            max_retries=3,
        )

    @property
    def model_name(self) -> str:
        return self._model

    def with_thinking(self, effort: str) -> Anthropic:
        clone = Anthropic(
            model=self._model,
            base_url=self._base_url,
            api_key=self._api_key,
            default_max_tokens=self._default_max_tokens,
            metadata=self._metadata,
            default_headers=self._default_headers,
        )
        clone.thinking_effort = effort
        if effort == "off":
            clone._thinking_config = {"type": "disabled"}
            clone._beta_features = []
        else:
            budget = 8192 if effort == "high" else 5000
            clone._thinking_config = {"type": "enabled", "budget_tokens": budget}
            clone._beta_features = ["interleaved-thinking-2025-05-14"]
        return clone

    def _request_headers(self) -> dict[str, str] | None:
        if not self._beta_features:
            return None
        return {"anthropic-beta": ",".join(self._beta_features)}

    def _extract_system_and_messages(
        self,
        messages: list[dict[str, Any]],
    ) -> tuple[list[TextBlockParam] | None, list[MessageParam]]:
        system_texts: list[str] = []
        non_system: list[dict[str, Any]] = []
        for msg in messages:
            if msg.get("role") == "system":
                content = msg.get("content", "")
                if isinstance(content, str):
                    system_texts.append(content)
            else:
                non_system.append(msg)

        params: list[MessageParam] = []
        for msg in non_system:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            tool_calls = msg.get("tool_calls") or []
            tool_call_id = msg.get("tool_call_id")

            if role == "tool" and tool_call_id:
                tool_content: Any = content
                if isinstance(tool_content, list):
                    text_parts: list[str] = []
                    for blk in tool_content:
                        if isinstance(blk, dict) and blk.get("type") == "text":
                            text_parts.append(blk.get("text", ""))
                        elif isinstance(blk, str):
                            text_parts.append(blk)
                    tool_content = "\n".join(text_parts)
                elif not isinstance(tool_content, str):
                    tool_content = str(tool_content) if tool_content else ""
                params.append(MessageParam(role="user", content=[
                    {
                        "type": "tool_result",
                        "tool_use_id": str(tool_call_id),
                        "content": tool_content or "",
                    }
                ]))
                continue

            if role == "assistant" and tool_calls:
                blocks: list[dict[str, Any]] = []
                if isinstance(content, str) and content.strip():
                    blocks.append({"type": "text", "text": content})
                elif isinstance(content, list):
                    for blk in content:
                        if isinstance(blk, dict) and blk.get("type") == "text":
                            blocks.append({"type": "text", "text": blk.get("text", "")})
                for tc in tool_calls:
                    if not isinstance(tc, dict):
                        continue
                    func = tc.get("function") or {}
                    raw_args = func.get("arguments", tc.get("arguments", "{}"))
                    tool_name = func.get("name") or tc.get("name", "")
                    try:
                        parsed_input = json.loads(raw_args) if isinstance(raw_args, str) and raw_args else (raw_args if isinstance(raw_args, dict) else {})
                    except (json.JSONDecodeError, TypeError):
                        parsed_input = {}
                    blocks.append({
                        "type": "tool_use",
                        "id": tc.get("id", ""),
                        "name": tool_name,
                        "input": parsed_input,
                    })
                params.append(MessageParam(role="assistant", content=blocks))
                continue

            if isinstance(content, list):
                blocks2: list[dict[str, Any]] = []
                for block in content:
                    if isinstance(block, dict):
                        if block.get("type") == "text":
                            blocks2.append({"type": "text", "text": block.get("text", "")})
                        elif block.get("type") == "tool_use":
                            blocks2.append({
                                "type": "tool_use",
                                "id": block.get("id", ""),
                                "name": block.get("name", ""),
                                "input": block.get("input", {}),
                            })
                        elif block.get("type") == "tool_result":
                            blocks2.append({
                                "type": "tool_result",
                                "tool_use_id": block.get("tool_use_id", ""),
                                "content": block.get("content", ""),
                            })
                        elif block.get("type") == "image_url":
                            image_url = block.get("image_url", {})
                            url = image_url.get("url", "") if isinstance(image_url, dict) else ""
                            if url.startswith("data:"):
                                try:
                                    media_part, b64 = url.split(",", 1)
                                    media_type = media_part.split(";")[0].replace("data:", "") or "image/png"
                                    blocks2.append({
                                        "type": "image",
                                        "source": {"type": "base64", "media_type": media_type, "data": b64},
                                    })
                                except Exception:
                                    pass
                    elif isinstance(block, str):
                        blocks2.append({"type": "text", "text": block})
                if blocks2:
                    params.append(MessageParam(role=role if role in ("user", "assistant") else "user", content=blocks2))
                continue

            text = content if isinstance(content, str) else (str(content) if content else "")
            if text:
                params.append(MessageParam(role=role if role in ("user", "assistant") else "user", content=text))

        system = None
        if system_texts:
            system = [TextBlockParam(type="text", text="\n".join(system_texts))]

        return system, params

    def _convert_tools(self, tools: list[dict[str, Any]]) -> list[ToolParam]:
        anthropic_tools: list[ToolParam] = []
        for tool in tools:
            func = tool.get("function", {})
            if func:
                anthropic_tools.append(ToolParam(
                    name=func.get("name", ""),
                    description=func.get("description", ""),
                    input_schema=func.get("parameters", {"type": "object", "properties": {}}),
                ))
        return anthropic_tools

    def _merge_tool_results(self, messages: list[MessageParam]) -> list[MessageParam]:
        merged: list[MessageParam] = []
        pending_tool_results: list[dict[str, Any]] = []
        for msg in messages:
            content = msg["content"]
            is_tool_result_msg = (
                msg["role"] == "user"
                and isinstance(content, list)
                and all(isinstance(b, dict) and b.get("type") == "tool_result" for b in content)
            )
            if is_tool_result_msg:
                pending_tool_results.extend(content)
                continue
            if pending_tool_results:
                merged.append(MessageParam(role="user", content=pending_tool_results))
                pending_tool_results = []
            merged.append(msg)
        if pending_tool_results:
            merged.append(MessageParam(role="user", content=pending_tool_results))
        return merged

    async def generate(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        system, anthropic_msgs = self._extract_system_and_messages(messages)
        anthropic_msgs = self._merge_tool_results(anthropic_msgs)

        create_kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": anthropic_msgs,
            "max_tokens": kwargs.get("max_tokens", self._default_max_tokens),
        }
        if system:
            create_kwargs["system"] = system
        if tools:
            create_kwargs["tools"] = self._convert_tools(tools)
        if "temperature" in kwargs:
            create_kwargs["temperature"] = kwargs["temperature"]
        if self._thinking_config:
            create_kwargs["thinking"] = self._thinking_config
        extra_headers = self._request_headers()
        if extra_headers:
            create_kwargs["extra_headers"] = extra_headers

        _logger.info("Anthropic POST model=%s stream=False", self._model)
        response = await self._client.messages.create(**create_kwargs)
        return response.model_dump()

    async def generate_stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ):
        system, anthropic_msgs = self._extract_system_and_messages(messages)
        anthropic_msgs = self._merge_tool_results(anthropic_msgs)

        create_kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": anthropic_msgs,
            "max_tokens": kwargs.get("max_tokens", self._default_max_tokens),
            "stream": True,
        }
        if system:
            create_kwargs["system"] = system
        if tools:
            create_kwargs["tools"] = self._convert_tools(tools)
        if "temperature" in kwargs:
            create_kwargs["temperature"] = kwargs["temperature"]
        if self._thinking_config:
            create_kwargs["thinking"] = self._thinking_config
        extra_headers = self._request_headers()
        if extra_headers:
            create_kwargs["extra_headers"] = extra_headers

        _logger.info("Anthropic STREAM model=%s base_url=%s", self._model, self._base_url)

        tool_call_states: dict[int, ToolCall] = {}

        try:
            response = await self._client.messages.create(**create_kwargs)
            async with response as stream:
                async for event in stream:
                    if isinstance(event, MessageStartEvent):
                        pass
                    elif isinstance(event, RawContentBlockStartEvent):
                        block = event.content_block
                        block_type = getattr(block, "type", "")
                        block_index = event.index
                        if block_type == "tool_use":
                            tc_id = getattr(block, "id", "")
                            name = getattr(block, "name", "")
                            tool_call = ToolCall(
                                id=tc_id,
                                function=ToolCall.FunctionBody(name=name, arguments=""),
                            )
                            tool_call_states[block_index] = tool_call
                            yield tool_call
                        elif block_type == "thinking":
                            thinking_text = getattr(block, "thinking", "")
                            if thinking_text:
                                yield ThinkPart(think=thinking_text)
                    elif isinstance(event, RawContentBlockDeltaEvent):
                        delta = event.delta
                        delta_type = getattr(delta, "type", "")
                        if delta_type == "text_delta":
                            text = getattr(delta, "text", "")
                            if text:
                                yield TextPart(text=text)
                        elif delta_type == "thinking_delta":
                            think = getattr(delta, "thinking", "")
                            if think:
                                yield ThinkPart(think=think)
                        elif delta_type == "input_json_delta":
                            block_index = event.index
                            partial_json = getattr(delta, "partial_json", "")
                            if partial_json and block_index in tool_call_states:
                                yield ToolCallPart(arguments_part=partial_json)
                        elif delta_type == "signature_delta":
                            pass
                    elif isinstance(event, MessageDeltaEvent):
                        pass
                    elif isinstance(event, MessageStopEvent):
                        pass
        except Exception as exc:
            _logger.error("Anthropic stream error: %s", exc)
            raise
