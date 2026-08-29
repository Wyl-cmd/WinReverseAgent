from __future__ import annotations

import json
from typing import Any

from kosong.providers.reasoning import extract_reasoning_from_openai_message
from kosong.types import (
    GenerateResult,
    ImageURLPart,
    Message,
    TextPart,
    ThinkPart,
    Tool,
    ToolCall,
    Usage,
)


class OpenAIShim:
    def __init__(self, registry: Any = None) -> None:
        self._registry = registry

    def to_openai_messages(self, messages: list[Message]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for msg in messages:
            d: dict[str, Any] = {"role": msg.role}
            if msg.content:
                if len(msg.content) == 1 and isinstance(msg.content[0], TextPart):
                    d["content"] = msg.content[0].text
                else:
                    parts: list[dict[str, Any]] = []
                    for part in msg.content:
                        if isinstance(part, TextPart):
                            parts.append({"type": "text", "text": part.text})
                        elif isinstance(part, ImageURLPart):
                            parts.append({
                                "type": "image_url",
                                "image_url": {"url": part.image_url.url},
                            })
                    d["content"] = parts if parts else None
            else:
                d["content"] = None
            if msg.tool_calls is not None:
                d["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments or "",
                        },
                    }
                    for tc in msg.tool_calls
                ]
            if msg.tool_call_id is not None:
                d["tool_call_id"] = msg.tool_call_id
            if msg.name is not None:
                d["name"] = msg.name
            result.append(d)
        return result

    def to_openai_tools(self, tools: list[Tool]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for tool in tools:
            schema = self._tool_parameters_schema(tool)
            result.append(
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": schema,
                    },
                }
            )
        return result

    @staticmethod
    def _tool_parameters_schema(tool: Tool) -> dict[str, Any]:
        if tool.parameters_schema:
            return tool.parameters_schema
        properties: dict[str, Any] = {}
        required: list[str] = []
        for param in tool.parameters:
            prop: dict[str, Any] = {"type": param.type}
            if param.description is not None:
                prop["description"] = param.description
            if param.enum is not None:
                prop["enum"] = param.enum
            properties[param.name] = prop
            if param.required:
                required.append(param.name)
        schema: dict[str, Any] = {
            "type": "object",
            "properties": properties,
        }
        if required:
            schema["required"] = required
        return schema

    def from_openai_response(self, response: dict[str, Any]) -> GenerateResult:
        choices = response.get("choices", [])
        choice = choices[0] if choices else {}
        message_data = choice.get("message", {})

        content_parts: list[Any] = []

        reasoning_content = extract_reasoning_from_openai_message(message_data)
        if reasoning_content:
            content_parts.append(ThinkPart(think=reasoning_content))

        text_content = message_data.get("content")
        if text_content:
            content_parts.append(TextPart(text=text_content))

        tool_calls_data = message_data.get("tool_calls")
        tool_calls: list[ToolCall] | None = None
        if tool_calls_data:
            parsed_tool_calls: list[ToolCall] = []
            for tc in tool_calls_data:
                # Support both OpenAI format and non-standard format
                func = tc.get("function", {})
                if func:
                    # OpenAI standard format
                    raw_args = func.get("arguments", "")
                    name = func.get("name", "")
                else:
                    # Non-standard format (direct name and arguments)
                    raw_args = tc.get("arguments", "")
                    name = tc.get("name", "")
                arguments = raw_args if isinstance(raw_args, str) else json.dumps(raw_args)
                parsed_tool_calls.append(ToolCall(
                    id=tc["id"],
                    function=ToolCall.FunctionBody(
                        name=name,
                        arguments=arguments or None,
                    ),
                ))
            tool_calls = parsed_tool_calls

        message = Message(
            role=message_data.get("role", "assistant"),
            content=content_parts if content_parts else [],
            tool_calls=tool_calls,
            reasoning_content=reasoning_content or None,
        )

        usage_data = response.get("usage", {})
        usage = self._parse_openai_token_usage(usage_data)
        stop_reason = choice.get("finish_reason", "stop")
        return GenerateResult(
            message=message,
            usage=usage,
            stop_reason=stop_reason,
            raw_response=response,
        )

    def _parse_openai_token_usage(self, usage_data: dict[str, Any]) -> Usage | None:
        if not usage_data:
            return None
        prompt_tokens = usage_data.get("prompt_tokens", usage_data.get("input_tokens", 0))
        completion_tokens = usage_data.get("completion_tokens", usage_data.get("output_tokens", 0))
        prompt_details = usage_data.get("prompt_tokens_details", {}) or {}
        input_details = usage_data.get("input_tokens_details", {}) or {}
        cached_tokens = (
            input_details.get("cached_tokens", 0)
            or prompt_details.get("cached_tokens", 0)
            or usage_data.get("cached_tokens", 0)
            or usage_data.get("prompt_cache_hit_tokens", 0)
            or usage_data.get("cached_content_token_count", 0)
        )
        cache_creation = usage_data.get("cache_creation_input_tokens", 0) or usage_data.get("prompt_cache_miss_tokens", 0)
        return Usage(
            input_tokens=prompt_tokens,
            output_tokens=completion_tokens,
            cache_read_tokens=cached_tokens,
            cache_creation_tokens=cache_creation,
        )

    def _parse_anthropic_token_usage(self, usage_data: dict[str, Any]) -> Usage | None:
        if not usage_data:
            return None
        input_tokens = usage_data.get("input_tokens", 0)
        output_tokens = usage_data.get("output_tokens", 0)
        cache_read = usage_data.get("cache_read_input_tokens", 0)
        cache_creation = usage_data.get("cache_creation_input_tokens", 0)
        return Usage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read,
            cache_creation_tokens=cache_creation,
        )

    def _parse_google_token_usage(self, usage_data: dict[str, Any]) -> Usage | None:
        if not usage_data:
            return None
        prompt_tokens = usage_data.get("promptTokenCount", 0)
        candidates_tokens = usage_data.get("candidatesTokenCount", 0)
        cached_tokens = usage_data.get("cachedContentTokenCount", 0)
        return Usage(
            input_tokens=prompt_tokens,
            output_tokens=candidates_tokens,
            cache_read_tokens=cached_tokens,
        )

    def _parse_provider_token_usage(self, provider: str, usage_data: dict[str, Any]) -> Usage | None:
        if provider == "anthropic":
            return self._parse_anthropic_token_usage(usage_data)
        if provider == "google":
            return self._parse_google_token_usage(usage_data)
        return self._parse_openai_token_usage(usage_data)

    def anthropic_to_openai(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role == "user" and isinstance(content, list):
                parts: list[str] = []
                for block in content:
                    if isinstance(block, dict):
                        if block.get("type") == "text":
                            parts.append(block.get("text", ""))
                    elif isinstance(block, str):
                        parts.append(block)
                result.append({"role": "user", "content": "\n".join(parts)})
            elif role == "assistant" and isinstance(content, list):
                text_parts: list[str] = []
                tool_calls_list: list[dict[str, Any]] = []
                for block in content:
                    if isinstance(block, dict):
                        if block.get("type") == "text":
                            text_parts.append(block.get("text", ""))
                        elif block.get("type") == "tool_use":
                            tool_calls_list.append(
                                {
                                    "id": block["id"],
                                    "type": "function",
                                    "function": {
                                        "name": block["name"],
                                        "arguments": json.dumps(block.get("input", {})),
                                    },
                                }
                            )
                d: dict[str, Any] = {"role": "assistant"}
                if text_parts:
                    d["content"] = "\n".join(text_parts)
                if tool_calls_list:
                    d["tool_calls"] = tool_calls_list
                result.append(d)
            else:
                result.append(msg)
        return result

    def openai_to_anthropic(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            tool_calls = msg.get("tool_calls") or []
            tool_call_id = msg.get("tool_call_id")

            if role == "tool" and tool_call_id:
                result.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": str(tool_call_id),
                        "content": content if isinstance(content, str) else str(content or ""),
                    }],
                })
                continue

            blocks: list[dict[str, Any]] = []
            if isinstance(content, str):
                if content:
                    blocks.append({"type": "text", "text": content})
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, str):
                        blocks.append({"type": "text", "text": block})
                    elif isinstance(block, dict):
                        block_type = block.get("type")
                        if block_type == "text":
                            blocks.append({"type": "text", "text": block.get("text", "")})
                        elif block_type == "image_url":
                            image_url = block.get("image_url", {})
                            url = image_url.get("url", "") if isinstance(image_url, dict) else ""
                            if url.startswith("data:"):
                                try:
                                    media_part, b64 = url.split(",", 1)
                                    media_type = media_part.split(";")[0].replace("data:", "") or "image/png"
                                    blocks.append({
                                        "type": "image",
                                        "source": {
                                            "type": "base64",
                                            "media_type": media_type,
                                            "data": b64,
                                        },
                                    })
                                except ValueError:
                                    pass
                        elif block_type in {"tool_use", "tool_result"}:
                            blocks.append(block)
            elif content is not None:
                blocks.append({"type": "text", "text": str(content)})

            if role == "assistant" and tool_calls:
                for tc in tool_calls:
                    if not isinstance(tc, dict):
                        continue
                    func = tc.get("function") or {}
                    raw_args = func.get("arguments", tc.get("arguments", "{}"))
                    try:
                        parsed_input = json.loads(raw_args) if isinstance(raw_args, str) and raw_args else raw_args
                    except (TypeError, json.JSONDecodeError):
                        parsed_input = {}
                    if not isinstance(parsed_input, dict):
                        parsed_input = {}
                    blocks.append({
                        "type": "tool_use",
                        "id": str(tc.get("id", "")),
                        "name": func.get("name") or tc.get("name", ""),
                        "input": parsed_input,
                    })

            anthropic_role = role if role in {"user", "assistant"} else "user"
            if blocks:
                result.append({"role": anthropic_role, "content": blocks})
            else:
                result.append({"role": anthropic_role, "content": ""})
        return result

    def google_to_openai(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for msg in messages:
            role = msg.get("role", "")
            parts = msg.get("parts", [])
            if role == "user":
                text_parts: list[str] = []
                for part in parts:
                    if isinstance(part, dict) and "text" in part:
                        text_parts.append(part["text"])
                    elif isinstance(part, str):
                        text_parts.append(part)
                result.append({"role": "user", "content": "\n".join(text_parts)})
            elif role == "model":
                text_parts_g: list[str] = []
                for part in parts:
                    if isinstance(part, dict) and "text" in part:
                        text_parts_g.append(part["text"])
                    elif isinstance(part, str):
                        text_parts_g.append(part)
                result.append({"role": "assistant", "content": "\n".join(text_parts_g)})
            else:
                result.append(msg)
        return result

    def _adapt_anthropic_response(self, response: dict[str, Any]) -> GenerateResult:
        content = response.get("content", [])
        content_parts: list[Any] = []
        tool_calls: list[ToolCall] = []
        for block in content:
            if isinstance(block, dict):
                if block.get("type") == "text":
                    content_parts.append(TextPart(text=block.get("text", "")))
                elif block.get("type") == "thinking":
                    content_parts.append(ThinkPart(think=block.get("thinking", "")))
                elif block.get("type") == "tool_use":
                    raw_input = block.get("input", {})
                    arguments = json.dumps(raw_input) if isinstance(raw_input, dict) else str(raw_input)
                    tool_calls.append(
                        ToolCall(
                            id=block["id"],
                            function=ToolCall.FunctionBody(
                                name=block["name"],
                                arguments=arguments,
                            ),
                        )
                    )
        message = Message(
            role="assistant",
            content=content_parts if content_parts else [],
            tool_calls=tool_calls if tool_calls else None,
        )
        usage_data = response.get("usage", {})
        usage = self._parse_anthropic_token_usage(usage_data)
        stop_reason = response.get("stop_reason", "end_turn")
        return GenerateResult(
            message=message,
            usage=usage,
            stop_reason=stop_reason,
            raw_response=response,
        )

    def _adapt_google_response(self, response: dict[str, Any]) -> GenerateResult:
        candidates = response.get("candidates", [])
        candidate = candidates[0] if candidates else {}
        content = candidate.get("content", {})
        parts = content.get("parts", [])
        content_parts: list[Any] = []
        for part in parts:
            if isinstance(part, dict) and "text" in part:
                content_parts.append(TextPart(text=part["text"]))
        message = Message(
            role="assistant",
            content=content_parts if content_parts else [],
        )
        usage_metadata = response.get("usageMetadata", {})
        usage = self._parse_google_token_usage(usage_metadata)
        finish_reason = candidate.get("finishReason", "STOP")
        return GenerateResult(
            message=message,
            usage=usage,
            stop_reason=finish_reason,
            raw_response=response,
        )

    def adapt_request(
        self,
        provider: str,
        model: str,
        messages: list[Message],
        tools: list[Tool] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        from kosong.providers.runtime import _is_anthropic_provider

        payload: dict[str, Any] = {"model": model}
        is_anthropic = _is_anthropic_provider(provider, registry=self._registry)
        if is_anthropic:
            system_messages = [m for m in messages if m.role == "system"]
            non_system = [m for m in messages if m.role != "system"]
            if system_messages:
                system_texts: list[str] = []
                for m in system_messages:
                    system_texts.append(m.extract_text())
                payload["system"] = "\n".join(t for t in system_texts if t)
            openai_msgs = self.to_openai_messages(non_system)
            anthropic_msgs = self.openai_to_anthropic(openai_msgs)
            payload["messages"] = anthropic_msgs
        elif provider == "google":
            openai_msgs = self.to_openai_messages(messages)
            google_msgs = self.google_to_openai(openai_msgs)
            payload["messages"] = google_msgs
        else:
            payload["messages"] = self.to_openai_messages(messages)
        if tools:
            if is_anthropic:
                payload["tools"] = self._to_anthropic_tools(tools)
            else:
                payload["tools"] = self.to_openai_tools(tools)
        if "max_tokens" in kwargs:
            payload["max_tokens"] = kwargs["max_tokens"]
        elif is_anthropic:
            payload["max_tokens"] = 8192
        if "temperature" in kwargs:
            payload["temperature"] = kwargs["temperature"]
        if "stream" in kwargs:
            payload["stream"] = kwargs["stream"]
        for key, value in kwargs.items():
            if key not in ("max_tokens", "temperature", "stream", "base_url", "api_key", "extra_headers"):
                payload[key] = value
        return payload

    def _to_anthropic_tools(self, tools: list[Tool]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for tool in tools:
            schema = OpenAIShim._tool_parameters_schema(tool)
            result.append(
                {
                    "name": tool.name,
                    "description": tool.description or "",
                    "input_schema": schema,
                }
            )
        return result

    def adapt_response(self, provider: str, response_data: dict[str, Any]) -> GenerateResult:
        from kosong.providers.runtime import _is_anthropic_provider
        if _is_anthropic_provider(provider, registry=self._registry):
            return self._adapt_anthropic_response(response_data)
        if provider == "google":
            return self._adapt_google_response(response_data)
        return self.from_openai_response(response_data)
