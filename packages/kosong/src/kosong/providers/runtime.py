from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator
from typing import Any

import httpx

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
from kosong.providers.registry import ProviderRegistry
from kosong.providers.shim import OpenAIShim
from kosong.providers.reasoning import (
    ReasoningKeyDetect,
    extract_reasoning_from_openai_stream,
)


ANTHROPIC_PROVIDERS = {"anthropic"}
ANTHROPIC_ENDPOINT = "messages"
DEFAULT_ENDPOINT = "chat/completions"


class AnthropicStreamedMessage:
    def __init__(self, response_cm: Any, provider: str, shim: OpenAIShim) -> None:
        self._response_cm = response_cm
        self._provider = provider
        self._shim = shim
        self._id: str | None = None
        self._usage: Usage | None = None
        self._tool_call_states: dict[int, ToolCall] = {}
        self._current_tool_index = 0

    @property
    def id(self) -> str | None:
        return self._id

    @property
    def usage(self) -> Usage | None:
        return self._usage

    async def __aiter__(self) -> AsyncIterator[StreamedMessagePart]:
        async with self._response_cm as response:
            if response.status_code >= 400:
                try:
                    body = await response.aread()
                    error_text = body.decode("utf-8", errors="replace")[:1000]
                except Exception:
                    error_text = ""
                raise httpx.HTTPStatusError(
                    f"Anthropic stream HTTP {response.status_code}: {error_text}",
                    request=response.request,
                    response=response,
                )
            async for line in response.aiter_lines():
                if not line.startswith("data: "):
                    continue
                data = line[6:]
                try:
                    chunk = json.loads(data)
                except json.JSONDecodeError:
                    continue

                event_type = chunk.get("type", "")

                if event_type == "message_start":
                    msg = chunk.get("message", {})
                    self._id = msg.get("id", self._id)
                    usage_data = msg.get("usage", {})
                    if usage_data:
                        self._usage = self._shim._parse_anthropic_token_usage(usage_data)

                elif event_type == "content_block_start":
                    block = chunk.get("content_block", {})
                    block_type = block.get("type", "")
                    block_index = chunk.get("index", 0)
                    if block_type == "tool_use":
                        tc_id = block.get("id", "")
                        name = block.get("name", "")
                        tool_call = ToolCall(
                            id=tc_id,
                            function=ToolCall.FunctionBody(
                                name=name,
                                arguments="",
                            ),
                        )
                        self._tool_call_states[block_index] = tool_call
                        yield tool_call
                    elif block_type == "thinking":
                        pass

                elif event_type == "content_block_delta":
                    delta = chunk.get("delta", {})
                    delta_type = delta.get("type", "")
                    if delta_type == "text_delta":
                        text = delta.get("text", "")
                        if text:
                            yield TextPart(text=text)
                    elif delta_type == "thinking_delta":
                        think = delta.get("thinking", "")
                        if think:
                            yield ThinkPart(think=think)
                    elif delta_type == "input_json_delta":
                        block_index = chunk.get("index", 0)
                        partial_json = delta.get("partial_json", "")
                        if partial_json and block_index in self._tool_call_states:
                            yield ToolCallPart(arguments_part=partial_json)

                elif event_type == "message_delta":
                    delta = chunk.get("delta", {})
                    usage_data = chunk.get("usage", {})
                    if usage_data:
                        if self._usage:
                            updated = self._shim._parse_anthropic_token_usage(usage_data)
                            if updated:
                                self._usage = Usage(
                                    input_tokens=self._usage.input_tokens + updated.input_tokens,
                                    output_tokens=self._usage.output_tokens + updated.output_tokens,
                                    cache_read_tokens=self._usage.cache_read_tokens + updated.cache_read_tokens,
                                    cache_creation_tokens=self._usage.cache_creation_tokens + updated.cache_creation_tokens,
                                )
                        else:
                            self._usage = self._shim._parse_anthropic_token_usage(usage_data)


class StreamedMessage:
    def __init__(self, response_cm: Any, provider: str, shim: OpenAIShim) -> None:
        self._response_cm = response_cm
        self._provider = provider
        self._shim = shim
        self._id: str | None = None
        self._usage: Usage | None = None
        self._tool_call_states: dict[int, ToolCall] = {}
        self._reasoning_detect = ReasoningKeyDetect()
        self._accumulated_reasoning = ""

    @property
    def id(self) -> str | None:
        return self._id

    @property
    def usage(self) -> Usage | None:
        return self._usage

    async def __aiter__(self) -> AsyncIterator[StreamedMessagePart]:
        async with self._response_cm as response:
            async for line in response.aiter_lines():
                if not line.startswith("data: "):
                    continue
                data = line[6:]
                if data.strip() == "[DONE]":
                    break
                try:
                    chunk = json.loads(data)
                except json.JSONDecodeError:
                    continue

                self._id = chunk.get("id", self._id)

                usage_data = chunk.get("usage")
                if usage_data:
                    self._usage = self._shim._parse_provider_token_usage(
                        self._provider, usage_data
                    )

                choices = chunk.get("choices", [])
                if not choices:
                    continue

                choice = choices[0]
                delta = choice.get("delta", {})
                message_obj = choice.get("message")
                message = message_obj if isinstance(message_obj, dict) else {}

                reasoning = extract_reasoning_from_openai_stream(
                    choice=choice,
                    delta=delta,
                    message=message,
                    detect=self._reasoning_detect,
                )
                if reasoning:
                    if self._accumulated_reasoning and reasoning.startswith(self._accumulated_reasoning):
                        reasoning = reasoning[len(self._accumulated_reasoning):]
                    if reasoning:
                        self._accumulated_reasoning += reasoning
                        yield ThinkPart(think=reasoning)

                content = delta.get("content")
                if content:
                    yield TextPart(text=content)

                tool_calls_delta = delta.get("tool_calls")
                if tool_calls_delta:
                    for tc_delta in tool_calls_delta:
                        index = tc_delta.get("index", 0)
                        if index not in self._tool_call_states:
                            tc_id = tc_delta.get("id", "")

                            func = tc_delta.get("function", {})
                            if func:
                                name = func.get("name", "")
                                arguments_part = func.get("arguments", "")
                            else:
                                name = tc_delta.get("name", "")
                                raw_args = tc_delta.get("arguments", "")
                                if isinstance(raw_args, dict):
                                    arguments_part = json.dumps(raw_args)
                                else:
                                    arguments_part = raw_args or ""

                            tool_call = ToolCall(
                                id=tc_id,
                                function=ToolCall.FunctionBody(
                                    name=name,
                                    arguments=arguments_part or None,
                                ),
                            )
                            self._tool_call_states[index] = tool_call
                            yield tool_call
                        else:
                            func = tc_delta.get("function", {})
                            if func:
                                arguments_part = func.get("arguments")
                            else:
                                raw_args = tc_delta.get("arguments", "")
                                if isinstance(raw_args, dict):
                                    arguments_part = json.dumps(raw_args)
                                else:
                                    arguments_part = raw_args
                            if arguments_part:
                                yield ToolCallPart(arguments_part=arguments_part)


def _is_anthropic_provider(provider: str, registry: ProviderRegistry | None = None) -> bool:
    if provider in ANTHROPIC_PROVIDERS or "anthropic" in provider.lower():
        return True
    if registry is not None:
        try:
            desc = registry.get(provider)
            headers = getattr(desc, "default_headers", None) or {}
            if "anthropic-version" in headers:
                return True
        except Exception:
            pass
    return False


def _get_endpoint(provider: str, registry: ProviderRegistry | None = None) -> str:
    if _is_anthropic_provider(provider, registry=registry):
        return ANTHROPIC_ENDPOINT
    return DEFAULT_ENDPOINT


class ProviderRuntime:
    def __init__(
        self,
        registry: ProviderRegistry,
        api_keys: dict[str, str] | None = None,
    ) -> None:
        self._registry = registry
        self._api_keys = api_keys or {}
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._shim = OpenAIShim(registry=registry)

    def _resolve_api_key(self, provider: str) -> str | None:
        if provider in self._api_keys:
            return self._api_keys[provider]
        try:
            descriptor = self._registry.get(provider)
            return os.environ.get(descriptor.api_key_env)
        except KeyError:
            return None

    def get_client(self, provider: str) -> httpx.AsyncClient:
        if provider in self._clients:
            return self._clients[provider]
        descriptor = self._registry.get(provider)
        api_key = self._resolve_api_key(provider)
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            api_key = api_key.strip()
            if _is_anthropic_provider(provider, registry=self._registry):
                headers["x-api-key"] = api_key
            else:
                headers["Authorization"] = f"Bearer {api_key}"
        if descriptor.default_headers:
            headers.update(descriptor.default_headers)
        import logging
        logging.getLogger("kosong").info(
            f"[Runtime] get_client provider={provider}, api_base={descriptor.api_base}, has_api_key={bool(api_key)}, is_anthropic={_is_anthropic_provider(provider)}"
        )
        base_url = (descriptor.api_base or "").rstrip("/") + "/"
        client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=httpx.Timeout(300.0, connect=30.0),
        )
        self._clients[provider] = client
        return client

    def build_request(
        self,
        provider: str,
        model: str,
        messages: list[Message],
        tools: list[Tool] | None = None,
        **kwargs: Any,
    ) -> httpx.Request:
        client = self.get_client(provider)
        payload = self._shim.adapt_request(
            provider=provider,
            model=model,
            messages=messages,
            tools=tools,
            **kwargs,
        )
        endpoint = _get_endpoint(provider, registry=self._registry)
        return client.build_request("POST", endpoint, json=payload)

    async def execute_request(self, request: httpx.Request, provider: str | None = None) -> httpx.Response:
        if not self._clients:
            raise RuntimeError("No provider client available. Call get_client() first.")
        client = None
        if provider and provider in self._clients:
            client = self._clients[provider]
        if client is None:
            for provider_name, c in self._clients.items():
                if provider_name in str(request.url):
                    client = c
                    break
        if client is None:
            client = list(self._clients.values())[0]
        response = await client.send(request)
        response.raise_for_status()
        return response

    def parse_response(self, provider: str, response: httpx.Response) -> GenerateResult:
        data = response.json()
        return self._shim.adapt_response(provider, data)

    def stream_generate(
        self,
        provider: str,
        model: str,
        messages: list[Message],
        tools: list[Tool] | None = None,
        **kwargs: Any,
    ) -> StreamedMessage | AnthropicStreamedMessage:
        kwargs["stream"] = True
        request = self.build_request(provider, model, messages, tools, **kwargs)
        client = self.get_client(provider)
        endpoint = _get_endpoint(provider, registry=self._registry)
        response_cm = client.stream(
            "POST",
            endpoint,
            content=request.content,
            headers=dict(request.headers),
        )
        if _is_anthropic_provider(provider, registry=self._registry):
            return AnthropicStreamedMessage(response_cm, provider, self._shim)
        return StreamedMessage(response_cm, provider, self._shim)

    async def close(self) -> None:
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()
