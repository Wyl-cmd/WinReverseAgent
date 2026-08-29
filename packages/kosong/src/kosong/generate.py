from __future__ import annotations

import inspect
from typing import Any, Callable

from kosong.types import (
    ContentPart,
    GenerateResult,
    Message,
    StreamedMessagePart,
    TextPart,
    ThinkPart,
    Tool,
    ToolCall,
)
from kosong.providers.runtime import ProviderRuntime
from kosong.providers.shim import OpenAIShim


async def generate(
    provider: str,
    model: str,
    messages: list[Message],
    tools: list[Tool] | None = None,
    *,
    runtime: ProviderRuntime,
    shim: OpenAIShim,
    max_tokens: int | None = None,
    temperature: float | None = None,
    stream: bool = False,
    on_message_part: Callable[[StreamedMessagePart], Any] | None = None,
    on_tool_call: Callable[[ToolCall], Any] | None = None,
) -> GenerateResult:
    kwargs: dict[str, Any] = {}
    if max_tokens is not None:
        kwargs["max_tokens"] = max_tokens
    if temperature is not None:
        kwargs["temperature"] = temperature

    if stream:
        return await _generate_streaming(
            provider=provider,
            model=model,
            messages=messages,
            tools=tools,
            runtime=runtime,
            on_message_part=on_message_part,
            on_tool_call=on_tool_call,
            **kwargs,
        )

    request = runtime.build_request(
        provider=provider,
        model=model,
        messages=messages,
        tools=tools,
        **kwargs,
    )
    response = await runtime.execute_request(request, provider=provider)
    return runtime.parse_response(provider, response)


async def _invoke_callback(fn: Callable[..., Any], *args: Any) -> None:
    result = fn(*args)
    if inspect.isawaitable(result):
        await result


async def _generate_streaming(
    provider: str,
    model: str,
    messages: list[Message],
    tools: list[Tool] | None,
    *,
    runtime: ProviderRuntime,
    on_message_part: Callable[[StreamedMessagePart], Any] | None = None,
    on_tool_call: Callable[[ToolCall], Any] | None = None,
    **kwargs: Any,
) -> GenerateResult:
    message = Message(role="assistant", content=[])
    pending_part: StreamedMessagePart | None = None

    streamed = runtime.stream_generate(
        provider=provider,
        model=model,
        messages=messages,
        tools=tools,
        **kwargs,
    )

    async for part in streamed:
        if on_message_part is not None:
            await _invoke_callback(on_message_part, part.model_copy(deep=True))

        if pending_part is None:
            pending_part = part
        elif not pending_part.merge_in_place(part):
            _message_append(message, pending_part)
            if isinstance(pending_part, ToolCall) and on_tool_call is not None:
                await _invoke_callback(on_tool_call, pending_part)
            pending_part = part

    if pending_part is not None:
        _message_append(message, pending_part)
        if isinstance(pending_part, ToolCall) and on_tool_call is not None:
            await _invoke_callback(on_tool_call, pending_part)

    if not message.content and not message.tool_calls:
        raise ValueError("The API returned an empty response.")

    has_think = any(isinstance(p, ThinkPart) for p in message.content)
    has_text = any(isinstance(p, TextPart) and p.text.strip() for p in message.content)
    if has_think and not has_text and not message.tool_calls:
        raise ValueError(
            "The API returned a response containing only thinking content "
            "without any text or tool calls."
        )

    return GenerateResult(
        id=streamed.id,
        message=message,
        usage=streamed.usage,
    )


def _message_append(message: Message, part: StreamedMessagePart) -> None:
    match part:
        case ContentPart():
            message.content.append(part)
        case ToolCall():
            if message.tool_calls is None:
                message.tool_calls = []
            message.tool_calls.append(part)
        case _:
            return
