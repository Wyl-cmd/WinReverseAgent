"""OpenAI / Anthropic 兼容协议：reasoning / thinking 字段提取与流式归一化。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


KNOWN_REASONING_STREAM_KEYS: tuple[str, ...] = (
    "reasoning_content",
    "reasoning",
    "thinking",
    "reasoning_text",
    "thought",
    "analysis",
)

_DELTA_NON_REASONING_KEYS = frozenset({
    "content",
    "role",
    "tool_calls",
    "function_call",
    "refusal",
    "audio",
    "name",
})


@dataclass
class ReasoningKeyDetect:
    """流式响应中自动识别到的 reasoning 字段名（首个非空 delta 锁定）。"""

    configured_key: str | None = None
    detected_key: str | None = None

    @property
    def active_key(self) -> str | None:
        return self.configured_key or self.detected_key


def _coerce_reasoning_text(value: Any) -> str:
    """将 Provider 返回的 reasoning 值转为可展示字符串。"""
    if isinstance(value, str) and value:
        return value
    if isinstance(value, dict):
        for key in ("text", "content", "thinking", "reasoning", "reasoning_content"):
            nested = value.get(key)
            if isinstance(nested, str) and nested:
                return nested
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, str) and item:
                parts.append(item)
            elif isinstance(item, dict):
                if item.get("type") in {"thinking", "reasoning", "reasoning_content"}:
                    text = _coerce_reasoning_text(item)
                    if text:
                        parts.append(text)
                elif item.get("type") == "text":
                    text = item.get("text", "")
                    if isinstance(text, str) and text:
                        parts.append(text)
        if parts:
            return "".join(parts)
    return ""


def _extract_from_containers(
    containers: tuple[dict[str, Any], ...],
    detect: ReasoningKeyDetect,
) -> str:
    if detect.configured_key:
        for container in containers:
            val = container.get(detect.configured_key)
            text = _coerce_reasoning_text(val)
            if text:
                detect.detected_key = detect.detected_key or detect.configured_key
                return text

    if detect.active_key:
        for container in containers:
            val = container.get(detect.active_key)
            text = _coerce_reasoning_text(val)
            if text:
                return text

    for container in containers:
        for key in KNOWN_REASONING_STREAM_KEYS:
            if key in _DELTA_NON_REASONING_KEYS:
                continue
            text = _coerce_reasoning_text(container.get(key))
            if text:
                detect.detected_key = key
                return text
    return ""


def extract_reasoning_from_openai_message(
    message: dict[str, Any],
    reasoning_key: str | None = None,
) -> str:
    """从非流式 OpenAI message 对象提取 reasoning 正文。"""
    detect = ReasoningKeyDetect(configured_key=reasoning_key)
    return _extract_from_containers((message,), detect)


def extract_reasoning_from_openai_stream(
    *,
    choice: dict[str, Any],
    delta: dict[str, Any] | None = None,
    message: dict[str, Any] | None = None,
    detect: ReasoningKeyDetect | None = None,
) -> str:
    """从 OpenAI Chat Completions 流式 chunk 提取 reasoning 增量/累积文本。"""
    detect = detect or ReasoningKeyDetect()
    delta_dict = dict(delta or {})
    message_dict = dict(message or {})
    reasoning = _extract_from_containers((delta_dict, message_dict), detect)
    if reasoning:
        return reasoning
    for key in KNOWN_REASONING_STREAM_KEYS:
        text = _coerce_reasoning_text(choice.get(key))
        if text:
            detect.detected_key = key
            return text
    return ""


def normalize_openai_stream_chunk(
    chunk: dict[str, Any],
    detect: ReasoningKeyDetect,
) -> dict[str, Any]:
    """将 Provider 自定义 reasoning 字段归一化到 delta.reasoning_content。"""
    choices = chunk.get("choices")
    if not isinstance(choices, list) or not choices:
        return chunk

    choice = choices[0]
    if not isinstance(choice, dict):
        return chunk

    delta = dict(choice.get("delta") or {})
    message_obj = choice.get("message")
    message = message_obj if isinstance(message_obj, dict) else {}

    reasoning = extract_reasoning_from_openai_stream(
        choice=choice,
        delta=delta,
        message=message,
        detect=detect,
    )
    if reasoning and not delta.get("reasoning_content"):
        delta["reasoning_content"] = reasoning

    if delta is not choice.get("delta"):
        new_choice = {**choice, "delta": delta}
        new_choices = [new_choice, *choices[1:]]
        return {**chunk, "choices": new_choices}
    return chunk
