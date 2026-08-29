"""OpenAI SDK 公共工具（对齐 kimi-cli / kxns-cli）。"""

from __future__ import annotations

from typing import Any, Literal

import httpx
from openai import AsyncOpenAI, OpenAIError
from openai.types import ReasoningEffort

ThinkingEffort = Literal["off", "low", "medium", "high"]


def create_openai_client(
    *,
    api_key: str,
    base_url: str,
    default_headers: dict[str, str] | None = None,
) -> AsyncOpenAI:
    kwargs: dict[str, Any] = {"api_key": api_key, "base_url": base_url}
    if default_headers:
        kwargs["default_headers"] = default_headers
    return AsyncOpenAI(**kwargs)


def thinking_effort_to_reasoning_effort(effort: ThinkingEffort) -> ReasoningEffort:
    match effort:
        case "off":
            return "none"
        case "low":
            return "low"
        case "medium":
            return "medium"
        case "high":
            return "high"


def extract_reasoning_from_delta(delta: Any, reasoning_key: str | None) -> str:
    """从 SDK delta 对象提取 reasoning 增量（兼容 model_extra / model_dump）。"""
    if not reasoning_key:
        return ""
    val = getattr(delta, reasoning_key, None)
    if isinstance(val, str) and val:
        return val
    dump = getattr(delta, "model_dump", None)
    if callable(dump):
        data = dump(exclude_none=True)
        if isinstance(data, dict):
            found = data.get(reasoning_key)
            if isinstance(found, str) and found:
                return found
    extra = getattr(delta, "model_extra", None)
    if isinstance(extra, dict):
        found = extra.get(reasoning_key)
        if isinstance(found, str) and found:
            return found
    return ""


def convert_openai_error(error: BaseException) -> Exception:
    if isinstance(error, OpenAIError):
        return error
    if isinstance(error, httpx.HTTPError):
        return error
    return error
