"""winreverse.llm_runtime — LLM 适配层（OpenAI 协议统一）。

仅支持 OpenAI 协议（/v1/chat/completions）：国内 AI 模型（Kimi/DeepSeek/
Qwen/GLM/豆包等）与各类网关、本地推理（vLLM/Ollama openai 模式）均兼容
该协议，基于官方 openai Python SDK 实现。

Soul 引擎 Runtime.call_llm(agent_id, messages, model, agent_config) 调用：
    self._llm.generate(messages=messages, model=model, tools=tools)

LLMAdapter 职责：
1. kosong Message/Tool 类型 → OpenAI 请求格式（含工具调用双向转换）
2. OpenAI 响应 → GenerateResult（usage 累计供 TUI 状态栏显示）
3. base_url 可配置：指向任意 OpenAI 协议兼容端点

用法：
    config = LLMConfig(model="kimi-k2", base_url="https://api.moonshot.cn/v1", api_key="...")
    llm = LLMAdapter(config)
    soul = WinReverseSoul(llm=llm, registry=registry)
"""

from __future__ import annotations

import logging
from typing import Any

from openai import AsyncOpenAI

from kosong.types import (
    GenerateResult,
    Message,
    MessageRole,
    TextPart,
    TokenUsage,
    Tool,
)
from winreverse.config import LLMConfig

logger = logging.getLogger(__name__)

_MAX_ERROR_TEXT = 500


class LLMError(RuntimeError):
    """LLM 调用失败的统一异常。"""


class LLMAdapter:
    """OpenAI 协议 LLM 适配器（AsyncOpenAI 实现）。

    对 Soul 引擎暴露统一接口：
        await llm.generate(messages=..., model=..., tools=...) -> GenerateResult
    """

    def __init__(self, config: LLMConfig) -> None:
        """初始化适配器。

        Args:
            config: LLM 配置（model/api_key/base_url 等；base_url 指向任意
                OpenAI 协议兼容端点，留空用 OpenAI 官方端点）
        """
        self._config = config
        api_key = config.resolve_api_key()
        base_url = config.base_url.strip() or None

        self._client = AsyncOpenAI(
            api_key=api_key or "EMPTY",  # 兼容本地推理（不校验 key）场景
            base_url=base_url,
            timeout=300.0,
        )

        logger.info(
            "LLMAdapter 初始化: model=%s, base_url=%s, has_api_key=%s",
            config.model,
            base_url or "(官方默认)",
            bool(api_key),
        )

    @property
    def config(self) -> LLMConfig:
        """关联的 LLM 配置。"""
        return self._config

    @property
    def provider(self) -> str:
        """协议名（固定 openai）。"""
        return "openai"

    # ------------------------- 格式转换 -------------------------

    @staticmethod
    def _parts_to_text(content: Any) -> str:
        """kosong content parts → 纯文本（思考/媒体部分跳过）。"""
        if not content:
            return ""
        parts: list[str] = []
        for part in content:
            text = getattr(part, "text", None)
            if text:
                parts.append(str(text))
        return "".join(parts)

    def _to_openai_messages(self, messages: list[Message]) -> list[dict[str, Any]]:
        """kosong 消息序列 → OpenAI chat 格式。"""
        result: list[dict[str, Any]] = []
        for msg in messages:
            role = msg.role.value if hasattr(msg.role, "value") else str(msg.role)
            text = self._parts_to_text(msg.content)
            entry: dict[str, Any] = {"role": role, "content": text}

            if role == "assistant" and msg.tool_calls:
                entry["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name if tc.function else "",
                            "arguments": tc.function.arguments or "{}" if tc.function else "{}",
                        },
                    }
                    for tc in msg.tool_calls
                ]

            if role == "tool":
                entry["tool_call_id"] = msg.tool_call_id or ""
                # OpenAI 协议中 tool 消息 content 不能为空
                if not text:
                    entry["content"] = "(empty tool result)"

            result.append(entry)
        return result

    @staticmethod
    def _tool_to_openai(tool: Tool) -> dict[str, Any]:
        """kosong Tool → OpenAI function 定义。"""
        if tool.parameters_schema:
            schema = tool.parameters_schema
        else:
            properties: dict[str, Any] = {}
            required: list[str] = []
            for param in tool.parameters:
                prop: dict[str, Any] = {"type": param.type}
                if param.description:
                    prop["description"] = param.description
                if param.enum:
                    prop["enum"] = param.enum
                properties[param.name] = prop
                if param.required:
                    required.append(param.name)
            schema = {"type": "object", "properties": properties, "required": required}

        return {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": schema,
            },
        }

    def _result_to_message(self, choice: Any) -> Message:
        """OpenAI choice → kosong Message（含工具调用还原）。"""
        message = choice.message
        tool_calls = None
        if getattr(message, "tool_calls", None):
            from kosong.types import ToolCall

            tool_calls = [
                ToolCall(
                    id=tc.id,
                    type="function",
                    function=ToolCall.FunctionBody(
                        name=tc.function.name,
                        arguments=tc.function.arguments,
                    ),
                )
                for tc in message.tool_calls
            ]
        return Message(
            role=MessageRole.ASSISTANT,
            content=[TextPart(type="text", text=message.content or "")],
            tool_calls=tool_calls,
        )

    @staticmethod
    def _map_stop_reason(finish_reason: str | None) -> str:
        """OpenAI finish_reason → Soul 循环 stop_reason。"""
        if finish_reason == "tool_calls":
            return "tool_use"
        if finish_reason == "length":
            return "max_tokens"
        return "stop"

    # ------------------------- 主入口 -------------------------

    async def generate(
        self,
        messages: list[Message],
        model: str | None = None,
        tools: list[Tool] | None = None,
        **kwargs: Any,
    ) -> GenerateResult:
        """调用 LLM（OpenAI /v1/chat/completions）。

        Args:
            messages: kosong 消息序列
            model: 模型 ID（None 时用 config 默认）
            tools: 可用工具列表（自动转 OpenAI function 格式）
            **kwargs: max_tokens / temperature 覆盖

        Returns:
            GenerateResult（assistant 消息 / usage / stop_reason）

        Raises:
            LLMError: 调用失败（网络 / 认证 / 端点错误）
        """
        actual_model = model or self._config.model
        if not actual_model:
            raise LLMError("未配置模型名。请在 winreverse gui 中填写模型 ID")

        max_tokens = kwargs.get("max_tokens", self._config.max_tokens)
        temperature = kwargs.get("temperature", self._config.temperature)

        request_kwargs: dict[str, Any] = {
            "model": actual_model,
            "messages": self._to_openai_messages(messages),
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if tools:
            request_kwargs["tools"] = [self._tool_to_openai(t) for t in tools]

        try:
            response = await self._client.chat.completions.create(**request_kwargs)
        except Exception as e:
            text = str(e)
            if "401" in text or "Unauthorized" in text:
                raise LLMError("LLM 认证失败（401）：请检查 api_key 与 base_url 是否匹配") from e
            if "404" in text:
                raise LLMError(
                    f"端点或模型不存在（404）：检查 base_url 与模型名（{actual_model}）"
                ) from e
            if "connect" in text.lower() or "connection" in text.lower() or "timed out" in text.lower():
                base_note = self._config.base_url.strip() or "OpenAI 官方端点（国内直连通常不可达）"
                raise LLMError(
                    "无法连接 LLM 端点: "
                    + base_note
                    + "\n排查：检查 base_url 是否正确（国内模型请填兼容端点，"
                    "如 https://api.moonshot.cn/v1）；确认网络可达与代理设置。"
                ) from e
            raise LLMError(f"LLM 调用失败: {text[:_MAX_ERROR_TEXT]}") from e

        choice = response.choices[0] if response.choices else None
        if choice is None:
            raise LLMError("LLM 返回了空 choices")

        usage = None
        if getattr(response, "usage", None):
            usage = TokenUsage(
                input_other=int(response.usage.prompt_tokens or 0),
                output=int(response.usage.completion_tokens or 0),
            )

        return GenerateResult(
            id=response.id or "",
            message=self._result_to_message(choice),
            usage=usage,
            stop_reason=self._map_stop_reason(choice.finish_reason),
        )

    async def close(self) -> None:
        """清理 HTTP 连接。"""
        await self._client.close()
