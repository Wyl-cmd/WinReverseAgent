"""winreverse.soul.toolset — Soul 工具集适配器。

桥接 WinReverseAgent 现有 ToolRegistry（47 个 ToolInterface 工具）
到 kosong LLM 抽象层期望的 Tool 列表格式。

设计原则（抄写优先）：
- 不重写 ToolInterface/ToolRegistry，直接复用现有实现
- 仅做格式转换：ToolInterface → kosong.Tool
- 工具调用结果（dict）序列化为 JSON 字符串供 LLM 消费

核心类：
- SoulToolsetAdapter: 适配器主类
- ToolCallResult: 工具调用结果数据类

参考：实施方案 §8.2.5
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from kosong.types import Tool, ToolParameter
from winreverse.engine.bus import ToolInterface, ToolNotFoundError, ToolRegistry

# 事件回调类型：接收一个事件字典，无返回值
ToolEventCallback = Callable[[dict[str, Any]], None]


@dataclass(slots=True)
class ToolCallResult:
    """工具调用结果。

    Attributes:
        name: 工具名
        output: 输出内容（字符串形式，供 LLM 消费）
        is_error: 是否为错误结果
    """

    name: str
    output: str
    is_error: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


class SoulToolsetAdapter:
    """Soul 工具集适配器。

    将 WinReverseAgent 的 ToolRegistry 包装为 kosong 期望的工具集接口，
    提供 to_kosong_tools()（导出工具列表给 LLM）和 execute()（执行工具调用）。

    用法：
        registry = ToolRegistry()
        register_all_tools(registry)
        adapter = SoulToolsetAdapter(registry)
        kosong_tools = adapter.to_kosong_tools()
        result = await adapter.execute("pe.parse", {"file_path": "test.exe"})
    """

    def __init__(
        self,
        registry: ToolRegistry,
        *,
        allowed_tools: list[str] | None = None,
        max_output_chars: int = 80_000,
        on_tool_event: ToolEventCallback | None = None,
    ) -> None:
        """初始化适配器。

        Args:
            registry: WinReverseAgent 工具注册中心
            allowed_tools: 仅暴露指定工具名列表（白名单过滤）；None 表示暴露全部
            max_output_chars: 单次工具输出最大字符数，超出截断
            on_tool_event: 工具调用事件回调（用于 TUI 实时更新），
                事件类型：tool_call（调用开始）/ tool_result（调用结束）
        """
        self._registry = registry
        self._allowed_tools: set[str] | None = (
            set(allowed_tools) if allowed_tools is not None else None
        )
        self._max_output_chars = max_output_chars
        self._on_tool_event = on_tool_event

    def list_tools(self) -> list[ToolInterface]:
        """列出所有已注册且未被白名单过滤的工具实例。"""
        all_tools = [
            t
            for t in self._registry._tools.values()
            if self._allowed_tools is None or t.name in self._allowed_tools
        ]
        return all_tools

    def to_kosong_tools(self) -> list[Tool]:
        """转换为 kosong Tool 列表，供 LLM generate() 调用。

        注意：当前 ToolInterface 未定义参数 schema，这里使用空参数列表。
        未来可在 ToolInterface 中扩展 parameters 字段。
        """
        kosong_tools: list[Tool] = []
        for tool in self.list_tools():
            kosong_tools.append(
                Tool(
                    name=tool.name,
                    description=tool.description,
                    parameters=self._infer_parameters(tool),
                )
            )
        return kosong_tools

    def _infer_parameters(self, tool: ToolInterface) -> list[ToolParameter]:
        """推断工具参数列表。

        当前实现返回空列表（ToolInterface 未定义参数 schema）。
        未来若 ToolInterface 扩展 parameters 字段，可在此处转换。

        Args:
            tool: 工具实例

        Returns:
            kosong ToolParameter 列表
        """
        # 预留：未来 ToolInterface 扩展后从 tool.parameters 转换
        _ = tool
        return []

    def _emit_event(self, event: dict[str, Any]) -> None:
        """安全触发事件回调（异常不中断主流程）。"""
        if self._on_tool_event is None:
            return
        with contextlib.suppress(Exception):
            self._on_tool_event(event)

    async def execute(self, name: str, arguments: dict[str, Any]) -> ToolCallResult:
        """执行工具调用（异步包装同步 ToolInterface.execute）。

        Args:
            name: 工具名
            arguments: 输入参数

        Returns:
            ToolCallResult，output 字段为 JSON 字符串
        """
        # 通知：工具调用开始
        self._emit_event({"type": "tool_call", "name": name, "args": arguments})

        try:
            # 白名单校验
            if self._allowed_tools is not None and name not in self._allowed_tools:
                result = ToolCallResult(
                    name=name,
                    output=f"Tool '{name}' is not in allowed_tools list",
                    is_error=True,
                )
                self._emit_event(
                    {"type": "tool_result", "name": name, "is_error": True, "output": result.output}
                )
                return result

            # 同步调用包装为异步（避免阻塞事件循环）
            raw_result = await asyncio.to_thread(self._registry.call, name, arguments)

            # 序列化为 JSON 字符串供 LLM 消费
            output = self._serialize_result(raw_result)

            # 截断超长输出
            if len(output) > self._max_output_chars:
                truncated = output[: self._max_output_chars]
                output = (
                    truncated + f"\n\n...[Output truncated: {len(output)} total characters, "
                    f"showing first {self._max_output_chars}]"
                )

            is_error = raw_result.get("status") == "error"
            result = ToolCallResult(
                name=name,
                output=output,
                is_error=is_error,
                raw=raw_result,
            )
            # 通知：工具调用结束
            self._emit_event(
                {"type": "tool_result", "name": name, "is_error": is_error, "output": output[:500]}
            )
            return result

        except ToolNotFoundError:
            result = ToolCallResult(
                name=name,
                output=f"Tool '{name}' not found in registry",
                is_error=True,
            )
            self._emit_event(
                {"type": "tool_result", "name": name, "is_error": True, "output": result.output}
            )
            return result
        except Exception as e:
            result = ToolCallResult(
                name=name,
                output=f"Tool '{name}' execution failed: {type(e).__name__}: {e}",
                is_error=True,
            )
            self._emit_event(
                {"type": "tool_result", "name": name, "is_error": True, "output": result.output}
            )
            return result

    @staticmethod
    def _serialize_result(result: dict[str, Any]) -> str:
        """将工具结果字典序列化为字符串。

        优先使用 JSON（保证机器可读），失败时退化为 str()。

        Args:
            result: 工具返回的字典

        Returns:
            JSON 字符串
        """
        try:
            return json.dumps(result, ensure_ascii=False, default=str, indent=2)
        except (TypeError, ValueError):
            return str(result)

    def get_tool(self, name: str) -> ToolInterface | None:
        """按名称获取工具实例（不抛异常，未找到返回 None）。"""
        try:
            return self._registry.get(name)
        except ToolNotFoundError:
            return None

    def __len__(self) -> int:
        """返回可暴露的工具数量。"""
        return len(self.list_tools())

    def __contains__(self, name: object) -> bool:
        """检查工具是否在适配器中（考虑白名单过滤）。"""
        if not isinstance(name, str):
            return False
        if self._allowed_tools is not None and name not in self._allowed_tools:
            return False
        return name in self._registry
