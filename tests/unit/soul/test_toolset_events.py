"""测试模块：winreverse.soul.toolset 事件回调功能

覆盖：
- SoulToolsetAdapter 的 on_tool_event 回调
- 工具调用开始/结束事件的触发
- 回调异常不影响工具执行
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from winreverse.engine.bus import ToolInterface, ToolRegistry
from winreverse.soul.toolset import SoulToolsetAdapter


class _FakeTool(ToolInterface):
    """测试用的假工具。"""

    @property
    def name(self) -> str:
        return "fake.tool"

    @property
    def description(self) -> str:
        return "测试工具"

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        """返回固定成功结果。"""
        if params.get("fail"):
            return {"status": "error", "error_message": "模拟失败"}
        return {"status": "success", "result": "ok"}


class _ErrorTool(ToolInterface):
    """测试用的抛异常工具。"""

    @property
    def name(self) -> str:
        return "error.tool"

    @property
    def description(self) -> str:
        return "会抛异常的工具"

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("工具执行异常")


@pytest.fixture
def registry_with_tools() -> ToolRegistry:
    """带测试工具的注册中心。"""
    registry = ToolRegistry()
    registry.register(_FakeTool())
    registry.register(_ErrorTool())
    return registry


class TestToolsetEventCallback:
    """SoulToolsetAdapter 事件回调测试。"""

    @pytest.mark.asyncio
    async def test_callback_fired_on_tool_call(self, registry_with_tools: ToolRegistry) -> None:
        """工具调用时应触发 tool_call 和 tool_result 事件。"""
        events: list[dict[str, Any]] = []
        adapter = SoulToolsetAdapter(
            registry_with_tools,
            on_tool_event=lambda e: events.append(e),
        )

        await adapter.execute("fake.tool", {})

        # 应有 2 个事件：tool_call + tool_result
        assert len(events) == 2
        assert events[0]["type"] == "tool_call"
        assert events[0]["name"] == "fake.tool"
        assert events[1]["type"] == "tool_result"
        assert events[1]["name"] == "fake.tool"
        assert events[1]["is_error"] is False

    @pytest.mark.asyncio
    async def test_callback_on_error_result(self, registry_with_tools: ToolRegistry) -> None:
        """工具返回 error 状态时回调应标记 is_error。"""
        events: list[dict[str, Any]] = []
        adapter = SoulToolsetAdapter(
            registry_with_tools,
            on_tool_event=lambda e: events.append(e),
        )

        await adapter.execute("fake.tool", {"fail": True})

        assert len(events) == 2
        assert events[1]["is_error"] is True

    @pytest.mark.asyncio
    async def test_callback_on_exception(self, registry_with_tools: ToolRegistry) -> None:
        """工具抛异常时回调应触发并标记错误。"""
        events: list[dict[str, Any]] = []
        adapter = SoulToolsetAdapter(
            registry_with_tools,
            on_tool_event=lambda e: events.append(e),
        )

        await adapter.execute("error.tool", {})

        assert len(events) == 2
        assert events[1]["is_error"] is True
        assert "RuntimeError" in events[1]["output"]

    @pytest.mark.asyncio
    async def test_callback_exception_does_not_break_execution(
        self, registry_with_tools: ToolRegistry
    ) -> None:
        """回调函数本身抛异常不应影响工具执行。"""

        def bad_callback(event: dict[str, Any]) -> None:
            raise ValueError("回调异常")

        adapter = SoulToolsetAdapter(
            registry_with_tools,
            on_tool_event=bad_callback,
        )

        result = await adapter.execute("fake.tool", {})

        # 工具应正常返回结果
        assert result.is_error is False
        assert "success" in result.output

    @pytest.mark.asyncio
    async def test_no_callback_works_fine(self, registry_with_tools: ToolRegistry) -> None:
        """未设置回调时应正常工作。"""
        adapter = SoulToolsetAdapter(registry_with_tools)

        result = await adapter.execute("fake.tool", {})

        assert result.is_error is False

    @pytest.mark.asyncio
    async def test_callback_with_mock(self, registry_with_tools: ToolRegistry) -> None:
        """使用 MagicMock 验证回调被调用。"""
        mock_callback = MagicMock()
        adapter = SoulToolsetAdapter(
            registry_with_tools,
            on_tool_event=mock_callback,
        )

        await adapter.execute("fake.tool", {"key": "value"})

        # 回调应被调用 2 次（tool_call + tool_result）
        assert mock_callback.call_count == 2
        # 第一次调用是 tool_call
        first_call_args = mock_callback.call_args_list[0][0][0]
        assert first_call_args["type"] == "tool_call"
        assert first_call_args["name"] == "fake.tool"
