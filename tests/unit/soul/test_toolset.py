"""测试模块：winreverse.soul.toolset

覆盖 SoulToolsetAdapter 的工具列表导出、工具调用执行、白名单过滤、错误处理。
"""

from __future__ import annotations

from typing import Any

import pytest

from kosong.types import Tool
from winreverse.engine.bus import ToolInterface, ToolRegistry
from winreverse.soul.toolset import SoulToolsetAdapter, ToolCallResult

# =============================================================================
# 测试用工具实现
# =============================================================================


class _SuccessTool:
    """成功返回的工具。"""

    name = "test.success"
    description = "返回成功结果"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {"status": "success", "echo": input_data.get("msg", "")}


class _ErrorTool:
    """返回错误的工具。"""

    name = "test.error"
    description = "返回错误结果"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {"status": "error", "error_message": "designed to fail"}


class _RaiseTool:
    """抛出异常的工具。"""

    name = "test.raise"
    description = "抛出异常"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("unexpected error")


def _build_registry(*tools: ToolInterface) -> ToolRegistry:
    """构造包含指定工具的 ToolRegistry。"""
    registry = ToolRegistry()
    for tool in tools:
        registry.register(tool)
    return registry


# =============================================================================
# 初始化与基本属性测试
# =============================================================================


class TestSoulToolsetAdapterInit:
    """SoulToolsetAdapter 初始化测试。"""

    def test_init_with_empty_registry(self) -> None:
        """空 registry 初始化成功。"""
        adapter = SoulToolsetAdapter(ToolRegistry())
        assert len(adapter) == 0

    def test_init_with_tools(self) -> None:
        """有工具的 registry 初始化成功。"""
        registry = _build_registry(_SuccessTool(), _ErrorTool())
        adapter = SoulToolsetAdapter(registry)
        assert len(adapter) == 2

    def test_init_with_allowed_tools_filter(self) -> None:
        """allowed_tools 白名单过滤。"""
        registry = _build_registry(_SuccessTool(), _ErrorTool())
        adapter = SoulToolsetAdapter(registry, allowed_tools=["test.success"])

        assert len(adapter) == 1
        assert "test.success" in adapter
        assert "test.error" not in adapter

    def test_contains_checks_whitelist(self) -> None:
        """__contains__ 考虑白名单。"""
        registry = _build_registry(_SuccessTool())
        adapter = SoulToolsetAdapter(registry, allowed_tools=["other"])
        assert "test.success" not in adapter

    def test_contains_rejects_non_str(self) -> None:
        """非字符串 name 不在适配器中。"""
        registry = _build_registry(_SuccessTool())
        adapter = SoulToolsetAdapter(registry)
        assert 123 not in adapter


# =============================================================================
# to_kosong_tools 测试
# =============================================================================


class TestToKosongTools:
    """to_kosong_tools 转换测试。"""

    def test_returns_list_of_tools(self) -> None:
        """返回 kosong Tool 列表。"""
        registry = _build_registry(_SuccessTool(), _ErrorTool())
        adapter = SoulToolsetAdapter(registry)
        tools = adapter.to_kosong_tools()

        assert len(tools) == 2
        assert all(isinstance(t, Tool) for t in tools)

    def test_tool_name_and_description_preserved(self) -> None:
        """工具名和描述被保留。"""
        registry = _build_registry(_SuccessTool())
        adapter = SoulToolsetAdapter(registry)
        tools = adapter.to_kosong_tools()

        assert tools[0].name == "test.success"
        assert tools[0].description == "返回成功结果"

    def test_filtered_by_allowed_tools(self) -> None:
        """白名单过滤生效。"""
        registry = _build_registry(_SuccessTool(), _ErrorTool())
        adapter = SoulToolsetAdapter(registry, allowed_tools=["test.success"])
        tools = adapter.to_kosong_tools()

        assert len(tools) == 1
        assert tools[0].name == "test.success"

    def test_empty_registry_returns_empty_list(self) -> None:
        """空 registry 返回空列表。"""
        adapter = SoulToolsetAdapter(ToolRegistry())
        assert adapter.to_kosong_tools() == []


# =============================================================================
# execute 测试
# =============================================================================


class TestSoulToolsetAdapterExecute:
    """SoulToolsetAdapter.execute 异步调用测试。"""

    @pytest.mark.asyncio
    async def test_execute_success(self) -> None:
        """成功调用返回 ToolCallResult。"""
        registry = _build_registry(_SuccessTool())
        adapter = SoulToolsetAdapter(registry)

        result = await adapter.execute("test.success", {"msg": "hello"})

        assert isinstance(result, ToolCallResult)
        assert result.name == "test.success"
        assert result.is_error is False
        assert "hello" in result.output
        assert result.raw["status"] == "success"

    @pytest.mark.asyncio
    async def test_execute_error_status(self) -> None:
        """工具返回 error 状态时 is_error=True。"""
        registry = _build_registry(_ErrorTool())
        adapter = SoulToolsetAdapter(registry)

        result = await adapter.execute("test.error", {})

        assert result.is_error is True
        assert "designed to fail" in result.output

    @pytest.mark.asyncio
    async def test_execute_tool_not_found(self) -> None:
        """调用未注册工具返回错误。"""
        adapter = SoulToolsetAdapter(ToolRegistry())

        result = await adapter.execute("nonexistent.tool", {})

        assert result.is_error is True
        assert "not found" in result.output

    @pytest.mark.asyncio
    async def test_execute_with_exception(self) -> None:
        """工具抛出异常时返回错误。"""
        registry = _build_registry(_RaiseTool())
        adapter = SoulToolsetAdapter(registry)

        result = await adapter.execute("test.raise", {})

        assert result.is_error is True
        assert "RuntimeError" in result.output
        assert "unexpected error" in result.output

    @pytest.mark.asyncio
    async def test_execute_blocked_by_whitelist(self) -> None:
        """白名单外的工具调用返回错误。"""
        registry = _build_registry(_SuccessTool())
        adapter = SoulToolsetAdapter(registry, allowed_tools=["other.tool"])

        result = await adapter.execute("test.success", {})

        assert result.is_error is True
        assert "not in allowed_tools" in result.output

    @pytest.mark.asyncio
    async def test_execute_output_is_json_string(self) -> None:
        """输出为 JSON 字符串。"""
        registry = _build_registry(_SuccessTool())
        adapter = SoulToolsetAdapter(registry)

        result = await adapter.execute("test.success", {"msg": "test"})

        # 应该是合法的 JSON
        import json

        parsed = json.loads(result.output)
        assert parsed["status"] == "success"

    @pytest.mark.asyncio
    async def test_execute_truncates_long_output(self) -> None:
        """超长输出被截断。"""

        class _LongOutputTool:
            name = "test.long"
            description = "返回超长结果"

            def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
                return {"status": "success", "data": "x" * 10000}

        registry = _build_registry(_LongOutputTool())
        adapter = SoulToolsetAdapter(registry, max_output_chars=100)

        result = await adapter.execute("test.long", {})

        assert len(result.output) <= 200  # 截断后加上提示信息
        assert "truncated" in result.output


# =============================================================================
# get_tool 测试
# =============================================================================


class TestGetTool:
    """get_tool 方法测试。"""

    def test_get_existing_tool(self) -> None:
        """获取已注册工具。"""
        tool = _SuccessTool()
        registry = _build_registry(tool)
        adapter = SoulToolsetAdapter(registry)

        result = adapter.get_tool("test.success")
        assert result is tool

    def test_get_nonexistent_returns_none(self) -> None:
        """获取未注册工具返回 None。"""
        adapter = SoulToolsetAdapter(ToolRegistry())
        assert adapter.get_tool("nonexistent") is None


# =============================================================================
# list_tools 测试
# =============================================================================


class TestListTools:
    """list_tools 方法测试。"""

    def test_list_all_tools(self) -> None:
        """列出所有工具。"""
        registry = _build_registry(_SuccessTool(), _ErrorTool())
        adapter = SoulToolsetAdapter(registry)

        tools = adapter.list_tools()
        assert len(tools) == 2

    def test_list_tools_filtered_by_whitelist(self) -> None:
        """白名单过滤生效。"""
        registry = _build_registry(_SuccessTool(), _ErrorTool())
        adapter = SoulToolsetAdapter(registry, allowed_tools=["test.success"])

        tools = adapter.list_tools()
        assert len(tools) == 1
        assert tools[0].name == "test.success"


# =============================================================================
# ToolCallResult 数据类测试
# =============================================================================


class TestToolCallResult:
    """ToolCallResult 数据类测试。"""

    def test_create_success_result(self) -> None:
        """创建成功结果。"""
        result = ToolCallResult(name="test", output="success output")
        assert result.name == "test"
        assert result.output == "success output"
        assert result.is_error is False
        assert result.raw == {}

    def test_create_error_result(self) -> None:
        """创建错误结果。"""
        result = ToolCallResult(
            name="test",
            output="error message",
            is_error=True,
            raw={"status": "error"},
        )
        assert result.is_error is True
        assert result.raw == {"status": "error"}
