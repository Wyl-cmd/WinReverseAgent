"""测试模块：winreverse.engine.bus

测试 ToolInterface Protocol 契约与 ToolRegistry 注册中心。
覆盖：
- ToolInterface 协议的 runtime_checkable 特性
- ToolRegistry 的注册/注销/查询/调用
- 重复注册/未注册工具的异常处理
- 全局默认单例的获取与重置
"""

from __future__ import annotations

from typing import Any

import pytest

from winreverse.engine.bus import (
    ToolInterface,
    ToolNotFoundError,
    ToolRegistry,
    get_default_registry,
    reset_default_registry,
)

# =============================================================================
# 测试用的工具实现（mock 工具）
# =============================================================================


class _MockTool:
    """最小化的 ToolInterface 实现用于测试。"""

    def __init__(self, name: str, description: str = "mock tool") -> None:
        self.name = name
        self.description = description

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {"status": "success", "input": input_data, "tool": self.name}


class _ErrorTool:
    """总是返回错误的工具实现。"""

    name = "error.tool"
    description = "always fails"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {"status": "error", "error_message": "designed to fail"}


# =============================================================================
# ToolInterface Protocol 测试
# =============================================================================


class TestToolInterfaceProtocol:
    """ToolInterface 协议测试"""

    def test_protocol_is_runtime_checkable(self) -> None:
        """ToolInterface 标记了 @runtime_checkable，支持 isinstance 检查。"""
        tool = _MockTool("test.tool")
        assert isinstance(tool, ToolInterface)

    def test_protocol_rejects_missing_name(self) -> None:
        """缺少 name 属性的对象不满足 ToolInterface 契约。"""
        obj = object()
        assert not isinstance(obj, ToolInterface)

    def test_protocol_rejects_missing_execute(self) -> None:
        """缺少 execute 方法的对象不满足契约。"""

        class _Incomplete:
            name = "incomplete"
            description = "missing execute"

        assert not isinstance(_Incomplete(), ToolInterface)


# =============================================================================
# ToolRegistry 注册测试
# =============================================================================


class TestToolRegistryRegister:
    """ToolRegistry 注册相关测试"""

    def test_register_single_tool(self, tool_registry: ToolRegistry) -> None:
        """注册单个工具应成功。"""
        tool = _MockTool("memory.attach")
        tool_registry.register(tool)
        assert len(tool_registry) == 1
        assert "memory.attach" in tool_registry

    def test_register_duplicate_raises(self, tool_registry: ToolRegistry) -> None:
        """重复注册同名工具应抛出 ValueError。"""
        tool_registry.register(_MockTool("memory.attach"))
        with pytest.raises(ValueError, match="工具已注册"):
            tool_registry.register(_MockTool("memory.attach"))

    def test_register_multiple_tools(self, tool_registry: ToolRegistry) -> None:
        """注册多个不同名称的工具应全部成功。"""
        tool_registry.register(_MockTool("memory.attach"))
        tool_registry.register(_MockTool("memory.read"))
        tool_registry.register(_MockTool("pe.parse"))
        assert len(tool_registry) == 3


# =============================================================================
# ToolRegistry 查询与调用测试
# =============================================================================


class TestToolRegistryQuery:
    """ToolRegistry 查询与调用相关测试"""

    def test_get_existing_tool(self, tool_registry: ToolRegistry) -> None:
        """获取已注册的工具应返回实例。"""
        tool = _MockTool("memory.attach", "附加进程")
        tool_registry.register(tool)
        result = tool_registry.get("memory.attach")
        assert result is tool

    def test_get_nonexistent_raises(self, tool_registry: ToolRegistry) -> None:
        """获取未注册的工具应抛出 ToolNotFoundError。"""
        with pytest.raises(ToolNotFoundError, match=r"nonexistent\.tool"):
            tool_registry.get("nonexistent.tool")

    def test_call_tool_success(self, tool_registry: ToolRegistry) -> None:
        """调用工具应返回执行结果。"""
        tool_registry.register(_MockTool("memory.attach"))
        result = tool_registry.call("memory.attach", {"process_name": "game.exe"})
        assert result["status"] == "success"
        assert result["input"] == {"process_name": "game.exe"}
        assert result["tool"] == "memory.attach"

    def test_call_error_tool(self, tool_registry: ToolRegistry) -> None:
        """调用返回错误的工具应保留 status=error。"""
        tool_registry.register(_ErrorTool())
        result = tool_registry.call("error.tool", {})
        assert result["status"] == "error"
        assert "error_message" in result

    def test_call_nonexistent_raises(self, tool_registry: ToolRegistry) -> None:
        """调用未注册工具应抛出 ToolNotFoundError。"""
        with pytest.raises(ToolNotFoundError):
            tool_registry.call("nonexistent.tool", {})

    def test_list_tools(self, tool_registry: ToolRegistry) -> None:
        """list_tools 应返回所有工具的 name 与 description。"""
        tool_registry.register(_MockTool("memory.attach", "附加进程"))
        tool_registry.register(_MockTool("pe.parse", "解析 PE 文件"))
        tools = tool_registry.list_tools()
        assert len(tools) == 2
        names = [t["name"] for t in tools]
        assert "memory.attach" in names
        assert "pe.parse" in names
        descriptions = [t["description"] for t in tools]
        assert "附加进程" in descriptions


# =============================================================================
# ToolRegistry 注销与清理测试
# =============================================================================


class TestToolRegistryUnregister:
    """ToolRegistry 注销与清理测试"""

    def test_unregister_existing(self, tool_registry: ToolRegistry) -> None:
        """注销已注册的工具应成功。"""
        tool_registry.register(_MockTool("memory.attach"))
        tool_registry.unregister("memory.attach")
        assert len(tool_registry) == 0
        assert "memory.attach" not in tool_registry

    def test_unregister_nonexistent_raises(self, tool_registry: ToolRegistry) -> None:
        """注销未注册的工具应抛出 ToolNotFoundError。"""
        with pytest.raises(ToolNotFoundError):
            tool_registry.unregister("nonexistent.tool")

    def test_clear_all(self, tool_registry: ToolRegistry) -> None:
        """clear 应清空所有工具。"""
        tool_registry.register(_MockTool("a"))
        tool_registry.register(_MockTool("b"))
        tool_registry.register(_MockTool("c"))
        tool_registry.clear()
        assert len(tool_registry) == 0


# =============================================================================
# 全局默认单例测试
# =============================================================================


class TestDefaultRegistry:
    """全局默认 ToolRegistry 单例测试"""

    def test_get_default_returns_same_instance(self) -> None:
        """多次获取应返回同一实例。"""
        r1 = get_default_registry()
        r2 = get_default_registry()
        assert r1 is r2

    def test_reset_default_creates_new_instance(self) -> None:
        """reset 后再获取应返回新实例。"""
        r1 = get_default_registry()
        reset_default_registry()
        r2 = get_default_registry()
        assert r1 is not r2

    def test_reset_clears_registered_tools(self) -> None:
        """reset 应清空已注册工具。"""
        registry = get_default_registry()
        registry.register(_MockTool("test.tool"))
        assert len(registry) == 1
        reset_default_registry()
        new_registry = get_default_registry()
        assert len(new_registry) == 0
