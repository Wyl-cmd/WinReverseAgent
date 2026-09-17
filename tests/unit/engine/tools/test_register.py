"""测试模块：winreverse.engine.tools（__init__.py）

测试 register_all_tools / count_tools / list_tool_names 函数。
"""

from __future__ import annotations

import pytest

from winreverse.engine.bus import ToolRegistry
from winreverse.engine.tools import (
    ALL_TOOLS,
    count_tools,
    list_tool_names,
    register_all_tools,
)


class TestCountTools:
    """count_tools 函数测试。"""

    def test_returns_21(self) -> None:
        """共 48 个工具（领域41+文件6+shell1；2026-09-16 新增 file.hash）。"""
        assert count_tools() == 48

    def test_matches_all_tools_length(self) -> None:
        """count_tools 与 ALL_TOOLS 长度一致。"""
        assert count_tools() == len(ALL_TOOLS)


class TestListToolNames:
    """list_tool_names 函数测试。"""

    def test_returns_all_names(self) -> None:
        """返回所有工具名。"""
        names = list_tool_names()
        assert len(names) == 48
        assert "pe.parse" in names
        assert "disasm" in names
        assert "yara.scan_file" in names
        assert "die.scan_file" in names
        assert "memory.attach" in names
        assert "memory.regions" in names
        assert "memory.dump" in names
        assert "memory.analyze" in names
        assert "android.devices" in names
        assert "android.analyze_image" in names
        assert "android.connect" in names
        assert "net.live_capture" in names
        assert "behavior.monitor" in names
        assert "fs.read_file" in names
        assert "file.hash" in names
        assert "shell.run" in names


class TestRegisterAllTools:
    """register_all_tools 函数测试。"""

    def test_registers_all_tools(self) -> None:
        """应注册全部 48 个工具到 registry。"""
        registry = ToolRegistry()
        register_all_tools(registry)
        assert len(registry) == 48

    def test_registered_tools_are_callable(self) -> None:
        """注册的工具应可通过 registry.call 调用。"""
        registry = ToolRegistry()
        register_all_tools(registry)

        # 验证所有工具名都在 registry 中
        for name in list_tool_names():
            assert name in registry

    def test_duplicate_registration_raises(self) -> None:
        """重复注册应抛出 ValueError。"""
        registry = ToolRegistry()
        register_all_tools(registry)
        with pytest.raises(ValueError, match="工具已注册"):
            register_all_tools(registry)

    def test_registry_call_invokes_tool(self) -> None:
        """registry.call 应正确调用工具的 execute 方法。"""
        registry = ToolRegistry()
        register_all_tools(registry)

        # 使用 disasm 工具（不需要真实文件）
        import base64

        result = registry.call(
            "disasm",
            {
                "code": base64.b64encode(b"\x90").decode("ascii"),
                "arch": "x64",
            },
        )
        assert result["status"] == "success"

    def test_tool_list_contains_descriptions(self) -> None:
        """list_tools 应返回 name 与 description。"""
        registry = ToolRegistry()
        register_all_tools(registry)

        tools = registry.list_tools()
        assert len(tools) == 48
        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert isinstance(tool["name"], str)
            assert isinstance(tool["description"], str)
            assert len(tool["description"]) > 0
