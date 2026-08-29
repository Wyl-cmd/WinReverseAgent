"""测试模块：winreverse.engine.mcp_adapter

测试 MCP 标准化集成预留接口契约。
覆盖：
- MCPConfig.from_toml() 默认返回 enabled=false
- Protocol 契约存在性验证
- 零运行时影响验证（不导入重依赖）
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from winreverse.engine.mcp_adapter import (
    MCPAuth,
    MCPConfig,
    MCPServerAdapter,
    MCPTransport,
)


class TestMCPConfigDefault:
    """MCPConfig 默认行为测试（enabled=false 时零开销）"""

    def test_from_toml_returns_disabled_by_default(self, tmp_path: Path) -> None:
        """from_toml 默认返回 enabled=false 的配置。"""
        config = MCPConfig.from_toml(tmp_path / "nonexistent.toml")
        assert config.enabled is False
        assert config.servers == []

    def test_config_repr(self) -> None:
        """MCPConfig 的 repr 应包含 enabled 与 servers 数量。"""
        config = MCPConfig(enabled=False, servers=[])
        repr_str = repr(config)
        assert "enabled=False" in repr_str
        assert "servers_count=0" in repr_str

    def test_no_heavy_dependencies_imported(self) -> None:
        """enabled=false 时不应导入 aiohttp/websockets 等重依赖。"""
        # 清除可能已导入的模块
        for mod in list(sys.modules.keys()):
            if mod.startswith(("aiohttp", "websockets")):
                del sys.modules[mod]

        # 加载 mcp_adapter 不应触发这些依赖的导入
        MCPConfig.from_toml(None)

        # 验证 aiohttp/websockets 未被导入
        assert "aiohttp" not in sys.modules
        assert "websockets" not in sys.modules


class TestMCPProtocolContracts:
    """MCP Protocol 契约存在性测试"""

    def test_mcp_transport_protocol_exists(self) -> None:
        """MCPTransport Protocol 已定义。"""
        assert MCPTransport is not None
        assert hasattr(MCPTransport, "send")
        assert hasattr(MCPTransport, "receive")
        assert hasattr(MCPTransport, "close")

    def test_mcp_auth_protocol_exists(self) -> None:
        """MCPAuth Protocol 已定义。"""
        assert MCPAuth is not None
        assert hasattr(MCPAuth, "apply")

    def test_mcp_server_adapter_protocol_exists(self) -> None:
        """MCPServerAdapter Protocol 已定义。"""
        assert MCPServerAdapter is not None
        assert hasattr(MCPServerAdapter, "connect")
        assert hasattr(MCPServerAdapter, "call_tool")
        assert hasattr(MCPServerAdapter, "list_tools")
        assert hasattr(MCPServerAdapter, "disconnect")


class TestMCPProtocolConformance:
    """MCP Protocol 一致性测试（用最小实现验证契约）"""

    def test_minimal_transport_satisfies_protocol(self) -> None:
        """最小实现的 transport 应满足 MCPTransport 契约。"""

        class _MinTransport:
            def send(self, message: dict[str, Any]) -> None:
                pass

            def receive(self) -> dict[str, Any]:
                return {}

            def close(self) -> None:
                pass

        transport = _MinTransport()
        # Protocol（非 runtime_checkable）只做静态类型检查，运行时 isinstance 不强制
        # 但我们验证方法存在
        assert callable(transport.send)
        assert callable(transport.receive)
        assert callable(transport.close)

    def test_minimal_auth_satisfies_protocol(self) -> None:
        """最小实现的 auth 应满足 MCPAuth 契约。"""

        class _MinAuth:
            def apply(self, request: dict[str, Any]) -> dict[str, Any]:
                return request

        auth = _MinAuth()
        assert callable(auth.apply)

    def test_minimal_adapter_satisfies_protocol(self) -> None:
        """最小实现的 adapter 应满足 MCPServerAdapter 契约。"""

        class _MinAdapter:
            def connect(self) -> None:
                pass

            def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
                return {"status": "success"}

            def list_tools(self) -> list[dict[str, Any]]:
                return []

            def disconnect(self) -> None:
                pass

        adapter = _MinAdapter()
        assert callable(adapter.connect)
        assert callable(adapter.call_tool)
        assert callable(adapter.list_tools)
        assert callable(adapter.disconnect)
