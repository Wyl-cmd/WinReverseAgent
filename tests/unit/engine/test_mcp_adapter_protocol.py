"""测试模块：winreverse.engine.mcp_adapter（Protocol 补充契约，自足文件）。

不改动既有 tests/unit/engine/test_mcp_adapter.py，本文件独立覆盖：
- Protocol 方法体为占位（按文档签名直呼应返回 None 且无副作用）
- runtime_checkable 动态包裹后的 isinstance 结构校验（缺方法即不满足契约）
- MCPConfig M1 短路契约补充（from_toml 忽略文件内容 / repr 的 servers 计数）
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, runtime_checkable

from winreverse.engine.mcp_adapter import (
    MCPAuth,
    MCPConfig,
    MCPServerAdapter,
    MCPTransport,
)


class TestProtocolPlaceholderBodies:
    """Protocol 方法体为占位（...）：按文档签名直呼应返回 None 且无副作用。

    若未来有人误在 Protocol 体里写实现逻辑，本组断言会立即暴露。
    """

    def test_transport_bodies_inert(self) -> None:
        """传输层三方法的占位体不得有返回值或副作用。"""
        assert MCPTransport.send(None, {"jsonrpc": "2.0", "id": 1}) is None
        assert MCPTransport.receive(None) is None
        assert MCPTransport.close(None) is None

    def test_auth_body_inert(self) -> None:
        """认证占位体不得改写入参请求。"""
        request = {"method": "tools/list"}
        assert MCPAuth.apply(None, request) is None
        assert request == {"method": "tools/list"}

    def test_adapter_bodies_inert(self) -> None:
        """适配器四方法的占位体不得有返回值。"""
        assert MCPServerAdapter.connect(None) is None
        assert MCPServerAdapter.call_tool(None, "t", {"a": 1}) is None
        assert MCPServerAdapter.list_tools(None) is None
        assert MCPServerAdapter.disconnect(None) is None


class TestRuntimeCheckableConformance:
    """runtime_checkable 动态包裹后的 isinstance 结构校验（缺方法即不满足契约）。"""

    def test_minimal_transport_satisfies_isinstance(self) -> None:
        """具备三方法的实现通过结构校验，缺方法对象被拒。"""

        class _MinTransport:
            def send(self, message: dict[str, Any]) -> None: ...

            def receive(self) -> dict[str, Any]: ...

            def close(self) -> None: ...

        transport_protocol = runtime_checkable(MCPTransport)
        assert isinstance(_MinTransport(), transport_protocol)
        assert not isinstance(object(), transport_protocol)

    def test_minimal_auth_satisfies_isinstance(self) -> None:
        """具备 apply 的实现通过结构校验。"""

        class _MinAuth:
            def apply(self, request: dict[str, Any]) -> dict[str, Any]:
                return request

        assert isinstance(_MinAuth(), runtime_checkable(MCPAuth))
        assert not isinstance(object(), runtime_checkable(MCPAuth))

    def test_minimal_adapter_satisfies_isinstance(self) -> None:
        """具备四方法的实现通过结构校验。"""

        class _MinAdapter:
            def connect(self) -> None: ...

            def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]: ...

            def list_tools(self) -> list[dict[str, Any]]: ...

            def disconnect(self) -> None: ...

        adapter_protocol = runtime_checkable(MCPServerAdapter)
        assert isinstance(_MinAdapter(), adapter_protocol)
        assert not isinstance(object(), adapter_protocol)


class TestMCPConfigShortCircuit:
    """MCPConfig M1 短路契约补充。"""

    def test_from_toml_ignores_file_content(self, tmp_path: Path) -> None:
        """即使 toml 声明 enabled=true 与 servers，M1 阶段也不解析文件。"""
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            '[mcp]\nenabled = true\n[[mcp.servers]]\nname = "x"\n',
            encoding="utf-8",
        )
        config = MCPConfig.from_toml(config_file)
        assert config.enabled is False
        assert config.servers == []

    def test_repr_counts_nonempty_servers(self) -> None:
        """repr 的 servers_count 应随 servers 实际长度变化。"""
        config = MCPConfig(enabled=True, servers=[{"name": "a"}, {"name": "b"}])
        assert "enabled=True" in repr(config)
        assert "servers_count=2" in repr(config)
