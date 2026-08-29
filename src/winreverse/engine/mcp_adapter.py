"""winreverse.engine.mcp_adapter — MCP 标准化集成预留。

【预留声明】
本模块仅定义接口契约（Protocol），不实现任何 transport/auth/adapter 具体类。
默认 enabled=false 时：
- 不 import 任何 MCP 重依赖（aiohttp/websockets 等）
- 不启动任何 MCP 服务或客户端
- 不影响主流程性能

未来启用 MCP 时，按以下顺序实施（M9 阶段）：
1. 实现 MCPTransport 三种 transport（stdio/sse/http）
2. 实现 MCPAuth 四种认证策略（none/api_key/oauth2/mtls）
3. 实现 MCPServerAdapter 完整连接/调用/断开逻辑
4. 在 bus.py 中实现 register_mcp_tools() 桥接
5. 通过 §7.4 四类测试方可上线

参考：实施方案 §7.3
"""

from __future__ import annotations

from typing import Any, Protocol


class MCPTransport(Protocol):
    """MCP 传输层契约。

    未来实现三种：
    - StdioTransport: 子进程 stdio 通信
    - SSETransport: Server-Sent Events
    - HTTPTransport: HTTP 长连接
    """

    def send(self, message: dict[str, Any]) -> None:
        """发送 JSON-RPC 消息。"""
        ...

    def receive(self) -> dict[str, Any]:
        """接收 JSON-RPC 消息（阻塞直到收到）。"""
        ...

    def close(self) -> None:
        """关闭传输连接。"""
        ...


class MCPAuth(Protocol):
    """认证策略契约。

    未来实现四种：
    - NoneAuth: 无认证
    - APIKeyAuth: API Key 认证
    - OAuth2Auth: OAuth 2.0 认证
    - MTLSAuth: 双向 TLS 认证
    """

    def apply(self, request: dict[str, Any]) -> dict[str, Any]:
        """将认证信息应用到请求中，返回带认证头的请求。"""
        ...


class MCPServerAdapter(Protocol):
    """MCP Server 适配器契约。

    未来实现完整的连接/调用/断开逻辑。
    """

    def connect(self) -> None:
        """建立与 MCP Server 的连接。"""
        ...

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """调用 MCP Server 暴露的工具。"""
        ...

    def list_tools(self) -> list[dict[str, Any]]:
        """列出 MCP Server 暴露的所有工具。"""
        ...

    def disconnect(self) -> None:
        """断开与 MCP Server 的连接。"""
        ...


class MCPConfig:
    """MCP 配置载体。

    M1 阶段仅交付 from_toml 加载逻辑，enabled=false 时短路返回空配置，
    不加载任何 MCP 依赖，零运行时影响。
    """

    def __init__(self, enabled: bool, servers: list[dict[str, Any]]) -> None:
        self.enabled = enabled
        self.servers = servers

    @classmethod
    def from_toml(cls, config_path: object) -> MCPConfig:
        """从 config.toml 加载 MCP 配置。

        Args:
            config_path: config.toml 文件路径

        Returns:
            MCPConfig 实例。enabled=false 时返回空 servers 列表，
            不解析任何 server 配置，零开销短路。
        """
        # 按设计预留：MCP 集成在当前阶段不实现，默认禁用，不读取文件
        # 保留标准化接口契约供未来阶段启用
        return cls(enabled=False, servers=[])

    def __repr__(self) -> str:
        return f"MCPConfig(enabled={self.enabled}, servers_count={len(self.servers)})"
