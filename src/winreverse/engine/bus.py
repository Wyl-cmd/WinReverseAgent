"""winreverse.engine.bus — 内部工具总线。

定义所有工具必须实现的 ToolInterface 契约，以及 ToolRegistry 注册中心。
新增工具时只需实现 ToolInterface 并注册到 ToolRegistry，无需改动 bus 调度逻辑。

契约稳定性要求：
- 对外暴露的 ToolInterface / ToolRegistry 一旦发布不可随意变更
- 修改必须遵循 DEVELOPMENT.md §7.1 变更管理流程
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class ToolParameterSpec:
    """工具参数声明（ToolInterface 的**可选**扩展契约）。

    用途（2026-09-16 P0-1 修复）：Soul 适配器需要把工具的入参 schema 暴露给 LLM，
    否则 LLM 每轮 tool_call 的 arguments 恒为 ``{}``，带参工具必然 KeyError。

    工具类可以直接声明 ``parameters: list[ToolParameterSpec]``（显式优先）；
    未声明时由 ``winreverse.soul.tool_schema.infer_parameters`` 从 ``_run`` 源码推断。

    Attributes:
        name: 参数名（必须与 ``_run`` 中读取 input_data 的键一致）
        type: JSON Schema 类型串（string/integer/number/boolean/array/object）
        description: 参数用途说明（供 LLM 理解）
        required: 是否必填
        default: 默认值（仅用于文档与推断，不参与运行时注入）
    """

    name: str
    type: str = "string"
    description: str = ""
    required: bool = True
    default: Any = None


@runtime_checkable
class ToolInterface(Protocol):
    """所有工具必须实现此契约。

    新增工具类型时只需实现此接口，无需改动 bus 调度逻辑。
    输入 JSON -> 处理 -> 输出 JSON，便于未来 MCP 透明桥接。

    Note（2026-09-16）:
        实现方**可以**额外声明 ``parameters: list[ToolParameterSpec]`` 描述入参；
        该属性是可选扩展（不加入 Protocol 成员，避免破坏既有实现与测试替身），
        Soul 适配器通过 ``getattr(tool, "parameters", None)`` 读取，
        未声明时回落到 ``_run`` 源码推断（见 ``soul/tool_schema.py``）。
    """

    name: str
    """工具唯一标识，建议用点分命名空间，如 'memory.attach'、'pe.parse'。"""

    description: str
    """工具用途说明，供 LLM 理解与调用。"""

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """执行工具。

        Args:
            input_data: 输入参数（JSON 兼容字典）

        Returns:
            输出结果（JSON 兼容字典），必须包含 'status' 字段：
                - 'success': 成功
                - 'error': 失败（同时附带 'error_message'）
        """
        ...


class ToolNotFoundError(KeyError):
    """请求的工具未注册时抛出。"""


class ToolRegistry:
    """工具注册中心。

    所有工具（内部工具 / MCP 桥接工具）统一注册到此中心。
    Soul 引擎通过 registry.call(name, args) 调用工具，对工具来源透明。
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolInterface] = {}

    def register(self, tool: ToolInterface) -> None:
        """注册工具。重复注册同名工具抛出 ValueError。"""
        if tool.name in self._tools:
            raise ValueError(f"工具已注册: {tool.name}")
        self._tools[tool.name] = tool

    def unregister(self, name: str) -> None:
        """注销工具。未注册的工具抛出 ToolNotFoundError。"""
        if name not in self._tools:
            raise ToolNotFoundError(name)
        del self._tools[name]

    def get(self, name: str) -> ToolInterface:
        """获取工具实例。未注册时抛出 ToolNotFoundError。"""
        if name not in self._tools:
            raise ToolNotFoundError(name)
        return self._tools[name]

    def list_tools(self) -> list[dict[str, str]]:
        """列出所有已注册工具的 name 与 description。"""
        return [
            {"name": tool.name, "description": tool.description} for tool in self._tools.values()
        ]

    def call(self, name: str, input_data: dict[str, Any]) -> dict[str, Any]:
        """调用工具。未注册时抛出 ToolNotFoundError。"""
        tool = self.get(name)
        return tool.execute(input_data)

    def clear(self) -> None:
        """清空所有注册的工具（主要用于测试）。"""
        self._tools.clear()

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: object) -> bool:
        return name in self._tools


# 全局默认注册中心实例（单例）
_default_registry: ToolRegistry | None = None


def get_default_registry() -> ToolRegistry:
    """获取全局默认 ToolRegistry 单例。

    首次调用时创建，后续调用返回同一实例。
    测试中可用 tool_registry fixture 注入临时实例避免污染。
    """
    global _default_registry
    if _default_registry is None:
        _default_registry = ToolRegistry()
    return _default_registry


def reset_default_registry() -> None:
    """重置全局默认 ToolRegistry（主要用于测试隔离）。"""
    global _default_registry
    _default_registry = None
