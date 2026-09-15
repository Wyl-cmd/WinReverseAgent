"""测试模块：winreverse.engine.bus 尾部路径

覆盖点：ToolInterface.execute 协议默认体（bus.py:41，guest 覆盖率唯一缺失行）——
未实现 execute 的显式子类沿 MRO 命中 Protocol 默认方法体，静默返回 None。
"""

from __future__ import annotations

from winreverse.engine.bus import ToolInterface, ToolRegistry


class _PartialTool(ToolInterface):
    """只实现契约属性的显式子类：不覆写 execute，走协议默认方法体。"""

    name = "partial.tool"
    description = "missing execute implementation"


class TestProtocolDefaultExecuteBody:
    """ToolInterface.execute 默认体（...）的真实行为。"""

    def test_partial_subclass_execute_returns_none(self) -> None:
        # 显式继承 Protocol 而不实现 execute：调用沿 MRO 落到默认体，
        # 契约不提供任何默认行为，静默返回 None（而非抛 NotImplementedError）。
        tool = _PartialTool()
        assert isinstance(tool, ToolInterface)  # runtime_checkable 对显式子类成立
        assert tool.execute({"any": "input"}) is None

    def test_registry_call_passthrough_default_none(self) -> None:
        # ToolRegistry.call 不校验返回值形状：命中默认体的工具把 None 原样透传，
        # 证明返回值契约（须含 'status'）只在文档层约束，注册中心无运行时防御。
        registry = ToolRegistry()
        registry.register(_PartialTool())
        assert registry.call("partial.tool", {}) is None
