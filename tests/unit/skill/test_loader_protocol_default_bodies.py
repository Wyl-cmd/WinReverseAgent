"""测试模块：winreverse.skill.loader 尾部路径

覆盖点：SkillLoader 协议默认方法体（loader.py:117/128，guest 覆盖率仅缺 2 行）——
未实现 load/supports 的显式子类沿 MRO 命中 Protocol 默认体，静默返回 None。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from winreverse.skill.loader import SkillLoader


class _BareLoader(SkillLoader):
    """显式继承 Protocol 而不实现任何方法：调用沿 MRO 落到协议默认体。"""


class TestSkillLoaderProtocolDefaultBodies:
    """SkillLoader.load / supports 默认体（...）的真实行为。"""

    def test_bare_subclass_load_returns_none(self) -> None:
        # 显式子类不实现 load：默认方法体只有 ...，契约不提供任何默认行为，
        # 调用静默返回 None（而非抛 NotImplementedError）——
        # 加载器契约的返回值约束只在文档层，无运行时防御。
        loader = _BareLoader()
        assert loader.load(Path("any.yaml")) is None

    def test_bare_subclass_supports_returns_none(self) -> None:
        # supports 同理：命中默认体返回 None 而非 False，
        # 说明调用方不能拿 supports 的返回值直接做布尔短路之外的语义判断。
        loader = _BareLoader()
        assert loader.supports(Path("any.yaml")) is None
        assert not loader.supports(Path("any.md"))  # None 为假值：布尔语义上等价"不支持"

    def test_protocol_is_not_runtime_checkable(self) -> None:
        # SkillLoader 未加 @runtime_checkable（与 engine.bus.ToolInterface 相反）：
        # 即使是显式子类实例，isinstance 也被 Protocol 元类拦截抛 TypeError。
        # 契约符合性只能靠静态检查器（mypy/pyright），运行时不可探测。
        with pytest.raises(TypeError, match="runtime_checkable"):
            isinstance(_BareLoader(), SkillLoader)
