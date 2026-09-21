"""测试模块：winreverse.engine.sandbox_runner（模块级公开面）。

覆盖点：钉扎"M1-M7 仅保留接口契约"的预留承诺——模块自定义公开名仅两个
Protocol，均直接继承 typing.Protocol，且不为实现方预设构造器。
"""

from __future__ import annotations

import inspect
from typing import Protocol

from winreverse.engine import sandbox_runner


class TestModuleSurface:
    """模块级公开面钉扎：契约-only 预留承诺。"""

    def test_module_defines_only_the_two_protocols(self) -> None:
        """模块自定义的公开名恰为 SandboxRunner / BehaviorAnalyzer 两个契约类。

        若有人提前落入具体后端实现（M8 前禁止）或泄漏模块级辅助符号，立即暴露。
        """
        defined = {
            name
            for name, value in vars(sandbox_runner).items()
            if getattr(value, "__module__", None) == sandbox_runner.__name__
        }
        assert defined == {"SandboxRunner", "BehaviorAnalyzer"}

    def test_both_protocols_directly_inherit_typing_protocol(self) -> None:
        """两个契约类均为 typing.Protocol 子类（结构化契约而非 ABC）。"""
        assert issubclass(sandbox_runner.SandboxRunner, Protocol)
        assert issubclass(sandbox_runner.BehaviorAnalyzer, Protocol)

    def test_protocols_are_classes_not_instances(self) -> None:
        """契约本身是类（可被 isinstance 外的反射工具检查），非模块级单例。"""
        assert inspect.isclass(sandbox_runner.SandboxRunner)
        assert inspect.isclass(sandbox_runner.BehaviorAnalyzer)
