"""测试模块：winreverse.engine.sandbox_runner（M8 杀箱后端契约，纯 Protocol 预留模块）。

覆盖点：SandboxRunner / BehaviorAnalyzer 的契约成员、方法签名与注解钉扎，
防止未来实现后端或重构时无声破坏契约（调用方 Skill / LLM 分析器依赖此契约）。
另覆盖：Protocol 占位方法体直呼返回 None、runtime_checkable 结构校验。
"""

from __future__ import annotations

import inspect
from typing import get_type_hints, runtime_checkable

import pytest

from winreverse.engine import sandbox_runner


def _public_methods(cls: type) -> dict[str, inspect.Signature]:
    """提取类的公开方法签名（Protocol 声明体不含继承 object 的成员）。"""
    return {
        name: inspect.signature(method)
        for name, method in vars(cls).items()
        if not name.startswith("_") and callable(method)
    }


def _param_names(cls: type, method_name: str) -> list[str]:
    """取契约方法参数名（去掉 self；Protocol 方法经 vars() 取出为未绑定函数）。"""
    return [name for name in _public_methods(cls)[method_name].parameters if name != "self"]


class TestSandboxRunnerContract:
    """SandboxRunner 杀箱后端契约钉扎。"""

    def test_contract_exposes_exactly_four_lifecycle_methods(self) -> None:
        """契约成员固定为 prepare/run/collect/destroy 生命周期四方法。"""
        methods = _public_methods(sandbox_runner.SandboxRunner)
        assert set(methods) == {"prepare", "run", "collect", "destroy"}

    def test_method_signatures_are_stable(self) -> None:
        """方法签名（参数名与顺序）钉扎：实现方与调用方按名传参依赖它们。"""
        assert _param_names(sandbox_runner.SandboxRunner, "prepare") == [
            "sample_path",
            "config",
        ]
        assert _param_names(sandbox_runner.SandboxRunner, "run") == [
            "session_id",
            "duration",
        ]
        assert _param_names(sandbox_runner.SandboxRunner, "collect") == ["session_id"]
        assert _param_names(sandbox_runner.SandboxRunner, "destroy") == ["session_id"]
        # duration 为必填位置参数（无默认值），避免实现方误加默认值改变语义
        run_sig = _public_methods(sandbox_runner.SandboxRunner)["run"]
        assert run_sig.parameters["duration"].default is inspect.Parameter.empty

    def test_return_annotations_are_declared(self) -> None:
        """返回注解钉扎：prepare 回传会话 ID 字符串，run/collect 回传事件 dict，destroy 无返回。"""
        prepare_ret = get_type_hints(sandbox_runner.SandboxRunner.prepare)["return"]
        assert prepare_ret is str
        assert get_type_hints(sandbox_runner.SandboxRunner.destroy)["return"] is type(None)
        for name in ("run", "collect"):
            ret = get_type_hints(getattr(sandbox_runner.SandboxRunner, name))["return"]
            assert getattr(ret, "__origin__", None) is dict, f"{name} 应声明返回 dict，实际 {ret}"


class TestBehaviorAnalyzerContract:
    """BehaviorAnalyzer LLM 行为分析器契约钉扎。"""

    def test_contract_exposes_single_analyze_method(self) -> None:
        """契约成员固定为 analyze 单方法，入参名 events。"""
        methods = _public_methods(sandbox_runner.BehaviorAnalyzer)
        assert set(methods) == {"analyze"}
        assert _param_names(sandbox_runner.BehaviorAnalyzer, "analyze") == ["events"]
        analyze_ret = get_type_hints(sandbox_runner.BehaviorAnalyzer.analyze)["return"]
        assert getattr(analyze_ret, "__origin__", None) is dict


class TestContractImplementability:
    """契约可实现性：示例后端按签名实现后应满足结构一致（鸭子类型校验）。"""

    def test_sample_backend_conforms(self) -> None:
        """按契约实现的样例后端的每个契约方法应可调用且签名兼容。"""

        class _WindowsSandboxRunner:
            def prepare(self, sample_path: str, config: dict) -> str:
                return "session-1"

            def run(self, session_id: str, duration: int) -> dict:
                return {}

            def collect(self, session_id: str) -> dict:
                return {}

            def destroy(self, session_id: str) -> None:
                return None

        contract = _public_methods(sandbox_runner.SandboxRunner)
        impl = _public_methods(_WindowsSandboxRunner)
        assert set(impl) == set(contract)
        for name, sig in contract.items():
            # 实现方参数集应与契约一致（self 之外）
            assert set(impl[name].parameters) == set(sig.parameters), name

    def test_incomplete_backend_detected(self) -> None:
        """缺少 destroy 的实现应被契约校验发现（M8 阶段防止半成品后端合入）。"""

        class _BrokenRunner:
            def prepare(self, sample_path: str, config: dict) -> str:
                return ""

            def run(self, session_id: str, duration: int) -> dict:
                return {}

            def collect(self, session_id: str) -> dict:
                return {}

        contract = _public_methods(sandbox_runner.SandboxRunner)
        impl = _public_methods(_BrokenRunner)
        missing = set(contract) - set(impl)
        assert missing == {"destroy"}


@pytest.mark.parametrize(
    ("cls", "module"),
    [
        (sandbox_runner.SandboxRunner, sandbox_runner),
        (sandbox_runner.BehaviorAnalyzer, sandbox_runner),
    ],
)
def test_protocols_are_runtime_classes(cls: type, module: object) -> None:
    """两个契约均为模块级可导出的真实类（预留接口可被 isinstance 外工具检查）。"""
    assert inspect.isclass(cls)
    assert cls.__module__ == module.__name__


class TestProtocolPlaceholderBodies:
    """Protocol 方法体为占位（...）：按契约签名直呼应返回 None 且无副作用。

    若未来有人误在 Protocol 体里写实现逻辑（而非在 M8 实现类中），本组断言立即暴露。
    """

    def test_sandbox_runner_bodies_inert(self) -> None:
        """杀箱四阶段方法的占位体不得有返回值或副作用。"""
        assert sandbox_runner.SandboxRunner.prepare(None, "sample.exe", {"net": "off"}) is None
        assert sandbox_runner.SandboxRunner.run(None, "sess-1", 60) is None
        assert sandbox_runner.SandboxRunner.collect(None, "sess-1") is None
        assert sandbox_runner.SandboxRunner.destroy(None, "sess-1") is None

    def test_behavior_analyzer_body_inert(self) -> None:
        """行为分析占位体不得改写入参事件集合。"""
        events: dict[str, object] = {"files": []}
        assert sandbox_runner.BehaviorAnalyzer.analyze(None, events) is None
        assert events == {"files": []}


class TestRuntimeCheckableConformance:
    """runtime_checkable 动态包裹后的 isinstance 结构校验（缺方法即破坏契约）。"""

    def test_complete_runner_satisfies_contract(self) -> None:
        """四阶段齐全的实现通过结构校验。"""

        class _FullRunner:
            def prepare(self, sample_path: str, config: dict) -> str:
                return "sess-1"

            def run(self, session_id: str, duration: int) -> dict:
                return {}

            def collect(self, session_id: str) -> dict:
                return {}

            def destroy(self, session_id: str) -> None:
                return None

        assert isinstance(_FullRunner(), runtime_checkable(sandbox_runner.SandboxRunner))

    def test_runner_missing_destroy_rejected(self) -> None:
        """缺 destroy 的半成品后端应被结构校验拒绝（与签名钉扎测试互为冗余防线）。"""

        class _NoDestroy:
            def prepare(self, sample_path: str, config: dict) -> str:
                return ""

            def run(self, session_id: str, duration: int) -> dict:
                return {}

            def collect(self, session_id: str) -> dict:
                return {}

        assert not isinstance(_NoDestroy(), runtime_checkable(sandbox_runner.SandboxRunner))

    def test_analyzer_satisfies_contract(self) -> None:
        """具备 analyze 的实现通过结构校验，普通对象被拒。"""

        class _MinAnalyzer:
            def analyze(self, events: dict) -> dict:
                return {}

        analyzer_protocol = runtime_checkable(sandbox_runner.BehaviorAnalyzer)
        assert isinstance(_MinAnalyzer(), analyzer_protocol)
        assert not isinstance(object(), analyzer_protocol)
