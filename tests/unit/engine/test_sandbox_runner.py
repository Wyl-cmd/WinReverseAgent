"""测试模块：winreverse.engine.sandbox_runner

测试 SandboxRunner 预留契约（M8 占位）。
覆盖：
- SandboxRunner Protocol 契约存在性
- BehaviorAnalyzer Protocol 契约存在性
- 最小实现的一致性验证
"""

from __future__ import annotations

from typing import Any

from winreverse.engine.sandbox_runner import BehaviorAnalyzer, SandboxRunner


class TestSandboxRunnerContract:
    """SandboxRunner 契约测试"""

    def test_protocol_exists(self) -> None:
        """SandboxRunner Protocol 已定义。"""
        assert SandboxRunner is not None

    def test_protocol_has_required_methods(self) -> None:
        """SandboxRunner 必须包含 prepare/run/collect/destroy 四个方法。"""
        assert hasattr(SandboxRunner, "prepare")
        assert hasattr(SandboxRunner, "run")
        assert hasattr(SandboxRunner, "collect")
        assert hasattr(SandboxRunner, "destroy")

    def test_minimal_implementation_satisfies_protocol(self) -> None:
        """最小实现应满足 SandboxRunner 契约。"""

        class _MinRunner:
            def prepare(self, sample_path: str, config: dict[str, Any]) -> str:
                return "session-001"

            def run(self, session_id: str, duration: int) -> dict[str, Any]:
                return {"events": []}

            def collect(self, session_id: str) -> dict[str, Any]:
                return {"events": []}

            def destroy(self, session_id: str) -> None:
                pass

        runner = _MinRunner()
        assert callable(runner.prepare)
        assert callable(runner.run)
        assert callable(runner.collect)
        assert callable(runner.destroy)

        # 验证调用流程符合契约
        session_id = runner.prepare("/sample.exe", {})
        assert isinstance(session_id, str)

        events = runner.run(session_id, 60)
        assert isinstance(events, dict)

        collected = runner.collect(session_id)
        assert isinstance(collected, dict)

        runner.destroy(session_id)  # 应不抛异常


class TestBehaviorAnalyzerContract:
    """BehaviorAnalyzer 契约测试"""

    def test_protocol_exists(self) -> None:
        """BehaviorAnalyzer Protocol 已定义。"""
        assert BehaviorAnalyzer is not None

    def test_protocol_has_analyze_method(self) -> None:
        """BehaviorAnalyzer 必须包含 analyze 方法。"""
        assert hasattr(BehaviorAnalyzer, "analyze")

    def test_minimal_implementation_satisfies_protocol(self) -> None:
        """最小实现应满足 BehaviorAnalyzer 契约。"""

        class _MinAnalyzer:
            def analyze(self, events: dict[str, Any]) -> dict[str, Any]:
                return {
                    "behavior_summary": "test",
                    "technical_capabilities": [],
                    "risk_score": 0,
                    "family_attribution": "unknown",
                    "disposal_suggestions": [],
                }

        analyzer = _MinAnalyzer()
        result = analyzer.analyze({"events": []})
        assert isinstance(result, dict)
        assert "behavior_summary" in result
        assert "risk_score" in result
