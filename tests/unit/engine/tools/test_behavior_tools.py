"""测试模块：winreverse.engine.tools.behavior_tools

覆盖点：behavior.monitor 的 runner 生命周期（prepare/run/collect/destroy）
与清理失败不吞报告、behavior.sandbox_check/wsb 的分支与默认输出路径。
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

try:
    import yara  # noqa: F401

    from winreverse.engine.tools.behavior_tools import (
        BEHAVIOR_TOOLS,
        BehaviorMonitorTool,
        BehaviorSandboxCheckTool,
        BehaviorSandboxWsbTool,
    )
except ModuleNotFoundError as exc:
    # 导入链 behavior_tools → forensics.behavior → yara_api，yara 缺失时整体跳过；
    # 用哨兵检查保证多个测试文件的跳过行为与收集顺序无关
    pytest.skip(f"平台依赖缺失，跳过 behavior_tools 测试：{exc}", allow_module_level=True)

_NS = "winreverse.engine.tools.behavior_tools"


class TestRegistry:
    """BEHAVIOR_TOOLS 注册清单。"""

    def test_unique_names(self) -> None:
        names = [t.name for t in BEHAVIOR_TOOLS]
        assert len(names) == len(set(names)) == 3


class TestBehaviorMonitorTool:
    """behavior.monitor：进程隔离后端的工具封装。"""

    def _patched_runner(self) -> MagicMock:
        runner = MagicMock()
        runner.prepare.return_value = "session-1"
        runner.collect.return_value = {"risk_score": 7, "processes": ["m.exe"]}
        return runner

    def test_full_lifecycle(self) -> None:
        runner = self._patched_runner()
        with patch(f"{_NS}.ProcessIsolationRunner", return_value=runner) as runner_cls:
            result = BehaviorMonitorTool().execute(
                {"sample_path": "/tmp/m.exe", "duration": "12", "poll_interval": "0.2"}
            )
        assert result == {"risk_score": 7, "processes": ["m.exe"], "status": "success"}
        runner.prepare.assert_called_once_with("/tmp/m.exe", {})
        runner.run.assert_called_once_with("session-1", duration=12)
        runner.collect.assert_called_once_with("session-1")
        runner.destroy.assert_called_once_with("session-1")
        # sessions_root 未提供 → 默认构造（仅 poll_interval）
        runner_cls.assert_called_once_with(poll_interval=0.2)

    def test_sessions_root_forwarded(self) -> None:
        runner = self._patched_runner()
        with patch(f"{_NS}.ProcessIsolationRunner", return_value=runner) as runner_cls:
            BehaviorMonitorTool().execute(
                {"sample_path": "/tmp/m.exe", "sessions_root": "/tmp/sessions"}
            )
        runner_cls.assert_called_once_with(sessions_root="/tmp/sessions", poll_interval=0.5)

    def test_destroy_failure_does_not_swallow_report(self) -> None:
        """清理失败（销毁残留进程异常）不影响报告返回。"""
        runner = self._patched_runner()
        runner.destroy.side_effect = RuntimeError("残留进程清理失败")
        with patch(f"{_NS}.ProcessIsolationRunner", return_value=runner):
            result = BehaviorMonitorTool().execute({"sample_path": "/tmp/m.exe"})
        assert result["status"] == "success"
        assert result["risk_score"] == 7

    def test_missing_sample_path_is_error(self) -> None:
        assert BehaviorMonitorTool().execute({})["status"] == "error"

    def test_runner_failure_is_error(self) -> None:
        runner = self._patched_runner()
        runner.run.side_effect = RuntimeError("样本运行超时")
        with patch(f"{_NS}.ProcessIsolationRunner", return_value=runner):
            result = BehaviorMonitorTool().execute({"sample_path": "/tmp/m.exe"})
        assert result["status"] == "error"
        assert "样本运行超时" in result["error_message"]


class TestBehaviorSandboxCheckTool:
    """behavior.sandbox_check：可用性检测分支。"""

    @pytest.mark.parametrize(
        ("available", "note_keyword"),
        [(True, "sandbox_wsb"), (False, "behavior.monitor")],
    )
    def test_note_matches_availability(self, available: bool, note_keyword: str) -> None:
        with patch(f"{_NS}.is_sandbox_available", return_value=available):
            result = BehaviorSandboxCheckTool().execute({})
        assert result["available"] is available
        assert note_keyword in result["note"]
        assert result["status"] == "success"


class TestBehaviorSandboxWsbTool:
    """behavior.sandbox_wsb：引爆配置生成。"""

    def test_custom_output_path_forwarded(self, tmp_path) -> None:
        sample = tmp_path / "m.exe"
        sample.write_bytes(b"MZ")
        out = tmp_path / "m.wsb"
        with patch(f"{_NS}.write_wsb_config", return_value=out) as write:
            result = BehaviorSandboxWsbTool().execute(
                {
                    "sample_path": str(sample),
                    "output_path": str(out),
                    "networking": True,
                    "logon_command": "start m.exe",
                }
            )
        assert result == {"wsb": str(out), "status": "success"}
        write.assert_called_once_with(
            str(sample),
            str(out),
            networking=True,
            mapped_folder=None,
            logon_command="start m.exe",
        )

    def test_default_output_under_behavior_sessions(self, tmp_path) -> None:
        """未指定 output_path 时落到 output/behavior_sessions 下。"""
        sample = tmp_path / "m.exe"
        sample.write_bytes(b"MZ")
        expected = tmp_path / "expected.wsb"
        with patch(f"{_NS}.write_wsb_config", return_value=expected) as write:
            BehaviorSandboxWsbTool().execute({"sample_path": str(sample)})
        args, kwargs = write.call_args
        assert "behavior_sessions" in args[1]
        assert kwargs["networking"] is False  # 默认关网络

    def test_invalid_sample_is_error(self, tmp_path) -> None:
        result = BehaviorSandboxWsbTool().execute(
            {"sample_path": str(tmp_path / "ghost.exe"), "output_path": str(tmp_path / "x.wsb")}
        )
        assert result["status"] == "error"
        assert "样本不存在" in result["error_message"]

    def test_missing_sample_param_is_error(self) -> None:
        assert BehaviorSandboxWsbTool().execute({})["status"] == "error"
