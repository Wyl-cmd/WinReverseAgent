"""被测模块: winreverse.engine.tools.shell_tools（ShellRunTool 异常与边界）。

覆盖点: 非法 shell / 缺参校验、超时分支、shell 缺失（FileNotFoundError→RuntimeError）、
64KB 输出截断与 truncated 标志、危险命令大小写不敏感与 yolo/allow_dangerous 放行、
cmd/powershell argv 形态。全程不依赖真实 cmd.exe（subprocess.run 打桩），双平台等价。
winreverse.engine.tools 包导入链缺 die/yara 等 Windows 运行时依赖 → Linux 下如实报 collection
error（基线接受态），待 Windows 实机（依赖就位）实跑回填。
"""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from winreverse.engine.tools import shell_tools
from winreverse.engine.tools.shell_tools import ShellRunTool

_TRUNC = 64 * 1024


def _fake_run(stdout: str = "ok", returncode: int = 0, capture: list[Any] | None = None):
    def _run(argv: list[str], **kwargs: Any):
        if capture is not None:
            capture.append(argv)
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="")

    return _run


class TestInputValidation:
    """入参校验（BaseTool._require + shell 白名单）。"""

    def test_missing_command_is_key_error(self) -> None:
        result = ShellRunTool().execute({})
        assert result["status"] == "error"
        assert "KeyError" in result["error_message"]
        assert "command" in result["error_message"]

    def test_unsupported_shell_is_value_error(self) -> None:
        result = ShellRunTool().execute({"command": "dir", "shell": "pwsh"})
        assert result["status"] == "error"
        assert "不支持的 shell" in result["error_message"]
        assert "pwsh" in result["error_message"]


class TestSubprocessFailureBranches:
    """subprocess 异常分支（打桩，双平台等价）。"""

    def test_timeout_returns_timed_out_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _raise_timeout(argv: list[str], **kwargs: Any):
            raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs["timeout"])

        monkeypatch.setattr(shell_tools.subprocess, "run", _raise_timeout)
        result = ShellRunTool().execute({"command": "ping -n 999 127.0.0.1", "timeout": 1})
        assert result["status"] == "error"
        assert result["timed_out"] is True
        assert "超时" in result["error_message"]
        assert ">1s" in result["error_message"]

    def test_missing_shell_becomes_runtime_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _raise_not_found(argv: list[str], **kwargs: Any):
            raise FileNotFoundError(2, "No such file", "cmd.exe")

        monkeypatch.setattr(shell_tools.subprocess, "run", _raise_not_found)
        result = ShellRunTool().execute({"command": "echo hi"})
        assert result["status"] == "error"
        assert "RuntimeError" in result["error_message"]
        assert "shell 不可用" in result["error_message"]


class TestOutputTruncation:
    """输出截断到 64KB 及 truncated 标志。"""

    def test_large_stdout_truncated_with_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shell_tools.subprocess, "run", _fake_run(stdout="A" * (_TRUNC + 10)))
        result = ShellRunTool().execute({"command": "echo big"})
        assert len(result["stdout"]) == _TRUNC
        assert result["truncated"] is True

    def test_small_output_not_truncated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shell_tools.subprocess, "run", _fake_run(stdout="tiny"))
        result = ShellRunTool().execute({"command": "echo tiny"})
        assert result["stdout"] == "tiny"
        assert result["truncated"] is False


class TestArgvShapes:
    """cmd / powershell 的 argv 构造（不真执行）。"""

    def test_cmd_argv(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: list[Any] = []
        monkeypatch.setattr(shell_tools.subprocess, "run", _fake_run(capture=captured))
        ShellRunTool().execute({"command": "dir /b"})
        assert captured[0] == ["cmd.exe", "/c", "dir /b"]

    def test_powershell_argv(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: list[Any] = []
        monkeypatch.setattr(shell_tools.subprocess, "run", _fake_run(capture=captured))
        ShellRunTool().execute({"command": "Get-Process", "shell": "powershell"})
        assert captured[0][0] == "powershell.exe"
        for flag in ("-NoProfile", "-NonInteractive", "-Command"):
            assert flag in captured[0]
        assert captured[0][-1] == "Get-Process"


class TestDangerousGuard:
    """危险命令守卫：大小写不敏感命中、双通道放行。"""

    def test_dangerous_pattern_is_case_insensitive(self) -> None:
        result = ShellRunTool().execute({"command": "FORMAT C: /Q"})
        assert result["status"] == "error"
        assert result["blocked_pattern"] == "format "
        assert "allow_dangerous=true" in result["error_message"]

    def test_allow_dangerous_bypasses_guard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("WINREVERSE_YOLO", raising=False)
        captured: list[Any] = []
        monkeypatch.setattr(shell_tools.subprocess, "run", _fake_run(capture=captured))
        result = ShellRunTool().execute(
            {"command": "format.com /?", "allow_dangerous": True}
        )
        assert result["status"] == "success"
        assert captured, "放行后必须真的下发执行"

    @pytest.mark.parametrize("value", ["1", "true", "yes", "YES"])
    def test_yolo_env_bypasses_guard(
        self, value: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # WINREVERSE_YOLO 放行危险命令 —— 必须打桩 subprocess，否则会真的下发
        # `shutdown /r`（真机上直接重启系统，导致测试自身把被测 VM 打掉）。
        monkeypatch.setenv("WINREVERSE_YOLO", value)
        captured: list[Any] = []
        monkeypatch.setattr(shell_tools.subprocess, "run", _fake_run(capture=captured))
        result = ShellRunTool().execute({"command": "shutdown /r"})
        assert "blocked_pattern" not in result
        assert result["returncode"] == 0
        assert captured, "放行后必须真的下发执行（此处由 subprocess 替身承接）"
        assert captured[0][-1] == "shutdown /r"
