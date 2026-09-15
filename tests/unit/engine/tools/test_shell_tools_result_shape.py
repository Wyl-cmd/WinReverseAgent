"""被测模块: winreverse.engine.tools.shell_tools（ShellRunTool 结果形态与守卫假值边界）。

覆盖点: 非零返回码→status=error、成功结果全键形态、stderr 透传、cwd 解析为绝对路径
与缺省 None、默认/自定义 timeout 下发、WINREVERSE_YOLO 假值不豁免、
_check_dangerous 未命中返回 None。subprocess.run 全程打桩，双平台等价。
winreverse.engine.tools 包导入链缺 die/yara 等 Windows 运行时依赖 → Linux 下如实报
collection error（基线接受态），待 Windows 实机实跑回填。
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from winreverse.engine.tools import shell_tools
from winreverse.engine.tools.shell_tools import ShellRunTool


def _capture_run(
    stdout: str = "ok",
    stderr: str = "",
    returncode: int = 0,
    calls: list[dict[str, Any]] | None = None,
):
    """构造打桩 subprocess.run：记录 (argv, kwargs)，返回可控结果。"""

    def _run(argv: list[str], **kwargs: Any):
        if calls is not None:
            calls.append({"argv": argv, **kwargs})
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)

    return _run


class TestResultShape:
    """结果字典形态（返回码标注、全键、stderr）。"""

    def test_nonzero_returncode_marks_status_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shell_tools.subprocess, "run", _capture_run(returncode=3))
        result = ShellRunTool().execute({"command": "exit 3"})
        assert result["status"] == "error"
        assert result["returncode"] == 3

    def test_success_result_has_full_shape(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            shell_tools.subprocess,
            "run",
            _capture_run(stdout="out", stderr="err", returncode=0),
        )
        result = ShellRunTool().execute({"command": "ver", "shell": "cmd"})
        for key in ("command", "shell", "returncode", "stdout", "stderr", "truncated"):
            assert key in result
        assert result["command"] == "ver"
        assert result["shell"] == "cmd"
        assert result["stdout"] == "out"
        assert result["stderr"] == "err"
        assert result["truncated"] is False

    def test_stderr_content_passthrough(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            shell_tools.subprocess, "run", _capture_run(stderr="boom", returncode=1)
        )
        result = ShellRunTool().execute({"command": "bad"})
        assert result["stderr"] == "boom"


class TestInvocationParams:
    """cwd 与 timeout 的下发行为（kwargs 打桩捕获）。"""

    def test_cwd_resolved_to_absolute_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        calls: list[dict[str, Any]] = []
        monkeypatch.setattr(shell_tools.subprocess, "run", _capture_run(calls=calls))
        ShellRunTool().execute({"command": "cd", "cwd": str(tmp_path)})
        assert calls[0]["cwd"] == str(Path(str(tmp_path)).resolve())

    def test_no_cwd_passes_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[dict[str, Any]] = []
        monkeypatch.setattr(shell_tools.subprocess, "run", _capture_run(calls=calls))
        ShellRunTool().execute({"command": "cd"})
        assert calls[0]["cwd"] is None

    def test_default_timeout_is_120s(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[dict[str, Any]] = []
        monkeypatch.setattr(shell_tools.subprocess, "run", _capture_run(calls=calls))
        ShellRunTool().execute({"command": "ping -n 1 127.0.0.1"})
        assert calls[0]["timeout"] == 120

    def test_custom_timeout_forwarded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[dict[str, Any]] = []
        monkeypatch.setattr(shell_tools.subprocess, "run", _capture_run(calls=calls))
        ShellRunTool().execute({"command": "dir", "timeout": 5})
        assert calls[0]["timeout"] == 5


class TestYoloFalseValues:
    """WINREVERSE_YOLO 假值不得豁免危险命令守卫（真值放行已在 edges 文件覆盖）。"""

    @pytest.mark.parametrize("value", ["0", "false", "no", "", "off"])
    def test_falsy_yolo_still_blocks(self, value: str, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WINREVERSE_YOLO", value)
        result = ShellRunTool().execute({"command": "shutdown /s"})
        assert result["status"] == "error"
        assert result["blocked_pattern"] == "shutdown"


class TestCheckDangerous:
    """静态判定函数：未命中返回 None、命中返回模式本身。"""

    def test_clean_command_returns_none(self) -> None:
        assert ShellRunTool._check_dangerous("dir /b && echo done") is None

    def test_hit_returns_pattern(self) -> None:
        assert ShellRunTool._check_dangerous("shutdown /r") == "shutdown"
