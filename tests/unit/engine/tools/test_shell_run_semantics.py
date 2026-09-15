"""被测模块: winreverse.engine.tools.shell_tools（ShellRunTool 返回语义与守卫次序）。

覆盖点: 非零返回码置 status=error、cwd 解析透传 / 空值置 None、truncated 按UTF-8字节
判定（多字节超限而字符数未超限的边界）、拦截先于执行（subprocess 零调用）、
_check_dangerous 首个命中模式、_yolo_enabled 假值矩阵、SHELL_TOOLS 注册表导出。
winreverse.engine.tools 包导入链缺 die/yara 等 Windows 运行时依赖 → Linux 下如实报
collection error（基线接受态），待 Windows 实机（依赖就位）实跑回填。
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from winreverse.engine.tools import shell_tools
from winreverse.engine.tools.shell_tools import SHELL_TOOLS, ShellRunTool

_TRUNC = 64 * 1024


def _fake_run(stdout: str = "ok", returncode: int = 0, capture: list[Any] | None = None):
    def _run(argv: list[str], **kwargs: Any):
        if capture is not None:
            capture.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="")

    return _run


class TestReturnCodeSemantics:
    """返回码 → status 语义（BaseTool 只在异常置 error，非零码由此处补标）。"""

    def test_nonzero_returncode_marks_status_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shell_tools.subprocess, "run", _fake_run(returncode=3))
        result = ShellRunTool().execute({"command": "dir missing"})
        assert result["status"] == "error"
        assert result["returncode"] == 3
        assert result["command"] == "dir missing"
        assert result["shell"] == "cmd"

    def test_zero_returncode_keeps_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shell_tools.subprocess, "run", _fake_run(returncode=0))
        result = ShellRunTool().execute({"command": "echo ok"})
        assert result["status"] == "success"
        assert result["truncated"] is False


class TestCwdHandling:
    """cwd 解析：相对路径 resolve 为绝对路径字符串；空值不下发 cwd。"""

    def test_relative_cwd_resolved_to_absolute(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: list[Any] = []
        monkeypatch.setattr(shell_tools.subprocess, "run", _fake_run(capture=captured))
        ShellRunTool().execute({"command": "dir", "cwd": "."})
        _, kwargs = captured[0]
        assert kwargs["cwd"] == str(Path(".").resolve())

    def test_empty_cwd_is_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: list[Any] = []
        monkeypatch.setattr(shell_tools.subprocess, "run", _fake_run(capture=captured))
        ShellRunTool().execute({"command": "dir", "cwd": ""})
        _, kwargs = captured[0]
        assert kwargs["cwd"] is None


class TestTruncateFlagByteSemantics:
    """truncated 按 UTF-8 字节数判定，截断切片按字符——多字节下两者不对称。"""

    def test_multibyte_over_bytes_but_under_chars_is_truncated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # 40000 个 CJK 字符 = 120000 字节 > 64KB，但字符数 40000 < 64KB：
        # 切片截不掉它，标志仍必须置 True
        text = "字" * 40000
        monkeypatch.setattr(shell_tools.subprocess, "run", _fake_run(stdout=text))
        result = ShellRunTool().execute({"command": "type dump.bin"})
        assert result["truncated"] is True
        assert len(result["stdout"]) == 40000

    def test_exactly_64kb_is_not_truncated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shell_tools.subprocess, "run", _fake_run(stdout="A" * _TRUNC))
        result = ShellRunTool().execute({"command": "echo big"})
        assert result["truncated"] is False
        assert len(result["stdout"]) == _TRUNC


class TestGuardBeforeExecution:
    """拦截必须先于执行：命中危险模式时 subprocess 零调用。"""

    def test_blocked_command_never_reaches_subprocess(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("WINREVERSE_YOLO", raising=False)
        executed: list[Any] = []

        def _must_not_run(argv: list[str], **kwargs: Any):
            executed.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setattr(shell_tools.subprocess, "run", _must_not_run)
        result = ShellRunTool().execute({"command": "del /f C:\\x.txt"})
        assert result["status"] == "error"
        assert result["blocked_pattern"] == "del /f"
        assert "yolo" in result["error_message"]
        assert executed == []


class TestDangerousPatternMatch:
    """_check_dangerous 纯函数：按声明序返回首个命中模式。"""

    def test_first_declared_pattern_wins(self) -> None:
        command = "del /f x.txt & shutdown /r"
        assert ShellRunTool._check_dangerous(command) == "del /f"

    def test_benign_command_is_none(self) -> None:
        assert ShellRunTool._check_dangerous("dir /b & echo done") is None


class TestYoloFalsyValues:
    """_yolo_enabled 假值矩阵：未设置 / 0 / off 均不豁免。"""

    @pytest.mark.parametrize("env", [None, "0", "off", ""])
    def test_falsy_env_keeps_guard(self, env: str | None, monkeypatch: pytest.MonkeyPatch) -> None:
        if env is None:
            monkeypatch.delenv("WINREVERSE_YOLO", raising=False)
        else:
            monkeypatch.setenv("WINREVERSE_YOLO", env)
        assert ShellRunTool._yolo_enabled() is False
        result = ShellRunTool().execute({"command": "bcdedit /set x y"})
        assert result["blocked_pattern"] == "bcdedit"


class TestRegistryExport:
    """SHELL_TOOLS 注册表：单一 shell.run 实例（engine 聚合层依赖此导出）。"""

    def test_shell_tools_contains_single_shell_run(self) -> None:
        assert len(SHELL_TOOLS) == 1
        tool = SHELL_TOOLS[0]
        assert isinstance(tool, ShellRunTool)
        assert tool.name == "shell.run"
        assert tool.description
