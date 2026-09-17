"""测试模块：shell.run 的 cmd 引号缺陷修复（P1-4 回归门禁）。

实测背景（2026-09-15，Windows 客机同一文件）：
    ``certutil -hashfile "C:\\work\\samples\\keylogger.exe" SHA256``
      → rc=2147942402（0x80070002 FILE_NOT_FOUND）❌
    ``certutil -hashfile C:\\work\\samples\\keylogger.exe SHA256``
      → rc=0，hash ``b2a99205…02b3c`` ✅
根因：``subprocess.run(["cmd.exe", "/c", command])`` 在 Windows 走 list2cmdline，
内嵌 ``"`` 被转义成 ``\\"``，而 cmd.exe 不认这种转义 → 路径被破坏成不存在的路径。

修复契约（本测试锁定）：
1. cmd 分支命令含内嵌引号时，命令原文落到临时 .bat，``cmd.exe /c <bat>`` 执行
   （不做任何转义改写，引号原样保留）；
2. 临时脚本执行后被清理（不留残留）；
3. 无内嵌引号的命令维持原 argv 形态（行为兼容）；
4. powershell 分支不变（argv 列表，无临时文件）。
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from winreverse.engine.tools import shell_tools
from winreverse.engine.tools.shell_tools import ShellRunTool

_QUOTED_CMD = 'certutil -hashfile "C:\\work\\samples\\keylogger.exe" SHA256'


def _capturing_run(captured: list[Any], payloads: dict[str, str]):
    """subprocess.run 打桩：记录 argv，并在执行时读取 .bat 内容。"""

    def _run(argv: Any, **kwargs: Any):
        captured.append(argv)
        if isinstance(argv, list) and argv[0] == "cmd.exe" and len(argv) > 2:
            script = Path(argv[2])
            if script.suffix == ".bat":
                payloads["content"] = script.read_bytes().decode("utf-8", errors="replace")
                payloads["existed"] = "1"
        return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

    return _run


class TestCmdQuotingFix:
    """含引号路径必须原样交给 cmd.exe。"""

    def test_quoted_path_goes_through_temp_bat_unchanged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: list[Any] = []
        payloads: dict[str, str] = {}
        monkeypatch.setattr(shell_tools.subprocess, "run", _capturing_run(captured, payloads))

        result = ShellRunTool().execute({"command": _QUOTED_CMD})

        assert result["status"] != "error", result
        argv = captured[0]
        assert argv[:2] == ["cmd.exe", "/c"]
        script_path = Path(argv[2])
        assert script_path.suffix == ".bat"
        # 命令原文（含双引号）必须一字不改地写进脚本
        assert _QUOTED_CMD in payloads.get("content", "")
        assert '\\"' not in payloads.get("content", ""), '引号不得被转义成 \\"'

    def test_temp_script_is_removed_after_run(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: list[Any] = []
        payloads: dict[str, str] = {}
        monkeypatch.setattr(shell_tools.subprocess, "run", _capturing_run(captured, payloads))

        ShellRunTool().execute({"command": _QUOTED_CMD})

        assert payloads.get("existed") == "1", "执行时必须已经落盘"
        assert not Path(captured[0][2]).exists(), "执行后临时脚本应被清理"

    def test_temp_script_removed_even_on_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: list[Any] = []

        def _raise_timeout(argv: Any, **kwargs: Any):
            captured.append(argv)
            raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs["timeout"])

        monkeypatch.setattr(shell_tools.subprocess, "run", _raise_timeout)
        result = ShellRunTool().execute({"command": _QUOTED_CMD, "timeout": 1})

        assert result["timed_out"] is True
        assert not Path(captured[0][2]).exists(), "超时分支同样要清理临时脚本"

    def test_command_without_quotes_keeps_original_argv(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: list[Any] = []
        monkeypatch.setattr(shell_tools.subprocess, "run", _capturing_run(captured, {}))

        ShellRunTool().execute({"command": "dir /b"})

        assert captured[0] == ["cmd.exe", "/c", "dir /b"], "无引号命令的行为必须保持原样"

    def test_powershell_branch_unchanged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: list[Any] = []
        monkeypatch.setattr(shell_tools.subprocess, "run", _capturing_run(captured, {}))

        ShellRunTool().execute(
            {
                "command": 'Get-FileHash -Algorithm SHA256 "C:\\work\\samples\\k.exe"',
                "shell": "powershell",
            }
        )

        argv = captured[0]
        assert argv[:3] == ["powershell.exe", "-NoProfile", "-NonInteractive"]
        assert argv[-1].count('"') == 2, "powershell 分支不落 .bat，命令原文直接传参"


class TestScriptHelpers:
    """临时脚本辅助函数的单元行为。"""

    def test_needs_cmd_script(self) -> None:
        assert shell_tools._needs_cmd_script(_QUOTED_CMD) is True
        assert shell_tools._needs_cmd_script("dir /b") is False

    def test_write_cmd_script_roundtrip(self, tmp_path: Path) -> None:
        path = shell_tools._write_cmd_script('echo "hello world"')
        try:
            text = path.read_bytes().decode("utf-8", errors="replace")
            assert text.startswith("@echo off\r\n")
            assert 'echo "hello world"' in text
            assert text.rstrip().endswith("exit /b %errorlevel%")
        finally:
            path.unlink(missing_ok=True)

    def test_script_encoding_non_windows_is_utf8(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """非 Windows 平台回退 utf-8（Windows 上走 mbcs，见下条）。"""
        monkeypatch.setattr(shell_tools.os, "name", "posix")

        assert shell_tools._script_encoding() == "utf-8"

    def test_script_encoding_windows_uses_mbcs(self) -> None:
        """Windows（os.name == 'nt'）用 mbcs，即 cmd.exe 当前 ANSI 代码页。"""
        if shell_tools.os.name != "nt":
            pytest.skip("仅 Windows 验证 mbcs 分支")

        assert shell_tools._script_encoding() == "mbcs"

    def test_write_cmd_script_unlinks_and_raises_on_oserror(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """写盘失败 → 清理临时文件并抛 OSError（不留垃圾、不静默）。"""
        created: list[Path] = []
        real_mkstemp = shell_tools.tempfile.mkstemp

        def _tracking_mkstemp(*args: Any, **kwargs: Any) -> Any:
            fd, raw = real_mkstemp(*args, **kwargs)
            created.append(Path(raw))
            return fd, raw

        def _boom(self: Path, *args: Any, **kwargs: Any) -> int:
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(shell_tools.tempfile, "mkstemp", _tracking_mkstemp)
        monkeypatch.setattr(Path, "write_bytes", _boom)

        with pytest.raises(OSError):
            shell_tools._write_cmd_script("dir /b")

        assert created and not created[0].exists(), "失败时必须删除临时 .bat"
