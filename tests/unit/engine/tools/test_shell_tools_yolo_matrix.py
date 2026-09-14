"""被测模块: winreverse.engine.tools.shell_tools（ShellRunTool 守卫矩阵）。

覆盖点: _DANGEROUS_PATTERNS 全家族逐一命中且大小写不敏感、WINREVERSE_YOLO
真值变体（1/true/yes 不限大小写放行，0/空/no 不放行）、非法 shell 报 ValueError。
winreverse.engine.tools 包导入链缺 die/yara 等 Windows 运行时依赖 → Linux 下
如实报 collection error（基线接受态），待 Windows 实机依赖就位后实跑回填。
"""

from __future__ import annotations

import subprocess

import pytest

from winreverse.engine.tools import shell_tools
from winreverse.engine.tools.shell_tools import SHELL_TOOLS, ShellRunTool

_TOOL = ShellRunTool()


def _completed(returncode: int = 0, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class TestDangerousPatternMatrix:
    """_DANGEROUS_PATTERNS 每条模式都必须能拦住对应真实命令（防模式表笔误）。"""

    @pytest.mark.parametrize(
        ("pattern", "command"),
        [
            ("format ", "format C:"),
            ("rd /s", "rd /s C:\\temp"),
            ("rmdir /s", "rmdir /s C:\\temp"),
            ("del /f", "del /f C:\\pagefile.sys"),
            ("del /q", "del /q C:\\pagefile.sys"),
            ("erase /f", "erase /f C:\\data"),
            ("shutdown", "shutdown /r /t 0"),
            ("diskpart", "diskpart"),
            ("bcdedit", "bcdedit /set testsigning on"),
            ("cipher /w", "cipher /w:C:\\"),
            ("reg add hkey_local_machine", "reg add hkey_local_machine\\SOFTWARE /v x /d 1"),
            ("reg delete hkey_local_machine", "reg delete hkey_local_machine\\SOFTWARE /v x /f"),
            ("vssadmin delete", "vssadmin delete shadows /all"),
            ("wbadmin delete", "wbadmin delete catalog"),
            ("remove-item -recurse", "Remove-Item -Recurse C:\\logs"),
            ("remove-item -force", "Remove-Item -Force C:\\logs"),
            ("stop-computer", "Stop-Computer -Force"),
            ("restart-computer", "Restart-Computer"),
            ("taskkill /f /im lsass", "taskkill /F /IM lsass"),
            ("attrib -s -h", "attrib -s -h C:\\file.txt"),
        ],
    )
    def test_pattern_catches_realistic_command(self, pattern: str, command: str) -> None:
        assert ShellRunTool._check_dangerous(command) == pattern

    @pytest.mark.parametrize(
        "command",
        ["dir C:\\", "type foo.txt", "Get-Process", "reg query hkey_local_machine\\SOFTWARE"],
    )
    def test_safe_commands_pass(self, command: str) -> None:
        # reg query（只读）不在拦截表内；拦截表只针对破坏性写操作
        assert ShellRunTool._check_dangerous(command) is None


class TestYoloEnvVariants:
    """WINREVERSE_YOLO 环境变量真值变体：真值放行、假值保持拦截。"""

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "Yes", "yes"])
    def test_truthy_values_bypass_guard(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        monkeypatch.setenv("WINREVERSE_YOLO", value)
        calls: list[dict] = []

        def _fake_run(argv, **kwargs):
            calls.append({"argv": argv, **kwargs})
            return _completed(returncode=0, stdout="ok")

        monkeypatch.setattr(shell_tools.subprocess, "run", _fake_run)
        result = _TOOL._run({"command": "format C:"})
        assert result["returncode"] == 0
        assert "status" not in result  # 返回码 0 不标 error
        assert len(calls) == 1

    @pytest.mark.parametrize("value", ["0", "", "no", "off", "false"])
    def test_falsy_values_keep_guard(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        monkeypatch.setenv("WINREVERSE_YOLO", value)

        def _forbidden(argv, **kwargs):
            raise AssertionError("yolo 假值时危险命令不允许触达 subprocess")

        monkeypatch.setattr(shell_tools.subprocess, "run", _forbidden)
        result = _TOOL._run({"command": "del /f C:\\x"})
        assert result["status"] == "error"
        assert result["blocked_pattern"] == "del /f"

    def test_unset_env_keeps_guard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("WINREVERSE_YOLO", raising=False)
        assert ShellRunTool._yolo_enabled() is False
        assert _TOOL._run({"command": "shutdown /s"})["status"] == "error"


class TestShellValidation:
    """shell 字段校验：仅接受 cmd / powershell（大小写不敏感路由）。"""

    def test_unknown_shell_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="不支持的 shell"):
            _TOOL._run({"command": "echo hi", "shell": "bash"})

    def test_shell_uppercase_routes_to_powershell(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[list[str]] = []

        def _fake_run(argv, **kwargs):
            seen.append(argv)
            return _completed(returncode=0)

        monkeypatch.setattr(shell_tools.subprocess, "run", _fake_run)
        result = _TOOL._run({"command": "Get-Date", "shell": "PowerShell"})
        assert result["shell"] == "powershell"
        assert seen[0][0] == "powershell.exe"
        assert seen[0][:3] == ["powershell.exe", "-NoProfile", "-NonInteractive"]


class TestShellToolsExport:
    """SHELL_TOOLS 导出清单契约：恰好一个 shell.run 实例。"""

    def test_shell_tools_exports_single_run_tool(self) -> None:
        assert [t.name for t in SHELL_TOOLS] == ["shell.run"]
        assert all(isinstance(t, ShellRunTool) for t in SHELL_TOOLS)
