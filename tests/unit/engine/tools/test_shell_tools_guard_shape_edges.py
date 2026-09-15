"""被测模块: winreverse.engine.tools.shell_tools（拦截结果形态 / yolo 取值表 / stderr 截断 / shell 名归一）。

覆盖点: 危险命令拦截返回 dict 的 blocked_pattern 字段与引导文案、WINREVERSE_YOLO
环境变量取值真值表（yes/True 大小写、0/空/未设）、仅 stderr 超限时 stdout 标志
truncated 不置位且 stderr 照截、shell 名大小写归一（PowerShell/CMD）。
全程 subprocess.run 打桩，不依赖真实 shell。
winreverse.engine.tools 包导入链缺 die/yara 等 Windows 运行时依赖 → Linux 下如实报
collection error（基线接受态），待 Windows 实机（依赖就位）实跑回填。
"""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from winreverse.engine.tools import shell_tools
from winreverse.engine.tools.shell_tools import ShellRunTool

_TRUNC = 64 * 1024


def _fake_run(
    stdout: str = "ok",
    stderr: str = "",
    returncode: int = 0,
    capture: list[Any] | None = None,
):
    def _run(argv: list[str], **kwargs: Any):
        if capture is not None:
            capture.append(argv)
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)

    return _run


class TestBlockedResultShape:
    """危险命令拦截分支的返回形态（非异常路径，status=error + blocked_pattern）。"""

    def test_blocked_result_carries_pattern_and_guidance(self) -> None:
        result = ShellRunTool().execute({"command": "format C: /q /x"})
        assert result["status"] == "error"
        assert result["blocked_pattern"] == "format "
        assert "已被拦截" in result["error_message"]
        assert "allow_dangerous=true" in result["error_message"]
        # 拦截不得演变成真实 subprocess 调用：无 returncode/stdout 字段
        assert "returncode" not in result
        assert "stdout" not in result


class TestYoloEnvTruthTable:
    """WINREVERSE_YOLO 环境变量取值真值表（与 config.agent.yolo 语义对齐）。"""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("1", True),
            ("true", True),
            ("YES", True),
            ("True", True),
            ("0", False),
            ("", False),
            ("off", False),
        ],
    )
    def test_values(self, monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool) -> None:
        monkeypatch.setenv("WINREVERSE_YOLO", raw)
        assert ShellRunTool._yolo_enabled() is expected

    def test_unset_is_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("WINREVERSE_YOLO", raising=False)
        assert ShellRunTool._yolo_enabled() is False

    def test_yolo_yes_bypasses_guard_without_allow_dangerous(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WINREVERSE_YOLO", "yes")
        capture: list[Any] = []
        monkeypatch.setattr(shell_tools.subprocess, "run", _fake_run(capture=capture))
        result = ShellRunTool().execute({"command": "rd /s C:\\x"})
        assert result["status"] != "error" or "blocked_pattern" not in result
        assert len(capture) == 1


class TestStderrOnlyOverflow:
    """仅 stderr 超限：stderr 照截到 64KB，truncated 标志只反映 stdout 保持 False。"""

    def test_big_stderr_clipped_but_flag_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            shell_tools.subprocess, "run", _fake_run(stdout="tiny", stderr="E" * (_TRUNC + 5))
        )
        result = ShellRunTool().execute({"command": "dir bad"})
        assert len(result["stderr"]) == _TRUNC
        assert result["truncated"] is False
        assert result["returncode"] == 0


class TestShellNameNormalization:
    """shell 名大小写归一：PowerShell/CMD 混合大小写均可路由到对应可执行文件。"""

    @pytest.mark.parametrize(
        ("shell", "expected_argv0"),
        [("PowerShell", "powershell.exe"), ("CMD", "cmd.exe"), ("Cmd", "cmd.exe")],
    )
    def test_case_insensitive_routing(
        self, monkeypatch: pytest.MonkeyPatch, shell: str, expected_argv0: str
    ) -> None:
        capture: list[Any] = []
        monkeypatch.setattr(shell_tools.subprocess, "run", _fake_run(capture=capture))
        result = ShellRunTool().execute({"command": "echo hi", "shell": shell})
        assert result["status"] != "error"
        assert capture[0][0] == expected_argv0
