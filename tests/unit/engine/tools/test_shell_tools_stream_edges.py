"""被测模块: winreverse.engine.tools.shell_tools（ShellRunTool 输出流边角语义）。

覆盖点: truncated 标志仅由 stdout 的 UTF-8 字节数判定（stderr 单独超限不置位）、
stdout/stderr 为 None 时回落空串、shell 名大小写归一化（"CMD" → cmd.exe argv）。
winreverse.engine.tools 包导入链缺 die/yara 等 Windows 运行时依赖 → Linux 下如实报
collection error（基线接受态），待 Windows 实机（依赖就位）实跑回填。
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from winreverse.engine.tools import shell_tools
from winreverse.engine.tools.shell_tools import ShellRunTool

_TRUNC = 64 * 1024


class TestStreamEdgeSemantics:
    """stdout/stderr 流处理边角（subprocess.run 打桩，双平台等价）。"""

    def test_stderr_overflow_alone_does_not_flag_truncated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """truncated 只反映 stdout 溢出；stderr 单独超限仅被切片，不置位标志。"""

        def _run(argv: list[str], **kwargs: Any):
            return SimpleNamespace(returncode=0, stdout="ok", stderr="x" * (_TRUNC + 1))

        monkeypatch.setattr(shell_tools.subprocess, "run", _run)
        result = ShellRunTool().execute({"command": "echo hi"})

        assert result["returncode"] == 0
        assert len(result["stderr"]) == _TRUNC
        assert result["truncated"] is False
        assert result["stdout"] == "ok"

    def test_none_streams_fall_back_to_empty_strings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _run(argv: list[str], **kwargs: Any):
            return SimpleNamespace(returncode=0, stdout=None, stderr=None)

        monkeypatch.setattr(shell_tools.subprocess, "run", _run)
        result = ShellRunTool().execute({"command": "ver"})

        assert result["stdout"] == ""
        assert result["stderr"] == ""
        assert result["truncated"] is False

    def test_uppercase_shell_name_is_normalized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[list[str]] = []

        def _run(argv: list[str], **kwargs: Any):
            seen.append(argv)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(shell_tools.subprocess, "run", _run)
        result = ShellRunTool().execute({"command": "dir", "shell": "CMD"})

        assert result["returncode"] == 0
        assert seen[0][:2] == ["cmd.exe", "/c"]
