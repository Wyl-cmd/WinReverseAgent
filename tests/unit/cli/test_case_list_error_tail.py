"""被测模块: winreverse.cli.case 的 list_cases 命令异常回落（真机 coverage 缺 77/79/80）。

覆盖点: manager.list_cases() 抛 CaseError 时命令打印错误并以退出码 1 终止，
单份损坏清单不得以 traceback 击穿整个列表命令（77 except / 79 打印 / 80 Exit）。
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

import winreverse.cli.case as case_module
from winreverse.cli import app as cli_app
from winreverse.forensics.case import CaseError

runner = CliRunner()


class _BrokenManager:
    """list_cases 恒抛 CaseError 的替身管理器。"""

    def list_cases(self) -> list:
        raise CaseError("清单文件损坏")


def test_list_cases_case_error_exits_gracefully(monkeypatch: pytest.MonkeyPatch) -> None:
    """list_cases 抛 CaseError → 打印错误消息并以退出码 1 结束，无 traceback。"""
    monkeypatch.setattr(case_module, "_get_manager", lambda: _BrokenManager())
    result = runner.invoke(cli_app, ["case", "list"])
    assert result.exit_code == 1
    assert "清单文件损坏" in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
