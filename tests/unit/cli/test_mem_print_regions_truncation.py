"""被测模块: winreverse.cli.mem（_print_regions）。
覆盖点: 区域表 >200 行时的截断提示弧（98 行），以及未超阈值时不提示的负控。
本机（Linux）导入 winreverse.cli 触 yara 链 → collection error = 基线接受态
（WINREVERSE_TASKS L5-L6 口径），待 Windows 实机依赖就位后实跑回填。
"""

from __future__ import annotations

import io
from types import SimpleNamespace

import pytest
from rich.console import Console

from winreverse.cli.mem import _print_regions

_TRUNCATE_NOTICE = "仅显示前 200 个"


def _fake_region(index: int) -> SimpleNamespace:
    return SimpleNamespace(
        base_address=0x00400000 + index * 0x1000,
        size=0x1000,
        protect_name="PAGE_EXECUTE_READWRITE",
        type_name="MEM_PRIVATE",
        mapped_file=None,
        is_executable=True,
        is_suspicious=True,
    )


def _capture_console(monkeypatch: pytest.MonkeyPatch) -> io.StringIO:
    buffer = io.StringIO()
    monkeypatch.setattr("winreverse.cli.mem.console", Console(file=buffer, width=200))
    return buffer


def test_regions_over_200_prints_truncation_notice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """201 个可执行区域 → 必须打印截断提示且注明总数。"""
    regions = [_fake_region(i) for i in range(201)]
    monkeypatch.setattr("winreverse.core.memdump_api.enumerate_regions", lambda *a, **k: regions)
    buffer = _capture_console(monkeypatch)
    pm_stub = SimpleNamespace(process_handle=0x1234)

    _print_regions("stub.exe", pm_stub, include_all=False)

    out = buffer.getvalue()
    assert _TRUNCATE_NOTICE in out
    assert "201" in out
    # 第 201 行的基地址不应出现在表格里（只渲染前 200 行）
    assert f"{0x00400000 + 200 * 0x1000:X}" not in out


def test_regions_within_200_no_truncation_notice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """未超阈值时不得误报截断提示（边界负控）。"""
    regions = [_fake_region(i) for i in range(200)]
    monkeypatch.setattr("winreverse.core.memdump_api.enumerate_regions", lambda *a, **k: regions)
    buffer = _capture_console(monkeypatch)
    pm_stub = SimpleNamespace(process_handle=0x1234)

    _print_regions("stub.exe", pm_stub, include_all=False)

    assert _TRUNCATE_NOTICE not in buffer.getvalue()
