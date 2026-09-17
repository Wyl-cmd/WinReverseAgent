"""测试模块：memdump_api 的非 Windows 平台守卫契约。

被测模块：``winreverse.core.memdump_api``（进程内存采集层）。
覆盖点：6 个 ``if sys.platform != "win32"`` 运行时守卫（真机 coverage L292/312/339/
394/447/577）——只读辅助函数返回安全默认值（``{}`` / ``""`` / ``None``），
采集主流程抛 ``MemoryAccessError``（中文提示，拒绝在非 Windows 平台误调 ctypes API）。
测法：monkeypatch ``sys.platform`` 模拟非 Windows 调用方（守卫为函数首语句，
打桩平台后不触碰任何 ctypes / 句柄参数），与 test_shell_cmd_quoting_fix.py 的
``os.name`` 打桩同一模式；不 skip、不注入假模块。

口径：memdump_api 顶层 ``import ctypes.wintypes``（Windows 专有）→ 本文件在
Linux 下如实报 collection error（基线接受态），待 Windows 实机（依赖就位）实跑回填。
"""

from __future__ import annotations

import sys

import pytest

from winreverse.core import memdump_api
from winreverse.core.memdump_api import MemoryAccessError

_FAKE_HANDLE = 0xDEAD  # 守卫为首语句，句柄值不会被使用


def _as_non_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """把 sys.platform 打桩为非 win32，触发被测守卫分支。"""
    monkeypatch.setattr(sys, "platform", "linux")


class TestNonWindowsGuardSafeDefaults:
    """只读辅助函数：非 Windows 平台必须返回安全默认值而非崩溃。"""

    def test_query_dos_device_map_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _as_non_windows(monkeypatch)

        assert memdump_api._query_dos_device_map() == {}

    def test_get_mapped_file_name_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _as_non_windows(monkeypatch)

        assert memdump_api._get_mapped_file_name(_FAKE_HANDLE, 0x400000) == ""

    def test_virtual_query_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _as_non_windows(monkeypatch)

        assert memdump_api._virtual_query(_FAKE_HANDLE, 0x400000) is None


class TestNonWindowsGuardRaises:
    """采集主流程：非 Windows 平台必须抛 MemoryAccessError（快速失败、可诊断）。"""

    def test_enumerate_regions_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _as_non_windows(monkeypatch)

        with pytest.raises(MemoryAccessError, match="内存区域枚举仅支持 Windows 平台"):
            memdump_api.enumerate_regions(_FAKE_HANDLE)

    def test_read_region_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _as_non_windows(monkeypatch)

        # region 参数在守卫之后才被使用，传 None 以聚焦守卫契约本身
        with pytest.raises(MemoryAccessError, match="内存读取仅支持 Windows 平台"):
            memdump_api.read_region(_FAKE_HANDLE, None)  # type: ignore[arg-type]

    def test_dump_process_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _as_non_windows(monkeypatch)

        # output_dir 同理：守卫先于任何目录/枚举操作触发
        with pytest.raises(MemoryAccessError, match="内存转储仅支持 Windows 平台"):
            memdump_api.dump_process(_FAKE_HANDLE, None)  # type: ignore[arg-type]
