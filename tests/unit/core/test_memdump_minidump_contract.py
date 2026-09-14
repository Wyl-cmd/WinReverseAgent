"""被测模块: winreverse.core.memdump_api（dump_minidump 契约）。

覆盖点: 非 Windows 平台守卫抛 MemoryAccessError、minidump 选项常量唯一性、
full_memory 开关对应的 dump_type 组合语义（常量层面）。
模块顶层 import pymem（Windows 运行时依赖）→ Linux 下如实报 collection
error（基线接受态），待 Windows 实机依赖就位后实跑回填。
"""

from __future__ import annotations

import sys

import pytest

from winreverse.core.memdump_api import (
    MINIDUMP_NORMAL,
    MINIDUMP_WITH_FULLMEMORY,
    MINIDUMP_WITH_HANDLE_DATA,
    dump_minidump,
)
from winreverse.core.memory_api import MemoryAccessError


class TestDumpMinidumpContract:
    """dump_minidump 平台守卫与选项常量契约。"""

    def test_non_windows_raises_memory_access_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """平台守卫：非 win32 一律抛 MemoryAccessError，不触碰输出路径。"""
        monkeypatch.setattr(sys, "platform", "linux")
        with pytest.raises(MemoryAccessError, match="仅支持 Windows"):
            dump_minidump(process_handle=0xDEADBEEF, pid=4242, output_path="unused.dmp")

    def test_dump_type_constants_are_distinct_bits(self) -> None:
        """选项常量必须互不重叠，full_memory 开关才有区分语义。"""
        assert MINIDUMP_NORMAL == 0x00000000
        assert MINIDUMP_WITH_FULLMEMORY & MINIDUMP_WITH_HANDLE_DATA == 0
        # 默认（full_memory=True）= 完整内存 | 句柄数据；False 归零为 NORMAL
        assert MINIDUMP_WITH_FULLMEMORY | MINIDUMP_WITH_HANDLE_DATA != MINIDUMP_NORMAL
