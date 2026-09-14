"""回归：memory.regions 在"枚举到 0 个已提交区域"时必须 fail-closed。

来源（2026-09-14 真机实测）：attach 成功的句柄在目标进程退出后,
`enumerate_regions` 会静默返回空列表；旧行为把空结果当"无可疑注入区域"上报
（status=success, total=0）——取证链上的**假阴性**证据。
本轮修复与 memory.dump 的 2026-09-12 fail-closed 修复同口径：直接报错。

进程会话通过向 memory_tools._sessions 注入 MagicMock 模拟，不依赖真实进程。
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from winreverse.core import memdump_api
from winreverse.core.memdump_api import MEM_FREE, MEM_RESERVE, MemoryRegion
from winreverse.engine.tools import memscan_tools
from winreverse.engine.tools.memory_tools import _clear_sessions, _sessions

PID = 4242


@pytest.fixture
def attached_session() -> MagicMock:
    """向会话表注入一个已附加进程的 mock Pymem（用后清理）。"""
    pm = MagicMock()
    pm.process_handle = 1234
    _sessions[PID] = pm
    yield pm
    _clear_sessions()


class TestMemoryRegionsFailClosed:
    """空枚举结果不得当作成功上报。"""

    def test_zero_regions_reports_error(
        self, attached_session: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """句柄无效 / 目标已退出时的空列表 → status=error 且提示可定位。"""
        monkeypatch.setattr(
            memdump_api, "enumerate_regions", lambda handle, only_committed=True: []
        )

        result = memscan_tools.MemoryRegionsTool().execute({"pid": PID})

        assert result["status"] == "error"
        assert "未枚举到任何已提交内存区域" in result["error_message"]
        assert f"pid={PID}" in result["error_message"]

    def test_uncommitted_only_reports_error(
        self, attached_session: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """仅返回 reserve/free 区域（无 MEM_COMMIT）同样视为无效枚举。"""
        regions = [
            MemoryRegion(0x1000, 0x1000, MEM_RESERVE, 0, 0),
            MemoryRegion(0x2000, 0x1000, MEM_FREE, 0, 0),
        ]
        monkeypatch.setattr(
            memdump_api, "enumerate_regions", lambda handle, only_committed=True: regions
        )

        result = memscan_tools.MemoryRegionsTool().execute({"pid": PID})

        assert result["status"] == "error"
        assert "未枚举到任何已提交内存区域" in result["error_message"]

    def test_single_committed_region_still_succeeds(
        self, attached_session: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """非空枚举保持原有成功语义（回归护栏，避免误伤正常路径）。"""
        from winreverse.core.memdump_api import MEM_COMMIT, MEM_PRIVATE, PAGE_READWRITE

        regions = [MemoryRegion(0x1000, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE)]
        monkeypatch.setattr(
            memdump_api, "enumerate_regions", lambda handle, only_committed=True: regions
        )

        result = memscan_tools.MemoryRegionsTool().execute({"pid": PID, "include_all": True})

        assert result["status"] == "success"
        assert result["total"] == 1
