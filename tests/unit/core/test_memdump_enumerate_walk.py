"""被测模块: winreverse.core.memdump_api（enumerate_regions 地址空间遍历逻辑）。

覆盖点: VirtualQueryEx 失败即终止、零长度区域防死循环、起始地址跳过 NULL 页、
步进=base+size、mapped_file 仅对已提交映像/映射区查询、only_committed=False
保留 reserve/free。以模块级 _virtual_query / _get_mapped_file_name 打桩（不真调
Windows API），断言遍历与标注逻辑本身。
模块导入链含 ctypes.wintypes/pymem（Windows 专有）→ Linux 下如实报 collection
error（基线接受态），待 Windows 实机实跑回填。
"""

from __future__ import annotations

from typing import Any

import pytest

from winreverse.core import memdump_api as md


def _q(
    base: int, size: int, state: int, protect: int, mem_type: int, alloc: int = 0
) -> tuple[int, int, int, int, int, int]:
    return (base, size, state, protect, mem_type, alloc)


class TestEnumerateWalk:
    """enumerate_regions 遍历协议（真进程布局不可复现，故打桩锁分支）。"""

    def test_walk_terminates_on_failed_query_and_maps_fields(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[int] = []

        def fake_query(handle: int, address: int) -> Any:
            calls.append(address)
            if len(calls) == 1:
                return _q(0x10000, 0x2000, md.MEM_COMMIT, md.PAGE_READWRITE, md.MEM_PRIVATE, 0x10000)
            return None  # 第二次查询失败 → 终止

        monkeypatch.setattr(md, "_virtual_query", fake_query)
        regions = md.enumerate_regions(0xDEAD)
        assert len(regions) == 1
        region = regions[0]
        assert region.base_address == 0x10000
        assert region.size == 0x2000
        assert region.state == md.MEM_COMMIT
        assert region.protect == md.PAGE_READWRITE
        assert region.type == md.MEM_PRIVATE
        assert region.allocation_base == 0x10000

    def test_walk_starts_past_null_page(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[int] = []
        monkeypatch.setattr(
            md, "_virtual_query", lambda h, a: seen.append(a) or None
        )
        regions = md.enumerate_regions(0xDEAD)
        assert regions == []
        assert seen == [md._PAGE_SIZE], "必须从 NULL 页之后起步且查询失败立即收尾"

    def test_zero_size_region_skipped_without_hang(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_query(handle: int, address: int) -> Any:
            if address == md._PAGE_SIZE:
                return _q(0x1000, 0, md.MEM_COMMIT, md.PAGE_READWRITE, md.MEM_PRIVATE)
            if address == md._PAGE_SIZE + 0x1000:
                return _q(0x2000, 0x1000, md.MEM_COMMIT, md.PAGE_READWRITE, md.MEM_PRIVATE)
            return None

        monkeypatch.setattr(md, "_virtual_query", fake_query)
        regions = md.enumerate_regions(0xDEAD)
        assert [r.base_address for r in regions] == [0x2000], "零长度区跳过且步进一页防死循环"

    def test_step_is_base_plus_size(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[int] = []

        def fake_query(handle: int, address: int) -> Any:
            seen.append(address)
            if len(seen) == 1:
                return _q(0x10000, 0x3000, md.MEM_COMMIT, md.PAGE_READONLY, md.MEM_IMAGE)
            return None

        monkeypatch.setattr(md, "_virtual_query", fake_query)
        md.enumerate_regions(0xDEAD)
        assert seen == [md._PAGE_SIZE, 0x10000 + 0x3000]

    def test_mapped_file_queried_only_for_committed_image_or_mapped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        queried: list[int] = []

        def fake_mapped(handle: int, base: int) -> str:
            queried.append(base)
            return "C:\\Windows\\System32\\ntdll.dll"

        def fake_query(handle: int, address: int) -> Any:
            if address == md._PAGE_SIZE:
                return _q(md._PAGE_SIZE, 0x1000, md.MEM_COMMIT, md.PAGE_EXECUTE_READ, md.MEM_IMAGE)
            if address == 0x2000:
                return _q(0x2000, 0x1000, md.MEM_COMMIT, md.PAGE_READWRITE, md.MEM_PRIVATE)
            if address == 0x3000:
                return _q(0x3000, 0x1000, md.MEM_COMMIT, md.PAGE_READONLY, md.MEM_MAPPED)
            if address == 0x4000:
                return _q(0x4000, 0x1000, md.MEM_COMMIT, md.PAGE_READONLY, md.MEM_IMAGE_SEC)
            return None

        monkeypatch.setattr(md, "_virtual_query", fake_query)
        monkeypatch.setattr(md, "_get_mapped_file_name", fake_mapped)
        regions = md.enumerate_regions(0xDEAD)
        assert queried == [md._PAGE_SIZE, 0x3000, 0x4000], "私有区不查映射文件"
        by_base = {r.base_address: r for r in regions}
        assert by_base[md._PAGE_SIZE].mapped_file == "C:\\Windows\\System32\\ntdll.dll"
        assert by_base[0x2000].mapped_file == ""
        assert by_base[0x4000].is_image is True, "SEC_IMAGE 变体必须按映像处理"

    def test_only_committed_false_keeps_reserve_and_free(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_query(handle: int, address: int) -> Any:
            seq = {
                md._PAGE_SIZE: _q(
                    md._PAGE_SIZE, 0x1000, md.MEM_RESERVE, md.PAGE_NOACCESS, md.MEM_PRIVATE
                ),
                0x2000: _q(0x2000, 0x1000, md.MEM_FREE, md.PAGE_NOACCESS, 0),
            }
            return seq.get(address)

        monkeypatch.setattr(md, "_virtual_query", fake_query)
        regions = md.enumerate_regions(0xDEAD, only_committed=False)
        assert [r.state for r in regions] == [md.MEM_RESERVE, md.MEM_FREE]
        assert all(not r.is_committed for r in regions)
        assert md.enumerate_regions(0xDEAD) == [], "默认 only_committed=True 时全部过滤"
