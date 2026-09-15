"""被测模块: winreverse.core.memdump_api — dump_process 全进程转储编排 + _write_manifest。

覆盖点: 打桩模块级 enumerate_regions/read_region 后的编排语义——区域 bin 文件落盘与
manifest.json 字段（SHA256 / hex 地址 / protect / type / suspicious）、suspicious_count
统计全量枚举区域、max_total_bytes 预算耗尽跳过剩余区域、零转储 fail-closed（2026-09-12
修复锁）、输出目录创建失败映射 MemoryAccessError。
winreverse.core 包导入链缺 pymem 等 Windows 运行时依赖 → Linux 下如实报 collection
error（基线接受态），待 Windows 实机（依赖就位）实跑回填。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from winreverse.core import memdump_api as md


def _region(
    base: int,
    size: int,
    state: int,
    protect: int,
    type_: int,
    mapped_file: str = "",
) -> md.MemoryRegion:
    return md.MemoryRegion(
        base_address=base,
        size=size,
        state=state,
        protect=protect,
        type=type_,
        mapped_file=mapped_file,
    )


def _fake_read(handle: int, region: md.MemoryRegion, max_bytes: int | None = None) -> bytes:
    """按 read_region 的实际契约返回数据：受 max_bytes 预算限制。"""
    return b"\x90" * min(region.size, max_bytes if max_bytes is not None else region.size)


class TestDumpProcessOrchestration:
    """dump_process 编排语义（enumerate_regions / read_region 打桩，纯编排路径）。"""

    def test_happy_path_writes_bins_and_manifest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        suspicious = _region(
            0x10000, 0x2000, md.MEM_COMMIT, md.PAGE_EXECUTE_READWRITE, md.MEM_PRIVATE
        )
        image = _region(
            0x7FF600000000,
            0x1000,
            md.MEM_COMMIT,
            md.PAGE_READONLY,
            md.MEM_IMAGE,
            mapped_file=r"C:\Windows\System32\notepad.exe",
        )
        reserved = _region(0x400000, 0x100000, md.MEM_RESERVE, md.PAGE_READONLY, md.MEM_PRIVATE)
        regions = [suspicious, image, reserved]
        monkeypatch.setattr(md, "enumerate_regions", lambda handle, only_committed=True: regions)
        monkeypatch.setattr(md, "read_region", _fake_read)

        result = md.dump_process(0xDEADBEEF, tmp_path)

        assert result.output_dir == str(tmp_path)
        assert result.region_count == 3
        assert result.dumped_count == 2  # reserved 未入选
        assert result.skipped_count == 0
        assert result.total_bytes == suspicious.size + image.size
        assert result.truncated_count == 0
        # suspicious_count 统计全量枚举区域，而非仅已转储区域（reserved 不可执行不计）
        assert result.suspicious_count == 1

        manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["schema_version"] == "1.0"
        assert manifest["tool"] == "winreverse-memdump"
        assert manifest["dumped_count"] == 2
        r0, r1 = manifest["regions"]
        assert r0["file"] == md._region_file_name(0, suspicious.base_address)
        assert r0["base_address"] == "0x10000"
        assert r0["protect"] == "RWX"
        assert r0["type"] == "private"
        assert r0["suspicious"] is True
        assert r0["mapped_file"] == ""
        assert r0["truncated"] is False
        assert r0["read_failed"] is False
        assert r0["sha256"] == hashlib.sha256(b"\x90" * suspicious.size).hexdigest()
        assert r1["base_address"] == "0x7FF600000000"
        assert r1["type"] == "image"
        assert r1["mapped_file"] == r"C:\Windows\System32\notepad.exe"
        # bin 文件确实落盘且内容与 SHA256 一致
        assert (tmp_path / r0["file"]).read_bytes() == b"\x90" * suspicious.size

    def test_zero_dumped_fails_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """读取全空时必须报错而非写出空 manifest 假证据（2026-09-12 修复回归锁）。"""
        region = _region(0x10000, 0x2000, md.MEM_COMMIT, md.PAGE_READWRITE, md.MEM_PRIVATE)
        monkeypatch.setattr(md, "enumerate_regions", lambda handle, only_committed=True: [region])
        monkeypatch.setattr(md, "read_region", lambda handle, region, max_bytes=None: b"")

        with pytest.raises(md.MemoryAccessError) as excinfo:
            md.dump_process(123, tmp_path)

        message = str(excinfo.value)
        assert "未转储到任何内存区域" in message
        assert "区域总数 1" in message
        assert "候选 1" in message
        # fail-closed：不得留下 manifest.json 假证据
        assert not (tmp_path / "manifest.json").exists()

    def test_total_budget_exhaustion_skips_remaining(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        r0 = _region(0x10000, 0x4000, md.MEM_COMMIT, md.PAGE_READWRITE, md.MEM_PRIVATE)
        r1 = _region(0x20000, 0x4000, md.MEM_COMMIT, md.PAGE_READWRITE, md.MEM_PRIVATE)
        monkeypatch.setattr(md, "enumerate_regions", lambda handle, only_committed=True: [r0, r1])
        calls: list[tuple[int, int | None]] = []

        def _spy_read(handle: int, region: md.MemoryRegion, max_bytes: int | None = None) -> bytes:
            calls.append((region.base_address, max_bytes))
            return _fake_read(handle, region, max_bytes)

        monkeypatch.setattr(md, "read_region", _spy_read)

        result = md.dump_process(123, tmp_path, max_total_bytes=0x4000, max_region_size=0x4000)

        # r0 拿满预算 0x4000；r1 因总预算耗尽被跳过且不触发读取
        assert calls == [(0x10000, 0x4000)]
        assert result.dumped_count == 1
        assert result.skipped_count == 1
        assert result.total_bytes == 0x4000
        assert result.truncated_count == 0
        files = sorted(p.name for p in tmp_path.glob("region_*.bin"))
        assert files == [md._region_file_name(0, r0.base_address)]

    def test_output_dir_file_conflict_maps_to_memory_access_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """输出目录路径被同名文件占用 → mkdir 失败须映射为 MemoryAccessError。"""
        region = _region(0x10000, 0x2000, md.MEM_COMMIT, md.PAGE_READWRITE, md.MEM_PRIVATE)
        monkeypatch.setattr(md, "enumerate_regions", lambda handle, only_committed=True: [region])
        blocker = tmp_path / "blocker"
        blocker.write_bytes(b"x")

        with pytest.raises(md.MemoryAccessError, match="创建输出目录失败"):
            md.dump_process(123, blocker)


class TestWriteManifest:
    """_write_manifest 直测：summary 合并、区域条目序列化、UTF-8 无 BOM JSON。"""

    def test_manifest_contains_summary_and_region_entries(self, tmp_path: Path) -> None:
        region = _region(0x420000, 0x1000, md.MEM_COMMIT, md.PAGE_EXECUTE_READ, md.MEM_MAPPED)
        entry = md._RegionDumpEntry(
            file="region_0000_0000420000.bin",
            region=region,
            sha256="abc123",
            size=0x800,
            truncated=True,
            read_failed=False,
        )
        summary: dict[str, Any] = {"region_count": 7, "total_bytes": 0x800}

        md._write_manifest(tmp_path, [entry], summary)

        manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["schema_version"] == md._MANIFEST_SCHEMA_VERSION
        assert manifest["region_count"] == 7
        assert manifest["total_bytes"] == 0x800
        assert manifest["created_at"]  # ISO 时间戳由函数填充
        (item,) = manifest["regions"]
        assert item == {
            "file": "region_0000_0000420000.bin",
            "base_address": "0x420000",
            "size": 0x800,
            "protect": region.protect_name,
            "type": "mapped",
            "mapped_file": "",
            "suspicious": False,
            "truncated": True,
            "read_failed": False,
            "sha256": "abc123",
        }
