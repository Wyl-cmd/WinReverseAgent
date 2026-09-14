"""被测模块: winreverse.core.memdump_api（DumpResult 摘要 / 修饰位后缀 / 清单标志位）。

覆盖点: DumpResult.to_dict 全字段、_protect_to_str 已知/未知值/修饰位剥离、
WRITECOPY 变体可写判定、NOCACHE/WC 修饰后缀及组合、mapped_file 透传 to_dict、
_select_regions include_private=False 与 min_size 闭边界、
manifest truncated/read_failed 标志位落盘、_RegionDumpEntry 默认值。
模块导入链含 ctypes.wintypes/pymem（Windows 专有）→ Linux 下如实报
collection error（基线接受态），待 Windows 实机实跑回填。
"""

from __future__ import annotations

import json
from pathlib import Path

from winreverse.core import memdump_api as md


def _region(**overrides):
    """构造已提交、私有、RWX 的基线区域，按需覆盖字段。"""
    fields = {
        "base_address": 0x7FF60000,
        "size": 0x10000,
        "state": md.MEM_COMMIT,
        "protect": md.PAGE_EXECUTE_READWRITE,
        "type": md.MEM_PRIVATE,
    }
    fields.update(overrides)
    return md.MemoryRegion(**fields)


class TestDumpResult:
    """全进程转储摘要的序列化。"""

    def test_to_dict_full_fields(self) -> None:
        result = md.DumpResult(
            output_dir="/tmp/dump",
            manifest_path="/tmp/dump/manifest.json",
            region_count=10,
            dumped_count=8,
            skipped_count=2,
            total_bytes=4096,
            suspicious_count=3,
            truncated_count=1,
        )
        payload = result.to_dict()
        assert payload == {
            "output_dir": "/tmp/dump",
            "manifest_path": "/tmp/dump/manifest.json",
            "region_count": 10,
            "dumped_count": 8,
            "skipped_count": 2,
            "total_bytes": 4096,
            "suspicious_count": 3,
            "truncated_count": 1,
        }

    def test_defaults_are_zero(self) -> None:
        payload = md.DumpResult(output_dir="o", manifest_path="m").to_dict()
        assert payload["dumped_count"] == 0
        assert payload["suspicious_count"] == 0
        assert payload["truncated_count"] == 0


class TestProtectToStr:
    """模块级保护属性格式化（与 MemoryRegion.protect_name 共用表）。"""

    def test_known_names(self) -> None:
        assert md._protect_to_str(md.PAGE_READONLY) == "R"
        assert md._protect_to_str(md.PAGE_READWRITE) == "RW"
        assert md._protect_to_str(md.PAGE_WRITECOPY) == "RC"
        assert md._protect_to_str(md.PAGE_EXECUTE) == "X"
        assert md._protect_to_str(md.PAGE_EXECUTE_WRITECOPY) == "RWC"

    def test_modifier_bits_are_stripped(self) -> None:
        assert md._protect_to_str(md.PAGE_READWRITE | md.PAGE_GUARD) == "RW"

    def test_unknown_value_falls_back_to_hex(self) -> None:
        assert md._protect_to_str(0x99) == "0x99"


class TestWritableVariants:
    """可写判定覆盖写拷贝变体（edges 文件只测了 RW/RWX）。"""

    def test_writecopy_is_writable(self) -> None:
        assert _region(protect=md.PAGE_WRITECOPY).is_writable is True

    def test_execute_writecopy_is_writable_and_executable(self) -> None:
        region = _region(protect=md.PAGE_EXECUTE_WRITECOPY)
        assert region.is_writable is True
        assert region.is_executable is True
        assert region.protect_name == "RWC"

    def test_readonly_is_not_writable(self) -> None:
        assert _region(protect=md.PAGE_READONLY).is_writable is False


class TestProtectSuffixes:
    """NOCACHE / WRITECOMBINE 修饰位后缀（GUARD 后缀已在既有文件覆盖）。"""

    def test_nocache_suffix(self) -> None:
        assert (
            _region(protect=md.PAGE_READONLY | md.PAGE_NOCACHE).protect_name
            == "R+NOCACHE"
        )

    def test_writecombine_suffix(self) -> None:
        assert (
            _region(protect=md.PAGE_READONLY | md.PAGE_WRITECOMBINE).protect_name
            == "R+WC"
        )

    def test_all_modifiers_combined_in_order(self) -> None:
        protect = (
            md.PAGE_READWRITE | md.PAGE_GUARD | md.PAGE_NOCACHE | md.PAGE_WRITECOMBINE
        )
        assert _region(protect=protect).protect_name == "RW+GUARD+NOCACHE+WC"


class TestMappedFilePassthrough:
    """映射文件路径在 to_dict 与 manifest 中透传。"""

    def test_to_dict_includes_mapped_file(self) -> None:
        region = _region(
            type=md.MEM_MAPPED,
            protect=md.PAGE_READONLY,
            mapped_file="\\Device\\HarddiskVolume3\\Windows\\system32\\kernel32.dll",
        )
        payload = region.to_dict()
        assert payload["mapped_file"].endswith("kernel32.dll")
        assert payload["type"] == "mapped"

    def test_private_region_defaults_to_empty_mapped_file(self) -> None:
        assert _region().to_dict()["mapped_file"] == ""


class TestSelectRegionsEdges:
    """过滤闭边界：include_private=False 与 min_size 恰好相等。"""

    def test_exclude_private_keeps_image_and_mapped(self) -> None:
        regions = [
            _region(base_address=0x10000),
            _region(base_address=0x20000, type=md.MEM_IMAGE, protect=md.PAGE_EXECUTE_READ),
            _region(base_address=0x30000, type=md.MEM_MAPPED, protect=md.PAGE_READONLY),
        ]
        selected = md._select_regions(
            regions,
            include_images=True,
            include_mapped=True,
            include_private=False,
            min_size=0x1000,
        )
        assert [r.base_address for r in selected] == [0x20000, 0x30000]

    def test_min_size_boundary_is_inclusive(self) -> None:
        regions = [
            _region(base_address=0x10000, size=0x1000),  # == min_size → 保留
            _region(base_address=0x20000, size=0xFFF),  # < min_size → 排除
        ]
        selected = md._select_regions(
            regions,
            include_images=True,
            include_mapped=True,
            include_private=True,
            min_size=0x1000,
        )
        assert [r.base_address for r in selected] == [0x10000]


class TestManifestFlags:
    """truncated / read_failed 标志位落盘与条目默认值。"""

    def test_entry_defaults(self) -> None:
        entry = md._RegionDumpEntry(file="a.bin", region=_region())
        assert entry.sha256 == ""
        assert entry.size == 0
        assert entry.truncated is False
        assert entry.read_failed is False

    def test_truncated_and_read_failed_roundtrip(self, tmp_path: Path) -> None:
        entries = [
            md._RegionDumpEntry(
                file="t.bin", region=_region(), size=0x10, truncated=True
            ),
            md._RegionDumpEntry(
                file="f.bin",
                region=_region(base_address=0x20000),
                size=0,
                read_failed=True,
            ),
        ]
        md._write_manifest(tmp_path, entries, {"pid": 7})
        manifest = json.loads(
            (tmp_path / md._MANIFEST_NAME).read_text(encoding="utf-8")
        )
        first, second = manifest["regions"]
        assert first["truncated"] is True and first["read_failed"] is False
        assert second["truncated"] is False and second["read_failed"] is True
        assert manifest["pid"] == 7
