"""被测模块: winreverse.core.memdump_api（区域分类纯逻辑 + 转储清单构建）。

覆盖点: MemoryRegion 提交/私有/映像/映射/可执行判定、protect_name 修饰位后缀、
is_suspicious 注入判定规则、to_dict 十六进制地址、_select_regions 过滤、
_region_file_name、_write_manifest 落盘结构。
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


class TestMemoryRegionClassification:
    """MemoryRegion 分类判定（取证判定规则的真实行为锁）。"""

    def test_private_rwx_is_suspicious(self) -> None:
        """私有可执行内存是注入/shellcode 最强信号，必须判可疑。"""
        region = _region()
        assert region.is_committed and region.is_private and region.is_executable
        assert region.is_suspicious is True
        assert region.protect_name == "RWX"
        assert region.type_name == "private"

    def test_private_rx_is_suspicious_even_without_write(self) -> None:
        """私有 + 可执行即判可疑（规则 1 不要求可写）。"""
        region = _region(protect=md.PAGE_EXECUTE_READ)
        assert region.is_suspicious is True
        assert region.is_writable is False
        assert region.protect_name == "RX"

    def test_image_region_is_not_suspicious(self) -> None:
        """模块映像区（含 SEC_IMAGE 变体）可执行但不算可疑。"""
        for image_type in (md.MEM_IMAGE, md.MEM_IMAGE_SEC):
            region = _region(type=image_type, protect=md.PAGE_EXECUTE_READ)
            assert region.is_image is True
            assert region.type_name == "image"
            assert region.is_suspicious is False

    def test_rwx_in_nonprivate_mapped_is_suspicious(self) -> None:
        """任意 RWX（含映射区）判可疑（规则 2）。"""
        region = _region(type=md.MEM_MAPPED)
        assert region.is_mapped is True
        assert region.is_suspicious is True
        assert region.type_name == "mapped"

    def test_reserved_memory_never_suspicious(self) -> None:
        """未提交（reserve）区域不可执行，不应误报。"""
        region = _region(state=md.MEM_RESERVE)
        assert region.is_committed is False
        assert region.is_suspicious is False

    def test_guard_page_suffix_and_base_protection(self) -> None:
        """GUARD/NOCACHE 修饰位进 protect_name 后缀，基本保护剥离后判定。"""
        region = _region(protect=md.PAGE_READWRITE | md.PAGE_GUARD)
        assert region.protect_name == "RW+GUARD"
        assert region.is_writable is True
        assert region.is_executable is False

    def test_unknown_values_fall_back_to_hex(self) -> None:
        """未登记的保护/类型值回落十六进制表示而非抛错。"""
        region = _region(protect=0x3F, type=0x1234)
        assert region.protect_name == "0x3F"
        assert region.type_name == "0x1234"

    def test_to_dict_addresses_as_hex(self) -> None:
        """to_dict 输出十六进制地址字符串，suspicious 与判定一致。"""
        payload = _region().to_dict()
        assert payload["base_address"] == "0x7FF60000"
        assert payload["size"] == 0x10000
        assert payload["suspicious"] is True


class TestSelectRegions:
    """dump_process 的区域过滤纯函数。"""

    def _sample_regions(self) -> list:
        return [
            _region(base_address=0x10000, size=0x20000),  # 私有 RWX → 选中
            _region(base_address=0x20000, size=0x10, protect=md.PAGE_READWRITE),  # 小于 min_size
            _region(base_address=0x30000, type=md.MEM_IMAGE, protect=md.PAGE_EXECUTE_READ),
            _region(base_address=0x40000, type=md.MEM_MAPPED, protect=md.PAGE_READONLY),
            _region(base_address=0x50000, state=md.MEM_FREE, protect=0, type=0),  # 空闲
            _region(base_address=0x60000, type=0, protect=md.PAGE_READWRITE),  # 无类型 → 排除
        ]

    def test_private_only_filter(self) -> None:
        selected = md._select_regions(
            self._sample_regions(),
            include_images=False,
            include_mapped=False,
            include_private=True,
            min_size=0x1000,
        )
        assert [r.base_address for r in selected] == [0x10000]

    def test_include_images_and_mapped(self) -> None:
        selected = md._select_regions(
            self._sample_regions(),
            include_images=True,
            include_mapped=True,
            include_private=True,
            min_size=0x1000,
        )
        assert [r.base_address for r in selected] == [0x10000, 0x30000, 0x40000]


class TestManifestBuilding:
    """区域文件名与 manifest.json 落盘结构。"""

    def test_region_file_name_format(self) -> None:
        assert md._region_file_name(3, 0x7FF60000) == "region_0003_00007ff60000.bin"

    def test_write_manifest_structure(self, tmp_path: Path) -> None:
        region = _region()
        entries = [
            md._RegionDumpEntry(
                file="region_0000_00007ff60000.bin",
                region=region,
                sha256="ab" * 32,
                size=0x10000,
            )
        ]
        md._write_manifest(tmp_path, entries, {"pid": 4242})
        manifest = json.loads((tmp_path / md._MANIFEST_NAME).read_text(encoding="utf-8"))
        assert manifest["schema_version"] == md._MANIFEST_SCHEMA_VERSION
        assert manifest["tool"] == "winreverse-memdump"
        assert manifest["pid"] == 4242
        assert "created_at" in manifest
        entry = manifest["regions"][0]
        assert entry["base_address"] == "0x7FF60000"
        assert entry["protect"] == "RWX" and entry["type"] == "private"
        assert entry["suspicious"] is True and entry["truncated"] is False
        assert entry["sha256"] == "ab" * 32
