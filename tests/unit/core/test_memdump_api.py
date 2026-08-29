"""测试模块：winreverse.core.memdump_api

覆盖：
- MemoryRegion 属性判定（状态/类型/保护/可疑标记/序列化）
- _select_regions 转储过滤逻辑
- _region_file_name 命名规则
- 自进程区域枚举 + 区域读取（windows_only，无需管理员）
- 自进程全量转储 + manifest 生成（windows_only）
- 自进程 minidump 转储（windows_only）
"""

from __future__ import annotations

import ctypes
import json
import sys
from pathlib import Path

import pytest

from winreverse.core import memdump_api
from winreverse.core.memdump_api import (
    MEM_COMMIT,
    MEM_IMAGE,
    MEM_MAPPED,
    MEM_PRIVATE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_NOACCESS,
    PAGE_READONLY,
    PAGE_READWRITE,
    DumpResult,
    MemoryRegion,
    dump_minidump,
    dump_process,
    enumerate_regions,
    read_region,
)

# =============================================================================
# MemoryRegion 属性判定
# =============================================================================


class TestMemoryRegion:
    """MemoryRegion 数据模型测试。"""

    def test_private_executable_is_suspicious(self) -> None:
        """私有可执行内存是最强注入信号，必须标记可疑。"""
        region = MemoryRegion(
            base_address=0x10000,
            size=0x1000,
            state=MEM_COMMIT,
            protect=PAGE_EXECUTE_READWRITE,
            type=MEM_PRIVATE,
        )
        assert region.is_suspicious is True
        assert region.is_executable is True
        assert region.is_writable is True
        assert region.is_private is True
        assert region.protect_name == "RWX"
        assert region.type_name == "private"

    def test_image_rx_is_not_suspicious(self) -> None:
        """正常模块的 RX 映像区域不应误报。"""
        region = MemoryRegion(
            base_address=0x7FF000000000,
            size=0x100000,
            state=MEM_COMMIT,
            protect=PAGE_EXECUTE_READ,
            type=MEM_IMAGE,
            mapped_file="C:\\Windows\\System32\\ntdll.dll",
        )
        assert region.is_suspicious is False
        assert region.is_image is True
        assert region.is_executable is True
        assert region.is_writable is False
        assert region.protect_name == "RX"
        assert region.mapped_file == "C:\\Windows\\System32\\ntdll.dll"

    def test_image_rwx_is_suspicious(self) -> None:
        """映像区域出现 RWX（自修改/脱壳中）应标记可疑。"""
        region = MemoryRegion(
            base_address=0x7FF000000000,
            size=0x100000,
            state=MEM_COMMIT,
            protect=PAGE_EXECUTE_READWRITE,
            type=MEM_IMAGE,
        )
        assert region.is_suspicious is True

    def test_private_rw_is_not_suspicious(self) -> None:
        """普通私有读写内存（数据段/堆）不标记可疑。"""
        region = MemoryRegion(
            base_address=0x10000,
            size=0x10000,
            state=MEM_COMMIT,
            protect=PAGE_READWRITE,
            type=MEM_PRIVATE,
        )
        assert region.is_suspicious is False
        assert region.is_executable is False
        assert region.is_writable is True

    def test_non_committed_is_not_suspicious(self) -> None:
        """未提交内存不参与可疑判定。"""
        region = MemoryRegion(
            base_address=0x10000,
            size=0x10000,
            state=0x2000,  # MEM_RESERVE
            protect=PAGE_NOACCESS,
            type=MEM_PRIVATE,
        )
        assert region.is_committed is False
        assert region.is_suspicious is False

    def test_protect_name_with_guard(self) -> None:
        """GUARD 修饰位应体现在保护名后缀。"""
        region = MemoryRegion(
            base_address=0x10000,
            size=0x1000,
            state=MEM_COMMIT,
            protect=PAGE_READWRITE | 0x100,
            type=MEM_PRIVATE,
        )
        assert region.protect_name == "RW+GUARD"

    def test_unknown_type_name(self) -> None:
        """未知内存类型输出十六进制。"""
        region = MemoryRegion(
            base_address=0x10000,
            size=0x1000,
            state=MEM_COMMIT,
            protect=PAGE_READONLY,
            type=0x1,
        )
        assert region.type_name == "0x1"
        assert region.is_mapped is False

    def test_to_dict_addresses_as_hex(self) -> None:
        """to_dict 中地址输出为十六进制字符串。"""
        region = MemoryRegion(
            base_address=0x7FF000000000,
            size=0x100000,
            state=MEM_COMMIT,
            protect=PAGE_EXECUTE_READ,
            type=MEM_IMAGE,
        )
        d = region.to_dict()
        assert d["base_address"] == "0x7FF000000000"
        assert d["size"] == 0x100000
        assert d["protect"] == "RX"
        assert d["type"] == "image"
        assert d["suspicious"] is False


# =============================================================================
# 纯函数逻辑
# =============================================================================


def _make_region(
    base: int,
    size: int,
    *,
    committed: bool = True,
    mem_type: int = MEM_PRIVATE,
    protect: int = PAGE_READWRITE,
) -> MemoryRegion:
    """构造测试用区域。"""
    return MemoryRegion(
        base_address=base,
        size=size,
        state=MEM_COMMIT if committed else 0x2000,
        protect=protect,
        type=mem_type,
    )


class TestSelectRegions:
    """_select_regions 过滤逻辑测试。"""

    def test_filters_by_type_flags(self) -> None:
        """按类型开关过滤区域。"""
        regions = [
            _make_region(0x1000, 0x1000, mem_type=MEM_IMAGE),
            _make_region(0x2000, 0x1000, mem_type=MEM_MAPPED),
            _make_region(0x3000, 0x1000, mem_type=MEM_PRIVATE),
        ]
        result = memdump_api._select_regions(
            regions,
            include_images=False,
            include_mapped=False,
            include_private=True,
            min_size=0x1000,
        )
        assert [r.base_address for r in result] == [0x3000]

    def test_filters_small_regions(self) -> None:
        """小于 min_size 的区域被过滤。"""
        regions = [
            _make_region(0x1000, 0x100),
            _make_region(0x2000, 0x1000),
        ]
        result = memdump_api._select_regions(
            regions,
            include_images=True,
            include_mapped=True,
            include_private=True,
            min_size=0x1000,
        )
        assert [r.base_address for r in result] == [0x2000]

    def test_skips_non_committed(self) -> None:
        """未提交区域不参与转储。"""
        regions = [
            _make_region(0x1000, 0x1000, committed=False),
            _make_region(0x2000, 0x1000, committed=True),
        ]
        result = memdump_api._select_regions(
            regions,
            include_images=True,
            include_mapped=True,
            include_private=True,
            min_size=0x1000,
        )
        assert [r.base_address for r in result] == [0x2000]

    def test_unknown_type_skipped(self) -> None:
        """非 image/mapped/private 类型区域跳过。"""
        regions = [_make_region(0x1000, 0x1000, mem_type=0x1)]
        result = memdump_api._select_regions(
            regions,
            include_images=True,
            include_mapped=True,
            include_private=True,
            min_size=0x1000,
        )
        assert result == []


class TestRegionFileName:
    """_region_file_name 命名规则测试。"""

    def test_name_format(self) -> None:
        """文件名格式为 region_NNNN_0xBASE.bin（基地址 12 位十六进制）。"""
        assert memdump_api._region_file_name(3, 0x7FF000000000) == "region_0003_7ff000000000.bin"

    def test_name_ordering_by_index(self) -> None:
        """索引零填充保证字典序 = 枚举序。"""
        names = [memdump_api._region_file_name(i, 0x1000 * i) for i in range(20)]
        assert names == sorted(names)


# =============================================================================
# 自进程真实验证（windows_only，伪句柄，无需管理员）
# =============================================================================


def _get_own_process_handle() -> int:
    """获取当前进程伪句柄（-1，无需关闭）。"""
    assert sys.platform == "win32"
    return int(ctypes.windll.kernel32.GetCurrentProcess())


@pytest.mark.windows_only
class TestOwnProcessRealAccess:
    """对当前进程做真实内存访问（自进程伪句柄即可，无需管理员权限）。"""

    def test_enumerate_regions_own_process(self) -> None:
        """枚举自身进程应返回大量已提交区域，且包含 PE 映像。"""
        handle = _get_own_process_handle()
        regions = enumerate_regions(handle, only_committed=True)
        assert len(regions) > 10
        assert all(r.is_committed for r in regions)
        assert any(r.is_image for r in regions)
        # 映像区域应解析出映射文件路径
        image_with_file = [r for r in regions if r.is_image and r.mapped_file]
        assert image_with_file, "至少应有一个映像区域关联到文件路径"
        # 地址升序
        bases = [r.base_address for r in regions]
        assert bases == sorted(bases)

    def test_read_region_python_image_mz(self) -> None:
        """读取自身进程映像区域头部应能找到 'MZ'（PE 头落盘校验）。"""
        handle = _get_own_process_handle()
        regions = enumerate_regions(handle, only_committed=True)
        images = [r for r in regions if r.is_image and r.is_executable]
        assert images, "自身进程应包含可执行映像区域"
        # 从各可执行映像区域回溯其模块头（映像首区域为只读 PE 头），至少一个应为 MZ
        found_mz = False
        for exec_region in images[:20]:
            alloc_base = exec_region.allocation_base
            header_regions = [r for r in regions if r.base_address == alloc_base and r.is_image]
            for header_region in header_regions:
                data = read_region(handle, header_region, max_bytes=2)
                if data[:2] == b"MZ":
                    found_mz = True
                    break
            if found_mz:
                break
        assert found_mz, "映像模块头部应可读且以 MZ 开头"

    def test_dump_process_own_process(self, tmp_path: Path) -> None:
        """自进程全量转储应生成 manifest.json 与区域文件，且内容一致。"""
        handle = _get_own_process_handle()
        out_dir = tmp_path / "dump"
        result = dump_process(
            handle,
            out_dir,
            min_size=0x10000,  # 跳过碎片区，控制测试耗时
            max_region_size=1 * 1024 * 1024,
            max_total_bytes=8 * 1024 * 1024,
        )
        assert isinstance(result, DumpResult)
        assert result.region_count > 0
        assert result.dumped_count > 0
        assert result.total_bytes > 0
        manifest_path = Path(result.manifest_path)
        assert manifest_path.is_file()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert manifest["dumped_count"] == result.dumped_count
        assert len(manifest["regions"]) == result.dumped_count
        # 每个登记的区域文件都存在且大小一致
        for entry in manifest["regions"]:
            region_file = out_dir / entry["file"]
            assert region_file.is_file()
            assert region_file.stat().st_size == entry["size"]
        # 结果可序列化
        json.dumps(result.to_dict())

    def test_dump_minidump_own_process(self, tmp_path: Path) -> None:
        """自进程 minidump 应生成 MDMP 魔数的合法 .dmp 文件。"""
        handle = _get_own_process_handle()
        out_path = tmp_path / "own.dmp"
        result = dump_minidump(handle, 0, out_path)
        assert result.is_file()
        assert result.stat().st_size > 0
        assert result.read_bytes()[:4] == b"MDMP"


@pytest.mark.windows_only
def test_dump_process_rejects_existing_file_as_dir(tmp_path: Path) -> None:
    """输出目录指向已存在的普通文件时应报 MemoryAccessError。"""
    handle = _get_own_process_handle()
    existing_file = tmp_path / "occupied.txt"
    existing_file.write_text("占用路径", encoding="utf-8")
    with pytest.raises(memdump_api.MemoryAccessError, match="创建输出目录失败"):
        dump_process(handle, existing_file)
