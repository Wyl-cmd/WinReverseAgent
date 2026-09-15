"""winreverse.core.memdump_api — 进程内存采集层（内存取证第一阶段）。

职责：
1. 枚举进程虚拟内存区域（VirtualQueryEx），标注保护属性 / 类型 / 映射文件
2. 识别可疑区域（无映像 backing 的可执行内存 → 注入代码 / shellcode 候选）
3. 区域级 / 全进程内存转储（raw bin + manifest.json 元数据清单）
4. 标准 minidump 转储（dbghelp.MiniDumpWriteDump，可被 WinDbg / Volatility 读取）

设计原则：
- 仅依赖 ctypes + Windows API + pymem 句柄，不引入新第三方依赖，
  保证 vendor/wheels 内置打包路径零增量
- 所有函数接收进程句柄（int），不在此层维护进程状态；
  engine 工具层从 memory_tools._sessions 取 Pymem 后传 pm.process_handle
- 原始数据采集与数据分析解耦：本层只管"采"，分析见 memanalysis_api

参考：实施方案 §4.2、§10（木马行为分析预留）
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from winreverse.core.memory_api import MemoryAccessError as MemoryAccessError

# ↑ `as` 同名为显式再导出：mypy no_implicit_reexport=true 下其他模块
#   （engine/tools/memscan_tools.py 等）才能合法引用 memdump_api.MemoryAccessError

# =============================================================================
# Windows 内存常量
# =============================================================================

# 内存状态（MEMORY_BASIC_INFORMATION.State）
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000

# 内存类型（MEMORY_BASIC_INFORMATION.Type）
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x100000
# Windows 10+ 实测：映像区域的 Type 常返回 SEC_IMAGE（0x1000000）
# 而非文档中的 MEM_IMAGE（0x100000），两者必须都按"映像"处理
MEM_IMAGE_SEC = 0x1000000

# 页保护属性（低 8 位为基本保护，高位为修饰标志 GUARD/NOCACHE/WRITECOMBINE）
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400

# 保护属性 → 人可读名称
_PROTECT_NAMES: dict[int, str] = {
    PAGE_NOACCESS: "NOACCESS",
    PAGE_READONLY: "R",
    PAGE_READWRITE: "RW",
    PAGE_WRITECOPY: "RC",
    PAGE_EXECUTE: "X",
    PAGE_EXECUTE_READ: "RX",
    PAGE_EXECUTE_READWRITE: "RWX",
    PAGE_EXECUTE_WRITECOPY: "RWC",
}

# 内存类型 → 人可读名称
_TYPE_NAMES: dict[int, str] = {
    MEM_PRIVATE: "private",
    MEM_MAPPED: "mapped",
    MEM_IMAGE: "image",
}

# 64 位用户态地址空间上限（user-mode VA 范围）
_MAX_USER_ADDRESS = 0x7FFFFFFEFFFF

_PAGE_SIZE = 0x1000

# ReadProcessMemory 单页读取块大小
_READ_CHUNK = 0x10000

# 转储单区域默认上限（超大区域截断，防止 reserve 区间拖爆磁盘）
_DEFAULT_MAX_REGION_SIZE = 64 * 1024 * 1024

# 全进程转储默认总量上限
_DEFAULT_MAX_TOTAL_BYTES = 1024**3

# manifest 清单文件名
_MANIFEST_NAME = "manifest.json"

# manifest 清单 schema 版本
_MANIFEST_SCHEMA_VERSION = "1.0"


# =============================================================================
# 数据模型
# =============================================================================


@dataclass(frozen=True)
class MemoryRegion:
    """单个虚拟内存区域的元数据。

    Attributes:
        base_address: 区域基地址
        size: 区域大小（字节）
        state: 内存状态（MEM_COMMIT / MEM_RESERVE / MEM_FREE）
        protect: 页保护属性（含 GUARD 等修饰位）
        type: 内存类型（MEM_PRIVATE / MEM_MAPPED / MEM_IMAGE）
        allocation_base: 分配基地址
        allocation_protect: 分配时保护属性
        mapped_file: 映射文件路径（image/mapped 区域；私有内存为空）
    """

    base_address: int
    size: int
    state: int
    protect: int
    type: int
    allocation_base: int = 0
    allocation_protect: int = 0
    mapped_file: str = ""

    @property
    def is_committed(self) -> bool:
        """是否为已提交（可访问）内存。"""
        return self.state == MEM_COMMIT

    @property
    def is_private(self) -> bool:
        """是否为私有内存（非文件映射）。"""
        return self.type == MEM_PRIVATE

    @property
    def is_image(self) -> bool:
        """是否为 PE 映像区域（模块代码/数据，兼容 SEC_IMAGE 变体）。"""
        return self.type in (MEM_IMAGE, MEM_IMAGE_SEC)

    @property
    def is_mapped(self) -> bool:
        """是否为文件映射区域（非映像）。"""
        return self.type == MEM_MAPPED

    @property
    def base_protect(self) -> int:
        """基本保护属性（剥离 GUARD/NOCACHE/WRITECOMBINE 修饰位）。"""
        return self.protect & 0xFF

    @property
    def is_executable(self) -> bool:
        """是否可执行。"""
        return bool(self.base_protect & 0xF0)

    @property
    def is_writable(self) -> bool:
        """是否可写。"""
        return self.base_protect in (
            PAGE_READWRITE,
            PAGE_WRITECOPY,
            PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY,
        )

    @property
    def protect_name(self) -> str:
        """保护属性人可读名称（如 'RW' / 'RWX'，含修饰位时加后缀）。"""
        name = _PROTECT_NAMES.get(self.base_protect, f"0x{self.base_protect:02X}")
        suffix = ""
        if self.protect & PAGE_GUARD:
            suffix += "+GUARD"
        if self.protect & PAGE_NOCACHE:
            suffix += "+NOCACHE"
        if self.protect & PAGE_WRITECOMBINE:
            suffix += "+WC"
        return name + suffix

    @property
    def type_name(self) -> str:
        """内存类型人可读名称（private / mapped / image / other）。"""
        if self.is_image:
            return "image"
        return _TYPE_NAMES.get(self.type, f"0x{self.type:X}")

    @property
    def is_suspicious(self) -> bool:
        """是否为可疑区域（注入代码 / shellcode 候选）。

        判定规则（保守，控制误报）：
        1. 私有内存 + 可执行 → 正常程序极少在私有内存执行代码，
           是代码注入 / 无文件落地木马的最强信号
        2. 任意 RWX（可读写执行）区域 → 自修改 / 解包壳 / 注入常用
        """
        if not self.is_committed or not self.is_executable:
            return False
        if self.is_private:
            return True
        return self.base_protect in (
            PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY,
        )

    def to_dict(self) -> dict[str, Any]:
        """转为 JSON 兼容字典（地址输出为十六进制字符串）。"""
        return {
            "base_address": f"0x{self.base_address:X}",
            "size": self.size,
            "state": self.state,
            "protect": self.protect_name,
            "protect_raw": self.protect,
            "type": self.type_name,
            "mapped_file": self.mapped_file,
            "suspicious": self.is_suspicious,
        }


@dataclass
class DumpResult:
    """全进程转储结果摘要。

    Attributes:
        output_dir: 转储输出目录
        manifest_path: manifest.json 路径
        region_count: 枚举到的已提交区域总数
        dumped_count: 实际写入的区域数
        skipped_count: 跳过数（被过滤条件排除 / 读取失败）
        total_bytes: 实际写入的总字节数
        suspicious_count: 可疑区域数（含未转储的）
        truncated_count: 因超出单区域上限被截断的区域数
    """

    output_dir: str
    manifest_path: str
    region_count: int = 0
    dumped_count: int = 0
    skipped_count: int = 0
    total_bytes: int = 0
    suspicious_count: int = 0
    truncated_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """转为 JSON 兼容字典。"""
        return {
            "output_dir": self.output_dir,
            "manifest_path": self.manifest_path,
            "region_count": self.region_count,
            "dumped_count": self.dumped_count,
            "skipped_count": self.skipped_count,
            "total_bytes": self.total_bytes,
            "suspicious_count": self.suspicious_count,
            "truncated_count": self.truncated_count,
        }


@dataclass
class _RegionDumpEntry:
    """manifest 中单个区域条目（内部构建用）。"""

    file: str
    region: MemoryRegion
    sha256: str = ""
    size: int = 0
    truncated: bool = False
    read_failed: bool = False


# =============================================================================
# 区域枚举
# =============================================================================


def _protect_to_str(protect: int) -> str:
    """保护属性转人可读字符串。"""
    base = protect & 0xFF
    return _PROTECT_NAMES.get(base, f"0x{base:02X}")


def _query_dos_device_map() -> dict[str, str]:
    """构建设备名 → 盘符映射（用于把 \\Device\\HarddiskVolumeN 路径还原为 C:\\ 形式）。"""
    result: dict[str, str] = {}
    if sys.platform != "win32":
        return result
    kernel32 = ctypes.windll.kernel32
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        dos_device = ctypes.create_unicode_buffer(8)
        dos_device.value = f"{letter}:"
        target = ctypes.create_unicode_buffer(1024)
        ret = kernel32.QueryDosDeviceW(dos_device.value, target, 1024)
        if ret:
            result[target.value] = f"{letter}:"
    return result


def _get_mapped_file_name(process_handle: int, base_address: int) -> str:
    """查询区域对应的映射文件路径（K32GetMappedFileNameW）。

    Returns:
        盘符化后的文件路径（如 'C:\\Windows\\System32\\ntdll.dll'），
        无映射文件或查询失败返回空字符串
    """
    if sys.platform != "win32":
        return ""
    kernel32 = ctypes.windll.kernel32
    buf = ctypes.create_unicode_buffer(1024)
    ret = kernel32.K32GetMappedFileNameW(
        ctypes.c_void_p(process_handle),
        ctypes.c_void_p(base_address),
        buf,
        1024,
    )
    if not ret:
        return ""
    path = buf.value
    if path.startswith("\\Device\\"):
        for device, letter in _query_dos_device_map().items():
            if path.startswith(device):
                return letter + path[len(device) :]
    return path


def _virtual_query(process_handle: int, address: int) -> tuple[int, int, int, int, int, int] | None:
    """执行 VirtualQueryEx。

    Returns:
        (base_address, region_size, state, protect, type, allocation_base)，
        查询失败返回 None
    """
    if sys.platform != "win32":
        return None

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        """winnt.h MEMORY_BASIC_INFORMATION（64 位布局）。"""

        _fields_ = [
            ("BaseAddress", ctypes.c_size_t),
            ("AllocationBase", ctypes.c_size_t),
            ("AllocationProtect", ctypes.wintypes.DWORD),
            ("_alignment1", ctypes.wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.wintypes.DWORD),
            ("Protect", ctypes.wintypes.DWORD),
            ("Type", ctypes.wintypes.DWORD),
            ("_alignment2", ctypes.wintypes.DWORD),
        ]

    mbi = MEMORY_BASIC_INFORMATION()
    ret = ctypes.windll.kernel32.VirtualQueryEx(
        ctypes.c_void_p(process_handle),
        ctypes.c_void_p(address),
        ctypes.byref(mbi),
        ctypes.sizeof(mbi),
    )
    if not ret:
        return None
    return (
        int(mbi.BaseAddress),
        int(mbi.RegionSize),
        int(mbi.State),
        int(mbi.Protect),
        int(mbi.Type),
        int(mbi.AllocationBase),
    )


def enumerate_regions(
    process_handle: int,
    only_committed: bool = True,
) -> list[MemoryRegion]:
    """枚举目标进程的用户态虚拟内存区域。

    从最低用户态地址开始按区域步进，直到地址空间上限或查询失败。

    Args:
        process_handle: 目标进程句柄（PROCESS_QUERY_INFORMATION | PROCESS_VM_READ）
        only_committed: 仅返回 MEM_COMMIT 区域（默认 True；False 时含 reserve/free）

    Returns:
        MemoryRegion 列表（按基地址升序）

    Raises:
        MemoryAccessError: 非 Windows 平台或查询异常
    """
    if sys.platform != "win32":
        raise MemoryAccessError("内存区域枚举仅支持 Windows 平台")

    regions: list[MemoryRegion] = []
    address = _PAGE_SIZE  # 跳过 NULL 页
    while address < _MAX_USER_ADDRESS:
        queried = _virtual_query(process_handle, address)
        if queried is None:
            break
        base, size, state, protect, mem_type, alloc_base = queried
        if size == 0:
            # 防御：异常的零长度区域，避免死循环
            address += _PAGE_SIZE
            continue
        if not only_committed or state == MEM_COMMIT:
            mapped_file = (
                _get_mapped_file_name(process_handle, base)
                if state == MEM_COMMIT and mem_type in (MEM_IMAGE, MEM_IMAGE_SEC, MEM_MAPPED)
                else ""
            )
            regions.append(
                MemoryRegion(
                    base_address=base,
                    size=size,
                    state=state,
                    protect=protect,
                    type=mem_type,
                    allocation_base=alloc_base,
                    mapped_file=mapped_file,
                )
            )
        address = base + size
    return regions


def read_region(
    process_handle: int,
    region: MemoryRegion,
    max_bytes: int | None = None,
) -> bytes:
    """读取单个内存区域的内容（分页容错）。

    使用 ReadProcessMemory 按块读取；遇到不可读页（如 GUARD 页）时
    保留已读部分继续跳页尝试，最终返回实际读取到的字节。

    Args:
        process_handle: 目标进程句柄
        region: 目标区域
        max_bytes: 最大读取字节数（None 表示整个区域，受区域大小限制）

    Returns:
        实际读取到的字节序列（可能短于区域大小）
    """
    if sys.platform != "win32":
        raise MemoryAccessError("内存读取仅支持 Windows 平台")
    kernel32 = ctypes.windll.kernel32

    read_size = region.size if max_bytes is None else min(region.size, max_bytes)
    chunks: list[bytes] = []
    offset = 0
    while offset < read_size:
        chunk_size = min(_READ_CHUNK, read_size - offset)
        buf = ctypes.create_string_buffer(chunk_size)
        bytes_read = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            ctypes.c_void_p(process_handle),
            ctypes.c_void_p(region.base_address + offset),
            buf,
            ctypes.c_size_t(chunk_size),
            ctypes.byref(bytes_read),
        )
        if ok and bytes_read.value > 0:
            chunks.append(buf.raw[: bytes_read.value])
            offset += chunk_size
        elif bytes_read.value > 0:
            # 部分读取（ERROR_PARTIAL_COPY）：保留可读部分，跳到下一页重试
            chunks.append(buf.raw[: bytes_read.value])
            offset += chunk_size
        else:
            # 整块不可读（GUARD / NOACCESS），跳过一页
            offset += _PAGE_SIZE
    return b"".join(chunks)


# =============================================================================
# 全进程转储
# =============================================================================


def _select_regions(
    regions: list[MemoryRegion],
    *,
    include_images: bool,
    include_mapped: bool,
    include_private: bool,
    min_size: int,
) -> list[MemoryRegion]:
    """按转储过滤条件筛选区域（纯函数，便于测试）。"""
    selected: list[MemoryRegion] = []
    for r in regions:
        if not r.is_committed or r.size < min_size:
            continue
        if r.is_image and not include_images:
            continue
        if r.is_mapped and not include_mapped:
            continue
        if r.is_private and not include_private:
            continue
        if not (r.is_image or r.is_mapped or r.is_private):
            continue
        selected.append(r)
    return selected


def _region_file_name(index: int, base_address: int) -> str:
    """生成区域转储文件名：region_NNNN_0xBASE.bin。"""
    return f"region_{index:04d}_{base_address:012x}.bin"


def _write_manifest(
    output_dir: Path, entries: list[_RegionDumpEntry], summary: dict[str, Any]
) -> None:
    """将转储清单写入 manifest.json。"""
    manifest = {
        "schema_version": _MANIFEST_SCHEMA_VERSION,
        "tool": "winreverse-memdump",
        "created_at": datetime.now(UTC).isoformat(),
        **summary,
        "regions": [
            {
                "file": e.file,
                "base_address": f"0x{e.region.base_address:X}",
                "size": e.size,
                "protect": e.region.protect_name,
                "type": e.region.type_name,
                "mapped_file": e.region.mapped_file,
                "suspicious": e.region.is_suspicious,
                "truncated": e.truncated,
                "read_failed": e.read_failed,
                "sha256": e.sha256,
            }
            for e in entries
        ],
    }
    manifest_path = output_dir / _MANIFEST_NAME
    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)


def dump_process(
    process_handle: int,
    output_dir: str | Path,
    *,
    include_images: bool = True,
    include_mapped: bool = True,
    include_private: bool = True,
    min_size: int = _PAGE_SIZE,
    max_region_size: int = _DEFAULT_MAX_REGION_SIZE,
    max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES,
) -> DumpResult:
    """全进程内存转储：按区域导出 raw bin + manifest.json 元数据清单。

    输出目录结构：
        <output_dir>/
        ├── manifest.json          # 区域元数据（地址/保护/类型/SHA256/可疑标记）
        └── region_NNNN_0xBASE.bin # 各区域原始内容

    Args:
        process_handle: 目标进程句柄
        output_dir: 输出目录（不存在则创建）
        include_images: 是否转储 PE 映像区域
        include_mapped: 是否转储文件映射区域
        include_private: 是否转储私有内存区域
        min_size: 最小区域大小（字节），过滤碎片区
        max_region_size: 单区域转储上限（超出截断）
        max_total_bytes: 总转储上限（超出停止）

    Returns:
        DumpResult 转储摘要

    Raises:
        MemoryAccessError: 非 Windows 平台 / 区域枚举失败 / 输出目录创建失败
    """
    if sys.platform != "win32":
        raise MemoryAccessError("内存转储仅支持 Windows 平台")

    all_regions = enumerate_regions(process_handle, only_committed=True)
    selected = _select_regions(
        all_regions,
        include_images=include_images,
        include_mapped=include_mapped,
        include_private=include_private,
        min_size=min_size,
    )

    out = Path(output_dir)
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise MemoryAccessError(f"创建输出目录失败: {out}: {e}") from e

    entries: list[_RegionDumpEntry] = []
    total_bytes = 0
    dumped = 0
    skipped = 0
    truncated_count = 0

    for index, region in enumerate(selected):
        if total_bytes >= max_total_bytes:
            skipped += 1
            continue
        budget = min(max_region_size, max_total_bytes - total_bytes)
        data = read_region(process_handle, region, max_bytes=budget)
        if not data:
            skipped += 1
            continue
        truncated = len(data) < region.size
        if truncated:
            truncated_count += 1
        file_name = _region_file_name(index, region.base_address)
        file_path = out / file_name
        try:
            file_path.write_bytes(data)
        except OSError as e:
            raise MemoryAccessError(f"写入区域文件失败: {file_path}: {e}") from e
        entries.append(
            _RegionDumpEntry(
                file=file_name,
                region=region,
                sha256=hashlib.sha256(data).hexdigest(),
                size=len(data),
                truncated=truncated,
            )
        )
        total_bytes += len(data)
        dumped += 1

    # 未写入文件但可疑的区域也计入统计（供分析层提示）
    suspicious_count = sum(1 for r in all_regions if r.is_suspicious)

    summary = {
        "region_count": len(all_regions),
        "selected_count": len(selected),
        "dumped_count": dumped,
        "skipped_count": skipped,
        "total_bytes": total_bytes,
        "suspicious_count": suspicious_count,
        "truncated_count": truncated_count,
    }
    if dumped == 0:
        # 修复(2026-09-12)：fail-closed。句柄无效 / 进程已退出 / 无权限时，区域枚举可能
        # 得到 0 条或全部读取失败；旧行为会写出空 manifest 并当作"成功"返回，上层
        # `case collect` 随即登记一条 0 字节证据并报成功——取证链上出现"成功但空"的假证据。
        # 现直接报错，由调用方映射为退出码 1。
        raise MemoryAccessError(
            f"未转储到任何内存区域（区域总数 {len(all_regions)}，候选 {len(selected)}，跳过 {skipped}）："
            "目标句柄可能无效、进程已退出或无权限"
        )

    _write_manifest(out, entries, summary)

    return DumpResult(
        output_dir=str(out),
        manifest_path=str(out / _MANIFEST_NAME),
        region_count=len(all_regions),
        dumped_count=dumped,
        skipped_count=skipped,
        total_bytes=total_bytes,
        suspicious_count=suspicious_count,
        truncated_count=truncated_count,
    )


# =============================================================================
# minidump 转储
# =============================================================================

# MINIDUMP_TYPE 标志
MINIDUMP_NORMAL = 0x00000000
MINIDUMP_WITH_FULLMEMORY = 0x00000002
MINIDUMP_WITH_HANDLE_DATA = 0x00000004
MINIDUMP_WITH_UNLOADED_MODULES = 0x00000020
MINIDUMP_WITH_PROCESS_THREAD_DATA = 0x00000040


def dump_minidump(
    process_handle: int,
    pid: int,
    output_path: str | Path,
    *,
    full_memory: bool = True,
) -> Path:
    """生成标准 minidump（.dmp），可被 WinDbg / Volatility 等外部工具读取。

    通过 dbghelp.MiniDumpWriteDump 实现，默认包含完整内存 + 句柄数据。

    Args:
        process_handle: 目标进程句柄
        pid: 目标进程 ID
        output_path: 输出 .dmp 文件路径
        full_memory: True 包含完整进程内存（体积大），False 仅线程/模块元数据

    Returns:
        输出文件路径

    Raises:
        MemoryAccessError: 非 Windows 平台 / 文件创建失败 / API 调用失败
    """
    if sys.platform != "win32":
        raise MemoryAccessError("minidump 转储仅支持 Windows 平台")
    kernel32 = ctypes.windll.kernel32
    dbghelp = ctypes.windll.dbghelp

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x1
    CREATE_ALWAYS = 2
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    file_handle = kernel32.CreateFileW(
        str(out),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        None,
        CREATE_ALWAYS,
        0,
        None,
    )
    if file_handle == INVALID_HANDLE_VALUE or file_handle is None:
        raise MemoryAccessError(f"创建 minidump 文件失败: {out}")

    dump_type = MINIDUMP_WITH_FULLMEMORY | MINIDUMP_WITH_HANDLE_DATA
    if not full_memory:
        dump_type = MINIDUMP_NORMAL

    try:
        ok = dbghelp.MiniDumpWriteDump(
            ctypes.c_void_p(process_handle),
            ctypes.wintypes.DWORD(pid),
            ctypes.c_void_p(file_handle),
            ctypes.wintypes.DWORD(dump_type),
            None,
            None,
            None,
        )
        if not ok:
            err = ctypes.GetLastError()
            # GetLastError 在部分路径返回 HRESULT 形态（如 0x8007012B），低 16 位才是
            # Win32 错误码；真机实测 2026-09-14：目标进程已退出时旧报错为
            # "WinError -2147024597"，无法定位。此处解码 + 常见原因提示。
            code = err & 0xFFFF
            raw = err & 0xFFFFFFFF
            hint = ""
            if code == 299:  # ERROR_PARTIAL_COPY
                hint = "：目标进程可能已退出或部分内存不可读，请确认目标仍在运行"
            elif code in (5, 6):  # ERROR_ACCESS_DENIED / ERROR_INVALID_HANDLE
                hint = "：句柄无效或权限不足（需要 SeDebugPrivilege / 管理员）"
            raise MemoryAccessError(
                f"MiniDumpWriteDump 失败 (WinError {code}"
                f"{f'/0x{raw:08X}' if raw != code else ''}){hint}"
            )
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(file_handle))

    return out
