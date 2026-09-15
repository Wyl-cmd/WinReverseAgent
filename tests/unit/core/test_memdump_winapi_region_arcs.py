"""被测模块: winreverse.core.memdump_api — 区域级 WinAPI 弧（guest 09-15 缺口行）。

覆盖点: 325（K32GetMappedFileNameW 非 \\Device 路径原样返回 / 无盘符设备路径保留）、
361（VirtualQueryEx 失败返 None）、464-467（ERROR_PARTIAL_COPY 部分读取保留后续读）、
468-470（整块不可读按页跳过）、613-614（区域 bin 写盘 OSError 收敛 MemoryAccessError）。
口径: 模块导入链经 memory_api 依赖 pymem，Linux 本机如实报 collection error（基线
接受态），待 Windows 实机实跑回填；测试内以 monkeypatch 替换 sys.platform（仿
test_cli_crash_regressions 既有惯用法）与 ctypes.windll（OS 边界），被测的容错/
收敛/设备映射还原逻辑全部真实执行，无平台守卫。
"""

from __future__ import annotations

import ctypes
import sys
from pathlib import Path
from typing import Any

import pytest

from winreverse.core import memdump_api as md
from winreverse.core.memory_api import MemoryAccessError


def _win32(monkeypatch: pytest.MonkeyPatch) -> None:
    """进入被测 win32 分支（guest 上天然满足；Linux 本机验证逻辑用，非守卫）。"""
    monkeypatch.setattr(sys, "platform", "win32")


def _install_windll(monkeypatch: pytest.MonkeyPatch, kernel32: Any) -> None:
    # Linux 无 ctypes.windll 属性，raising=False 保证双端语义一致（guest 上为替换）
    monkeypatch.setattr(ctypes, "windll", _FakeWindLL(kernel32), raising=False)


class _FakeWindLL:
    def __init__(self, kernel32: Any) -> None:
        self.kernel32 = kernel32


class _FakeKernel32Map:
    """K32GetMappedFileNameW + QueryDosDeviceW 桩（出参经 ctypes 缓冲区真实回写）。"""

    def __init__(self, mapped_path: str, dos_devices: dict[str, str]) -> None:
        self.mapped_path = mapped_path
        self.dos_devices = dos_devices

    def K32GetMappedFileNameW(self, handle: Any, base: Any, buf: Any, size: int) -> int:
        buf.value = self.mapped_path
        return len(self.mapped_path)

    def QueryDosDeviceW(self, name: str, target: Any, size: int) -> int:
        device = self.dos_devices.get(name)
        if device is None:
            return 0
        target.value = device
        return len(device)


def test_get_mapped_file_name_dos_path_passthrough(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """K32 返回已是 DOS 形态的路径（非 \\Device 前缀）应原样透传。"""
    _win32(monkeypatch)
    _install_windll(monkeypatch, _FakeKernel32Map(r"C:\Windows\System32\ntdll.dll", {}))
    assert md._get_mapped_file_name(0x1000, 0x7FF600000000) == r"C:\Windows\System32\ntdll.dll"


def test_get_mapped_file_name_device_volume_rewritten_to_drive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """\\Device\\HarddiskVolumeN 路径应经 QueryDosDeviceW 映射还原为盘符形态。"""
    _win32(monkeypatch)
    kernel32 = _FakeKernel32Map(
        r"\Device\HarddiskVolume2\Windows\foo.dll",
        {"C:": r"\Device\HarddiskVolume2"},
    )
    _install_windll(monkeypatch, kernel32)
    assert md._get_mapped_file_name(0x1000, 0x7FF600000000) == r"C:\Windows\foo.dll"


def test_get_mapped_file_name_device_without_drive_letter_kept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """无盘符可映射的设备路径（QueryDosDeviceW 全部失败）应保留原样而非丢弃。"""
    _win32(monkeypatch)
    _install_windll(monkeypatch, _FakeKernel32Map(r"\Device\HarddiskVolume9\unknown.bin", {}))
    assert (
        md._get_mapped_file_name(0x1000, 0x7FF600000000) == r"\Device\HarddiskVolume9\unknown.bin"
    )


def test_virtual_query_failure_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """VirtualQueryEx 返回 0（句柄无效/地址不可查询）时 _virtual_query 应返 None。"""
    _win32(monkeypatch)

    class _Kernel32:
        def VirtualQueryEx(self, *args: Any) -> int:
            return 0

    _install_windll(monkeypatch, _Kernel32())
    assert md._virtual_query(0xDEADBEEF, 0x10000) is None


class _FakeReadKernel32:
    """ReadProcessMemory 出参桩：按脚本 (ok, bytes_read, data) 回写出参。"""

    def __init__(self, script: list[tuple[int, int, bytes]]) -> None:
        self.script = list(script)
        self.calls: list[int] = []

    def ReadProcessMemory(
        self, handle: Any, address: Any, buf: Any, size: int, bytes_read_ref: Any
    ) -> int:
        # c_void_p 入参取 .value（int(c_void_p) 在部分解释器走字节转换不可靠）
        self.calls.append(int(getattr(address, "value", address) or 0))
        ok, n, data = self.script.pop(0)
        if n:
            buf[:n] = data
            # byref 包装下回写真实 c_size_t 出参（等价 ReadProcessMemory 的 *lpNumberOfBytesRead）
            bytes_read_ref._obj.value = n
        return ok


def test_read_region_partial_copy_keeps_partial_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ERROR_PARTIAL_COPY（ok=0 但读回部分字节）应保留已读部分并推进到下一块。"""
    _win32(monkeypatch)
    monkeypatch.setattr(md, "_READ_CHUNK", 4)
    monkeypatch.setattr(md, "_PAGE_SIZE", 0x10)
    kernel32 = _FakeReadKernel32([(0, 3, b"ABC")])
    _install_windll(monkeypatch, kernel32)
    region = md.MemoryRegion(
        base_address=0x10000,
        size=4,
        state=md.MEM_COMMIT,
        protect=md.PAGE_READWRITE,
        type=md.MEM_PRIVATE,
    )
    assert md.read_region(0x1000, region) == b"ABC"
    assert kernel32.calls == [0x10000]


def test_read_region_unreadable_pages_skipped_by_page_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """整块不可读（GUARD/NOACCESS，0 字节）应按 _PAGE_SIZE 步进跳页重试直至越界。"""
    _win32(monkeypatch)
    monkeypatch.setattr(md, "_READ_CHUNK", 4)
    monkeypatch.setattr(md, "_PAGE_SIZE", 2)
    kernel32 = _FakeReadKernel32([(0, 0, b"")] * 4)
    _install_windll(monkeypatch, kernel32)
    region = md.MemoryRegion(
        base_address=0x10000,
        size=8,
        state=md.MEM_COMMIT,
        protect=md.PAGE_NOACCESS,
        type=md.MEM_PRIVATE,
    )
    assert md.read_region(0x1000, region) == b""
    assert kernel32.calls == [0x10000, 0x10002, 0x10004, 0x10006]


def test_dump_process_region_write_failure_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """区域 bin 写盘失败（OSError）应收敛为 MemoryAccessError 且不产出 manifest。"""
    _win32(monkeypatch)
    region = md.MemoryRegion(
        base_address=0x10000,
        size=0x2000,
        state=md.MEM_COMMIT,
        protect=md.PAGE_READWRITE,
        type=md.MEM_PRIVATE,
    )
    monkeypatch.setattr(md, "enumerate_regions", lambda handle, only_committed=True: [region])
    monkeypatch.setattr(
        md, "read_region", lambda handle, region, max_bytes=None: b"0123456789abcdef"
    )
    out = tmp_path / "dump"
    out.mkdir()
    (out / md._region_file_name(0, 0x10000)).mkdir()  # 同名目录 → write_bytes 抛 OSError
    with pytest.raises(MemoryAccessError, match="写入区域文件失败"):
        md.dump_process(0x1000, out)
    assert not (out / "manifest.json").exists()
