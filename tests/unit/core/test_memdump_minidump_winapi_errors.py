"""测试模块：winreverse.core.memdump_api（dump_minidump 的 WinAPI 失败路径）

覆盖点：CreateFileW 失败（720-721）、full_memory=False 的 MINIDUMP_NORMAL 降档（724-725）、
MiniDumpWriteDump 失败的错误码解码与提示（742-749，09-14 真机实测后新增逻辑）、finally CloseHandle。
口径：本模块经 memory_api 顶层依赖 pymem，Linux 本机如实 collection error（基线接受态），
待 Windows 真机（guest）实跑回填；测试内仅以 monkeypatch 替换 ctypes.windll /
ctypes.GetLastError 的 OS 边界，被测的错误解码、提示选择与异常分支全部真实执行，无平台守卫。
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from winreverse.core.memdump_api import (
    MINIDUMP_NORMAL,
    MINIDUMP_WITH_FULLMEMORY,
    MINIDUMP_WITH_HANDLE_DATA,
    dump_minidump,
)
from winreverse.core.memory_api import MemoryAccessError

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def _as_int(arg: Any) -> int:
    """ctypes 实参归一化：py3.12 下 int() 直接作用于 ctypes 实例拿到的是原始字节缓冲
    （2026-09-15 guest 实测 ValueError: invalid literal ... b'\\x06\\x00\\x00\\x00'），
    必须经 .value 取值；bytes 形态按小端解码兜底。"""
    if isinstance(arg, bytes):
        return int.from_bytes(arg, "little")
    return int(getattr(arg, "value", arg))


class _FakeKernel32:
    def __init__(self, createfile_result: int | None) -> None:
        self.createfile_result = createfile_result
        self.closed_handles: list[Any] = []

    def CreateFileW(self, *args: Any, **kwargs: Any) -> int | None:
        return self.createfile_result

    def CloseHandle(self, handle: Any) -> int:
        self.closed_handles.append(handle)
        return 1


class _FakeDbgHelp:
    def __init__(self, writedump_result: int) -> None:
        self.writedump_result = writedump_result
        self.calls: list[tuple[Any, ...]] = []

    def MiniDumpWriteDump(self, *args: Any) -> int:
        self.calls.append(args)
        return self.writedump_result


class _FakeWindLL:
    def __init__(self, kernel32: _FakeKernel32, dbghelp: _FakeDbgHelp) -> None:
        self.kernel32 = kernel32
        self.dbghelp = dbghelp


def _install(
    monkeypatch: pytest.MonkeyPatch, kernel32: _FakeKernel32, dbghelp: _FakeDbgHelp
) -> None:
    monkeypatch.setattr(ctypes, "windll", _FakeWindLL(kernel32, dbghelp))


def test_createfile_failure_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """CreateFileW 返回 INVALID_HANDLE_VALUE 时应立即报错且不调用 MiniDumpWriteDump。"""
    kernel32 = _FakeKernel32(createfile_result=INVALID_HANDLE_VALUE)
    dbghelp = _FakeDbgHelp(writedump_result=1)
    _install(monkeypatch, kernel32, dbghelp)
    with pytest.raises(MemoryAccessError, match="创建 minidump 文件失败"):
        dump_minidump(0x1000, 4242, tmp_path / "dump.dmp")
    assert dbghelp.calls == []


def test_writedump_failure_partial_copy_hint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """HRESULT 形态错误码 0x8007012B 应解码为 Win32 299 并附 ERROR_PARTIAL_COPY 提示。"""
    kernel32 = _FakeKernel32(createfile_result=0x1234)
    dbghelp = _FakeDbgHelp(writedump_result=0)
    _install(monkeypatch, kernel32, dbghelp)
    monkeypatch.setattr(ctypes, "GetLastError", lambda: 0x8007012B)
    with pytest.raises(MemoryAccessError) as excinfo:
        dump_minidump(0x1000, 4242, tmp_path / "dump.dmp")
    msg = str(excinfo.value)
    assert "WinError 299/0x8007012B" in msg
    assert "部分内存不可读" in msg
    # finally 语义：文件句柄必须被关闭（src 传给 CloseHandle 的是 c_void_p 包装）
    assert [_as_int(h) for h in kernel32.closed_handles] == [0x1234]


def test_writedump_failure_access_denied_hint_without_hex(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """裸 Win32 错误码 5（raw == code）应附权限提示且不追加 /0x 形态。"""
    kernel32 = _FakeKernel32(createfile_result=0x1234)
    dbghelp = _FakeDbgHelp(writedump_result=0)
    _install(monkeypatch, kernel32, dbghelp)
    monkeypatch.setattr(ctypes, "GetLastError", lambda: 5)
    with pytest.raises(MemoryAccessError) as excinfo:
        dump_minidump(0x1000, 4242, tmp_path / "dump.dmp")
    msg = str(excinfo.value)
    assert "WinError 5" in msg
    assert "/0x" not in msg
    assert "SeDebugPrivilege" in msg
    assert [_as_int(h) for h in kernel32.closed_handles] == [0x1234]


def test_full_memory_flag_controls_dump_type(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """full_memory=True 走 FULLMEMORY|HANDLE_DATA，False 降档 MINIDUMP_NORMAL，成功返回输出路径。"""
    kernel32 = _FakeKernel32(createfile_result=0x1234)
    dbghelp = _FakeDbgHelp(writedump_result=1)
    _install(monkeypatch, kernel32, dbghelp)
    out = tmp_path / "dump.dmp"
    assert dump_minidump(0x1000, 4242, out) == out
    assert _as_int(dbghelp.calls[0][3]) == (MINIDUMP_WITH_FULLMEMORY | MINIDUMP_WITH_HANDLE_DATA)
    assert dump_minidump(0x1000, 4242, out, full_memory=False) == out
    assert _as_int(dbghelp.calls[1][3]) == MINIDUMP_NORMAL
    assert [_as_int(h) for h in kernel32.closed_handles] == [0x1234, 0x1234]
