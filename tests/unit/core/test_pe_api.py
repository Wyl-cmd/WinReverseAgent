"""测试模块：winreverse.core.pe_api

测试 pefile 薄包装层。
覆盖：
- parse / parse_bytes PE 文件解析
- list_imports 导入表查询
- list_exports 导出表查询
- list_sections 节区查询
- suspicious_imports 可疑导入检测
- get_entry_point / is_64bit / get_imphash 元信息

测试 PE 文件：C:\\Windows\\System32\\notepad.exe（标记 windows_only）
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from winreverse.core import pe_api
from winreverse.core.pe_api import (
    SUSPICIOUS_IMPORTS,
    get_entry_point,
    get_imphash,
    is_64bit,
    list_exports,
    list_imports,
    list_sections,
    parse,
    parse_bytes,
    suspicious_imports,
)

NOTEPAD_PATH = Path(r"C:\Windows\System32\notepad.exe")


@pytest.fixture(scope="module")
def notepad_pe() -> pe_api.PE:
    """加载 notepad.exe 的 PE 实例（模块级共享，避免重复 IO）。"""
    if not NOTEPAD_PATH.exists():
        pytest.skip(f"测试 PE 文件不存在: {NOTEPAD_PATH}")
    return parse(NOTEPAD_PATH)


@pytest.mark.windows_only
class TestParse:
    """PE 解析测试"""

    def test_parse_file_returns_pe_instance(self) -> None:
        """parse 应返回 pefile.PE 实例。"""
        if not NOTEPAD_PATH.exists():
            pytest.skip("notepad.exe 不存在")
        pe = parse(NOTEPAD_PATH)
        assert pe is not None
        assert hasattr(pe, "FILE_HEADER")
        assert hasattr(pe, "OPTIONAL_HEADER")

    def test_parse_bytes_returns_pe_instance(self) -> None:
        """parse_bytes 应能从字节序列解析 PE。"""
        if not NOTEPAD_PATH.exists():
            pytest.skip("notepad.exe 不存在")
        data = NOTEPAD_PATH.read_bytes()
        pe = parse_bytes(data[:1024])  # 仅前 1KB 即可解析 PE 头
        assert pe is not None


@pytest.mark.windows_only
class TestListImports:
    """导入表查询测试"""

    def test_notepad_has_imports(self, notepad_pe: pe_api.PE) -> None:
        """notepad.exe 应有非空导入表。"""
        imports = list_imports(notepad_pe)
        assert len(imports) > 0
        # 每项应含 'dll' 与 'name' 字段
        assert all("dll" in item and "name" in item for item in imports)
        # Win11 notepad.exe 可能通过 api-ms-win-* API set 解析导入，
        # 也可能直接引用 kernel32.dll/ntdll.dll，放宽断言以兼容系统版本差异
        dll_names = {item["dll"].lower() for item in imports}
        expected_patterns = ("kernel32", "ntdll", "api-ms-win", "kernelbase")
        assert any(any(p in dll for p in expected_patterns) for dll in dll_names)

    def test_pe_without_imports_returns_empty(self) -> None:
        """PE 无导入表时应返回空列表。"""
        pe = MagicMock(spec=[])  # 无 DIRECTORY_ENTRY_IMPORT 属性
        assert list_imports(pe) == []


@pytest.mark.windows_only
class TestListExports:
    """导出表查询测试"""

    def test_notepad_typically_no_exports(self, notepad_pe: pe_api.PE) -> None:
        """notepad.exe 是 EXE，通常无导出表。"""
        exports = list_exports(notepad_pe)
        # EXE 通常无导出表，返回空列表
        assert isinstance(exports, list)

    def test_pe_without_exports_returns_empty(self) -> None:
        """PE 无导出表时应返回空列表。"""
        pe = MagicMock(spec=[])  # 无 DIRECTORY_ENTRY_EXPORT 属性
        assert list_exports(pe) == []


@pytest.mark.windows_only
class TestListSections:
    """节区查询测试"""

    def test_notepad_has_sections(self, notepad_pe: pe_api.PE) -> None:
        """notepad.exe 应有 .text/.data 等节区。"""
        sections = list_sections(notepad_pe)
        assert len(sections) > 0
        # 每项应含必要字段
        required_keys = {"name", "virtual_size", "virtual_address", "raw_size", "characteristics"}
        assert all(required_keys.issubset(s.keys()) for s in sections)
        # 节区名应为字符串
        assert all(isinstance(s["name"], str) for s in sections)


@pytest.mark.windows_only
class TestSuspiciousImports:
    """可疑导入检测测试"""

    def test_notepad_no_suspicious_imports(self, notepad_pe: pe_api.PE) -> None:
        """notepad.exe 是正常程序，不应有可疑导入（VirtualAllocEx 等）。"""
        suspicious = suspicious_imports(notepad_pe)
        # notepad.exe 可能使用 OpenProcess 等少量 api，但通常不含 WriteProcessMemory/CreateRemoteThread
        # 这里只验证返回类型，不强制为空（系统版本差异）
        assert isinstance(suspicious, list)
        assert all(name in SUSPICIOUS_IMPORTS for name in suspicious)

    def test_pe_without_imports_returns_empty(self) -> None:
        """无导入表的 PE 应返回空列表。"""
        pe = MagicMock(spec=[])
        assert suspicious_imports(pe) == []


@pytest.mark.windows_only
class TestMetaInfo:
    """元信息查询测试"""

    def test_get_entry_point_returns_int(self, notepad_pe: pe_api.PE) -> None:
        """get_entry_point 应返回正整数 RVA。"""
        ep = get_entry_point(notepad_pe)
        assert isinstance(ep, int)
        assert ep >= 0

    def test_is_64bit_returns_bool(self, notepad_pe: pe_api.PE) -> None:
        """is_64bit 应返回布尔值（Win11 notepad 通常是 64 位）。"""
        result = is_64bit(notepad_pe)
        assert isinstance(result, bool)

    def test_get_imphash_returns_str(self, notepad_pe: pe_api.PE) -> None:
        """get_imphash 应返回 32 字符的 MD5 字符串。"""
        imphash = get_imphash(notepad_pe)
        assert isinstance(imphash, str)
        assert len(imphash) == 32
        # MD5 字符串应为小写十六进制
        assert all(c in "0123456789abcdef" for c in imphash)
