"""测试模块：winreverse.core.die_api

测试 die-python 薄包装层。
覆盖：
- scan_file / scan_file_raw 文件扫描
- scan_bytes / scan_bytes_raw 字节序列扫描
- get_version / get_dielib_version 版本查询
- DieScanError 异常
- 扫描 flags 组合（deep / heuristic / recursive）

测试 PE 文件：C:\\Windows\\System32\\notepad.exe（标记 windows_only）
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from winreverse.core.die_api import (
    DieScanError,
    get_dielib_version,
    get_version,
    scan_bytes,
    scan_bytes_raw,
    scan_file,
    scan_file_raw,
)

NOTEPAD_PATH = Path(r"C:\Windows\System32\notepad.exe")


@pytest.mark.windows_only
class TestScanFile:
    """文件扫描测试"""

    def test_scan_file_returns_dict(self) -> None:
        """scan_file 应返回字典。"""
        if not NOTEPAD_PATH.exists():
            pytest.skip("notepad.exe 不存在")
        result = scan_file(NOTEPAD_PATH)
        assert isinstance(result, dict)
        # notepad.exe 应被识别为 PE 文件
        if result:
            assert "detects" in result

    def test_scan_file_raw_returns_str(self) -> None:
        """scan_file_raw 应返回 JSON 字符串。"""
        if not NOTEPAD_PATH.exists():
            pytest.skip("notepad.exe 不存在")
        result = scan_file_raw(NOTEPAD_PATH)
        assert isinstance(result, str)
        # 应为有效 JSON 或空字符串
        if result:
            import json

            data = json.loads(result)
            assert isinstance(data, dict)

    def test_scan_file_with_deep_flag(self) -> None:
        """启用 deep flag 应正常扫描。"""
        if not NOTEPAD_PATH.exists():
            pytest.skip("notepad.exe 不存在")
        result = scan_file(NOTEPAD_PATH, deep=True)
        assert isinstance(result, dict)

    def test_scan_file_with_heuristic_flag(self) -> None:
        """启用 heuristic flag 应正常扫描。"""
        if not NOTEPAD_PATH.exists():
            pytest.skip("notepad.exe 不存在")
        result = scan_file(NOTEPAD_PATH, heuristic=True)
        assert isinstance(result, dict)

    def test_scan_file_failure_raises_die_scan_error(self) -> None:
        """扫描失败应抛出 DieScanError。"""
        with (
            patch("winreverse.core.die_api.die.scan_file", side_effect=OSError("scan failed")),
            pytest.raises(DieScanError, match="DIE 扫描失败"),
        ):
            scan_file(NOTEPAD_PATH)


class TestScanBytes:
    """字节序列扫描测试"""

    @pytest.mark.windows_only
    def test_scan_bytes_returns_dict(self) -> None:
        """scan_bytes 应返回字典。"""
        if not NOTEPAD_PATH.exists():
            pytest.skip("notepad.exe 不存在")
        data = NOTEPAD_PATH.read_bytes()[:4096]  # 前 4KB
        result = scan_bytes(data)
        assert isinstance(result, dict)

    def test_scan_bytes_raw_returns_str(self) -> None:
        """scan_bytes_raw 应返回字符串。"""
        # 用一段明显的 PE 头字节
        data = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00"
        result = scan_bytes_raw(data)
        assert isinstance(result, str)

    def test_scan_bytes_failure_raises_die_scan_error(self) -> None:
        """扫描失败应抛出 DieScanError。"""
        with (
            patch("winreverse.core.die_api.die.scan_memory", side_effect=OSError("scan failed")),
            pytest.raises(DieScanError, match="DIE 扫描失败"),
        ):
            scan_bytes(b"some bytes")


class TestVersionInfo:
    """版本信息测试"""

    def test_get_version_returns_str(self) -> None:
        """get_version 应返回非空字符串。"""
        version = get_version()
        assert isinstance(version, str)
        assert len(version) > 0

    def test_get_dielib_version_returns_str(self) -> None:
        """get_dielib_version 应返回非空字符串。"""
        version = get_dielib_version()
        assert isinstance(version, str)
        assert len(version) > 0
