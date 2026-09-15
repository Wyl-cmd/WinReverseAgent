"""测试模块：winreverse.core.die_api（离线逻辑路径）。

覆盖：_build_flags 位组合契约、scan_file_raw / scan_bytes_raw 空结果回退与
异常包装（DieScanError + 原因链）、scan_file / scan_bytes 的 JSON 解析失败
路径、scan_bytes_raw 强制 bytearray 传参（die-python 0.5.0 绕过）与 Path
转发约定。`die` 依赖缺失 → Linux 下如实报 collection error（基线接受态），
待 Windows 实机（依赖就位）实跑回填。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from winreverse.core import die_api
from winreverse.core.die_api import (
    DieScanError,
    _build_flags,
    scan_bytes,
    scan_bytes_raw,
    scan_file,
    scan_file_raw,
)

FLAGS = die_api.ScanFlags


class TestBuildFlags:
    """_build_flags：布尔开关到 ScanFlags 位组合的映射契约。"""

    def test_default_is_json_only(self) -> None:
        flags = _build_flags(False, False, False)
        assert flags == FLAGS.RESULT_AS_JSON
        assert not flags & FLAGS.DEEP_SCAN

    def test_each_switch_sets_its_own_bit(self) -> None:
        assert _build_flags(True, False, False) & FLAGS.DEEP_SCAN
        assert _build_flags(False, True, False) & FLAGS.HEURISTIC_SCAN
        assert _build_flags(False, False, True) & FLAGS.RECURSIVE_SCAN
        # 各开关互不串位
        assert not _build_flags(True, False, False) & FLAGS.HEURISTIC_SCAN

    def test_all_switches_combined(self) -> None:
        flags = _build_flags(True, True, True)
        assert (
            flags
            == FLAGS.RESULT_AS_JSON | FLAGS.DEEP_SCAN | FLAGS.HEURISTIC_SCAN | FLAGS.RECURSIVE_SCAN
        )


class TestScanFileRaw:
    """scan_file_raw：None 回退 / 异常包装 / 参数转发。"""

    def test_none_result_becomes_empty_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(die_api.die, "scan_file", lambda *a, **k: None)
        assert scan_file_raw("x.exe") == ""

    def test_error_wrapped_with_cause(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(*args: object, **kwargs: object) -> object:
            raise OSError("disk error")

        monkeypatch.setattr(die_api.die, "scan_file", boom)
        with pytest.raises(DieScanError, match="DIE 扫描失败") as exc_info:
            scan_file_raw("x.exe")
        assert isinstance(exc_info.value.__cause__, OSError)

    def test_path_and_flags_forwarded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: dict[str, object] = {}

        def fake(path: Path, flags: object) -> str:
            calls["path"] = path
            calls["flags"] = flags
            return "{}"

        monkeypatch.setattr(die_api.die, "scan_file", fake)
        scan_file_raw("x.exe", deep=True, recursive=True)
        assert calls["path"] == Path("x.exe")  # 字符串入参被统一为 Path
        flags = calls["flags"]
        assert flags & FLAGS.DEEP_SCAN and flags & FLAGS.RECURSIVE_SCAN
        assert not flags & FLAGS.HEURISTIC_SCAN


class TestScanBytesRaw:
    """scan_bytes_raw：bytearray 传参契约（die-python 0.5.0 bug 绕过）。"""

    def test_data_passed_as_bytearray_not_bytes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        def fake(data: object, flags: object) -> str:
            seen["data"] = data
            seen["type"] = type(data)
            return ""

        monkeypatch.setattr(die_api.die, "scan_memory", fake)
        assert scan_bytes_raw(b"MZ\x90\x00") == ""
        assert seen["data"] == b"MZ\x90\x00"
        assert seen["type"] is bytearray  # 直接传 bytes 会触发底层 TypeError

    def test_error_wrapped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(*args: object, **kwargs: object) -> object:
            raise TypeError("C layer rejected")

        monkeypatch.setattr(die_api.die, "scan_memory", boom)
        with pytest.raises(DieScanError, match="DIE 扫描失败"):
            scan_bytes_raw(b"data")


class TestJsonParsing:
    """scan_file / scan_bytes：空结果 → 空字典，坏 JSON → DieScanError。"""

    def test_scan_file_empty_raw_returns_empty_dict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(die_api.die, "scan_file", lambda *a, **k: "")
        assert scan_file("x.exe") == {}

    def test_scan_file_valid_json_returns_dict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        payload = json.dumps({"detects": [{"name": "MSVC", "version": "19.3"}]})
        monkeypatch.setattr(die_api.die, "scan_file", lambda *a, **k: payload)
        result = scan_file("x.exe")
        assert result["detects"][0]["name"] == "MSVC"

    def test_scan_file_bad_json_raises_die_scan_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(die_api.die, "scan_file", lambda *a, **k: "{not-json")
        with pytest.raises(DieScanError, match="JSON 解析失败"):
            scan_file("x.exe")

    def test_scan_bytes_empty_raw_returns_empty_dict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(die_api.die, "scan_memory", lambda *a, **k: "")
        assert scan_bytes(b"MZ") == {}

    def test_scan_bytes_bad_json_raises_die_scan_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(die_api.die, "scan_memory", lambda *a, **k: "]broken[")
        with pytest.raises(DieScanError, match="JSON 解析失败"):
            scan_bytes(b"MZ")
