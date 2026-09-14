"""被测模块：winreverse.engine.tools.fs_tools + winreverse.engine.tools.disasm_tool 尾部缺口。

覆盖点（对照 coverage_guest.xml 真机缺口）：disasm code 参数类型不支持分支、
fs.edit_file 文件不存在、fs.list_dir / fs.search 遍历中 OSError 跳过防御弧。
统一走 execute() 契约入口，断言平台无关、不加平台守卫：engine/tools 包 __init__
聚合导入触发 yara 链 → Linux 下如实报 collection error（基线接受态），
待 Windows 实机（依赖就位）实跑回填。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from winreverse.engine.tools.disasm_tool import DisasmTool
from winreverse.engine.tools.fs_tools import (
    FsEditFileTool,
    FsListDirTool,
    FsSearchTool,
)


class TestDisasmCodeTypeGuard:
    """disasm：code 参数类型不支持时返回 error（str/list/bytes 之外）。"""

    @pytest.mark.parametrize("bad_code", [123, 3.14, {"a": 1}, None])
    def test_unsupported_code_type_rejected(self, bad_code: Any) -> None:
        result = DisasmTool().execute({"code": bad_code, "arch": "x64"})
        assert result["status"] == "error"
        assert "code 参数类型不支持" in result["error_message"]
        assert type(bad_code).__name__ in result["error_message"]


class TestEditFileMissingFile:
    """fs.edit_file：目标文件不存在时拒绝且不落盘。"""

    def test_missing_file_rejected(self, tmp_path: Path) -> None:
        result = FsEditFileTool().execute(
            {"path": str(tmp_path / "nope.txt"), "old_string": "a", "new_string": "b"}
        )
        assert result["status"] == "error"
        assert "FileNotFoundError" in result["error_message"]
        assert "文件不存在" in result["error_message"]


class TestListDirStatOSErrorSkipped:
    """fs.list_dir：单个条目 stat 失败（OSError）时跳过该条目而非整体失败。"""

    def test_entry_stat_failure_is_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "good.txt").write_text("ok", encoding="utf-8")
        (tmp_path / "cursed.bin").write_bytes(b"x")
        original_stat = Path.stat

        def flaky_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
            if self.name == "cursed.bin":
                raise OSError(2, "模拟条目句柄失效")
            return original_stat(self, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", flaky_stat)
        result = FsListDirTool().execute({"path": str(tmp_path)})
        assert result["status"] == "success"
        names = [e["name"] for e in result["entries"]]
        assert "cursed.bin" not in names
        assert names == ["good.txt"]
        assert result["truncated"] is False


class TestSearchReadOSErrorSkipped:
    """fs.search：单个文件 read_bytes 失败（OSError）时跳过该文件而非整体失败。"""

    def test_unreadable_file_is_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "hit.txt").write_text("needle\n", encoding="utf-8")
        (tmp_path / "locked.txt").write_text("needle\n", encoding="utf-8")
        original_read_bytes = Path.read_bytes

        def flaky_read_bytes(self: Path) -> bytes:
            if self.name == "locked.txt":
                raise OSError(13, "模拟文件被占用")
            return original_read_bytes(self)

        monkeypatch.setattr(Path, "read_bytes", flaky_read_bytes)
        result = FsSearchTool().execute({"path": str(tmp_path), "pattern": "needle"})
        assert result["status"] == "success"
        files = [Path(m["file"]).name for m in result["matches"]]
        assert "locked.txt" not in files
        assert files == ["hit.txt"]
        assert result["count"] == 1
