"""测试模块：winreverse.engine.tools.fs_tools 边界分支。

覆盖 fs.read_file/write_file/edit_file/list_dir/search 的异常路径、
10MB 上限、行窗口与截断标记、递归列目录、搜索结果上限与 glob/大小过滤；
统一走 execute() 契约入口，断言 status/error_message/关键负载。
断言平台无关，不加平台守卫：Linux 无 Windows 专有依赖（yara）时如实报
collection error（基线接受态），待 Windows 实机（依赖就位）实跑回填。
"""

from __future__ import annotations

import base64
from pathlib import Path

from winreverse.engine.tools.fs_tools import (
    FS_TOOLS,
    FsEditFileTool,
    FsListDirTool,
    FsReadFileTool,
    FsSearchTool,
    FsWriteFileTool,
)

_LIMIT = 10 * 1024 * 1024


class TestReadFileEdges:
    """fs.read_file：大小上限、行窗口、二进制截断与缺参。"""

    def test_oversize_file_rejected(self, tmp_path: Path) -> None:
        big = tmp_path / "big.bin"
        with big.open("wb") as f:
            f.truncate(_LIMIT + 1)
        result = FsReadFileTool().execute({"path": str(big)})
        assert result["status"] == "error"
        assert "10MB" in result["error_message"]

    def test_offset_beyond_eof_returns_empty(self, tmp_path: Path) -> None:
        f = tmp_path / "a.txt"
        f.write_text("l1\nl2\n", encoding="utf-8")
        result = FsReadFileTool().execute({"path": str(f), "offset": 99, "length": 10})
        assert result["status"] == "success"
        assert result["lines"] == []
        assert result["total_lines"] == 2
        assert result["truncated"] is False

    def test_line_window_and_truncated_flag(self, tmp_path: Path) -> None:
        f = tmp_path / "a.txt"
        f.write_text("\n".join(f"l{i}" for i in range(1, 6)), encoding="utf-8")
        result = FsReadFileTool().execute({"path": str(f), "offset": 2, "length": 3})
        assert result["lines"] == ["l2", "l3", "l4"]
        assert result["truncated"] is True  # offset-1+length=4 < total=5

        result_tail = FsReadFileTool().execute({"path": str(f), "offset": 3, "length": 3})
        assert result_tail["lines"] == ["l3", "l4", "l5"]
        assert result_tail["truncated"] is False

    def test_binary_larger_than_read_truncate(self, tmp_path: Path) -> None:
        f = tmp_path / "b.bin"
        f.write_bytes(b"\x00PY" + b"\x01" * (256 * 1024))
        result = FsReadFileTool().execute({"path": str(f)})
        assert result["status"] == "success"
        assert result["binary"] is True
        assert result["truncated"] is True
        assert len(base64.b64decode(result["base64"])) == 256 * 1024
        assert result["hex_preview"].startswith("00 50 59")

    def test_missing_path_key(self) -> None:
        result = FsReadFileTool().execute({})
        assert result["status"] == "error"
        assert "缺少必需参数" in result["error_message"]


class TestWriteFileEdges:
    """fs.write_file：追加超限拒绝、追加建新文件、父目录自动创建。"""

    def test_append_exceeding_limit_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "big.txt"
        with f.open("wb") as fh:
            fh.truncate(_LIMIT)
        result = FsWriteFileTool().execute({"path": str(f), "content": "x", "append": True})
        assert result["status"] == "error"
        assert "10MB" in result["error_message"]
        assert f.stat().st_size == _LIMIT  # 原文件未被破坏

    def test_append_creates_missing_file(self, tmp_path: Path) -> None:
        f = tmp_path / "new.txt"
        result = FsWriteFileTool().execute({"path": str(f), "content": "abc", "append": True})
        assert result["status"] == "success"
        assert result["append"] is True
        assert result["bytes_written"] == 3
        assert f.read_text(encoding="utf-8") == "abc"

    def test_parent_dirs_auto_created(self, tmp_path: Path) -> None:
        f = tmp_path / "x" / "y" / "z.txt"
        result = FsWriteFileTool().execute({"path": str(f), "content": "hi"})
        assert result["status"] == "success"
        assert f.read_text(encoding="utf-8") == "hi"


class TestEditFileEdges:
    """fs.edit_file：0 次匹配拒绝且不落盘。"""

    def test_zero_matches_rejected_and_file_untouched(self, tmp_path: Path) -> None:
        f = tmp_path / "a.txt"
        f.write_text("hello world", encoding="utf-8")
        result = FsEditFileTool().execute({"path": str(f), "old_string": "xyz", "new_string": "n"})
        assert result["status"] == "error"
        assert "未找到" in result["error_message"]
        assert f.read_text(encoding="utf-8") == "hello world"


class TestListDirEdges:
    """fs.list_dir：目录缺失、递归相对名、500 条截断。"""

    def test_missing_directory_rejected(self, tmp_path: Path) -> None:
        result = FsListDirTool().execute({"path": str(tmp_path / "nope")})
        assert result["status"] == "error"
        assert "NotADirectoryError" in result["error_message"]

    def test_recursive_uses_relative_names(self, tmp_path: Path) -> None:
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "f.txt").write_text("12345", encoding="utf-8")
        result = FsListDirTool().execute({"path": str(tmp_path), "recursive": True})
        assert result["status"] == "success"
        by_name = {e["name"]: e for e in result["entries"]}
        assert by_name["sub"]["type"] == "dir"
        assert by_name["sub"]["size"] == 0
        assert by_name[str(Path("sub") / "f.txt")]["size"] == 5

    def test_truncates_at_500_entries(self, tmp_path: Path) -> None:
        for i in range(505):
            (tmp_path / f"{i:04}.txt").write_text("x", encoding="utf-8")
        result = FsListDirTool().execute({"path": str(tmp_path)})
        assert result["count"] == 500
        assert result["truncated"] is True


class TestSearchEdges:
    """fs.search：目录缺失、非法正则、max_results 截断、glob 与大小过滤。"""

    def test_missing_directory_rejected(self, tmp_path: Path) -> None:
        result = FsSearchTool().execute({"path": str(tmp_path / "nope"), "pattern": "x"})
        assert result["status"] == "error"
        assert "NotADirectoryError" in result["error_message"]

    def test_invalid_regex_rejected(self, tmp_path: Path) -> None:
        result = FsSearchTool().execute({"path": str(tmp_path), "pattern": "(unclosed"})
        assert result["status"] == "error"
        assert "正则非法" in result["error_message"]

    def test_max_results_truncates(self, tmp_path: Path) -> None:
        f = tmp_path / "a.txt"
        f.write_text("hit\n" * 5, encoding="utf-8")
        result = FsSearchTool().execute({"path": str(tmp_path), "pattern": "hit", "max_results": 3})
        assert result["count"] == 3
        assert result["truncated"] is True
        assert [m["line"] for m in result["matches"]] == [1, 2, 3]

    def test_glob_filter_and_oversize_file_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("needle\n", encoding="utf-8")
        (tmp_path / "b.txt").write_text("needle\n", encoding="utf-8")
        big = tmp_path / "big.py"
        big.write_text("needle\n" + "a" * _LIMIT, encoding="utf-8")  # >10MB 文本文件
        result = FsSearchTool().execute(
            {"path": str(tmp_path), "pattern": "needle", "glob": "*.py"}
        )
        files = [m["file"] for m in result["matches"]]
        assert files == [str(tmp_path / "a.py")]  # b.txt 被 glob 排除，big.py 超限跳过
        assert result["truncated"] is False


def test_fs_tools_registry() -> None:
    """FS_TOOLS 注册表：六个工具、命名空间唯一、描述非空。"""
    assert [t.name for t in FS_TOOLS] == [
        "fs.read_file",
        "fs.write_file",
        "fs.edit_file",
        "fs.list_dir",
        "fs.search",
        "file.hash",
    ]
    assert all(t.description for t in FS_TOOLS)
    assert len({t.name for t in FS_TOOLS}) == len(FS_TOOLS)
