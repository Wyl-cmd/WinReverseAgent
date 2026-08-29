"""测试模块：winreverse.engine.tools.fs_tools + shell_tools

Agent 基础设施工具测试：文件读写/编辑/搜索、shell 执行与危险命令守卫。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from winreverse.engine.tools.fs_tools import (
    FsEditFileTool,
    FsListDirTool,
    FsReadFileTool,
    FsSearchTool,
    FsWriteFileTool,
)
from winreverse.engine.tools.shell_tools import ShellRunTool

# =============================================================================
# 文件读写
# =============================================================================


class TestFsReadFile:
    """fs.read_file 测试。"""

    def test_read_text_with_lines(self, tmp_path: Path) -> None:
        """读取文本按行返回，行范围过滤。"""
        f = tmp_path / "code.py"
        f.write_text("line1\nline2\nline3\nline4\nline5\n", encoding="utf-8")
        result = FsReadFileTool().execute({"path": str(f), "offset": 2, "length": 2})
        assert result["status"] == "success"
        assert result["lines"] == ["line2", "line3"]
        assert result["total_lines"] == 5
        assert result["truncated"] is True  # 后面还有行未展示

        # 读到文件末尾时 truncated=False
        result2 = FsReadFileTool().execute({"path": str(f), "offset": 4, "length": 10})
        assert result2["truncated"] is False

    def test_read_binary_returns_hex(self, tmp_path: Path) -> None:
        """二进制文件返回十六进制预览而非整块文本。"""
        f = tmp_path / "sample.bin"
        f.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\xff\xff")
        result = FsReadFileTool().execute({"path": str(f)})
        assert result["binary"] is True
        assert result["hex_preview"].startswith("4d 5a")

    def test_read_missing_file(self, tmp_path: Path) -> None:
        """文件不存在报错。"""
        result = FsReadFileTool().execute({"path": str(tmp_path / "nope.txt")})
        assert result["status"] == "error"


class TestFsWriteFile:
    """fs.write_file 测试。"""

    def test_write_and_overwrite(self, tmp_path: Path) -> None:
        """写入与覆盖，父目录自动创建。"""
        tool = FsWriteFileTool()
        target = tmp_path / "sub" / "dir" / "report.md"
        r1 = tool.execute({"path": str(target), "content": "# 标题\n正文"})
        assert r1["status"] == "success"
        assert target.read_text(encoding="utf-8") == "# 标题\n正文"
        r2 = tool.execute({"path": str(target), "content": "v2"})
        assert r2["status"] == "success"
        assert target.read_text(encoding="utf-8") == "v2"

    def test_append(self, tmp_path: Path) -> None:
        """追加模式不清空原内容。"""
        target = tmp_path / "log.txt"
        tool = FsWriteFileTool()
        tool.execute({"path": str(target), "content": "first\n"})
        tool.execute({"path": str(target), "content": "second\n", "append": True})
        assert target.read_text(encoding="utf-8") == "first\nsecond\n"


class TestFsEditFile:
    """fs.edit_file 测试。"""

    def test_edit_unique_match(self, tmp_path: Path) -> None:
        """唯一匹配替换成功。"""
        f = tmp_path / "a.txt"
        f.write_text("port = 8080\nhost = localhost\n", encoding="utf-8")
        result = FsEditFileTool().execute(
            {"path": str(f), "old_string": "port = 8080", "new_string": "port = 9090"}
        )
        assert result["status"] == "success"
        assert "port = 9090" in f.read_text(encoding="utf-8")

    def test_edit_ambiguous_rejected(self, tmp_path: Path) -> None:
        """多处匹配且未 replace_all 时拒绝。"""
        f = tmp_path / "a.txt"
        f.write_text("x = 1\nx = 1\n", encoding="utf-8")
        result = FsEditFileTool().execute(
            {"path": str(f), "old_string": "x = 1", "new_string": "x = 2"}
        )
        assert result["status"] == "error"
        assert "不唯一" in result["error_message"]
        assert f.read_text(encoding="utf-8") == "x = 1\nx = 1\n"

    def test_edit_replace_all(self, tmp_path: Path) -> None:
        """replace_all 替换全部。"""
        f = tmp_path / "a.txt"
        f.write_text("x = 1\nx = 1\n", encoding="utf-8")
        result = FsEditFileTool().execute(
            {"path": str(f), "old_string": "x = 1", "new_string": "x = 2", "replace_all": True}
        )
        assert result["status"] == "success"
        assert result["replacements"] == 2
        assert f.read_text(encoding="utf-8") == "x = 2\nx = 2\n"

    def test_edit_not_found_rejected(self, tmp_path: Path) -> None:
        """old_string 未找到时报错。"""
        f = tmp_path / "a.txt"
        f.write_text("hello\n", encoding="utf-8")
        result = FsEditFileTool().execute(
            {"path": str(f), "old_string": "world", "new_string": "!"}
        )
        assert result["status"] == "error"
        assert "未找到" in result["error_message"]


class TestFsListAndSearch:
    """fs.list_dir / fs.search 测试。"""

    def test_list_dir(self, tmp_path: Path) -> None:
        """列出文件与目录。"""
        (tmp_path / "sub").mkdir()
        (tmp_path / "a.txt").write_text("data")
        result = FsListDirTool().execute({"path": str(tmp_path)})
        names = {e["name"]: e["type"] for e in result["entries"]}
        assert names["sub"] == "dir"
        assert names["a.txt"] == "file"

    def test_search_content(self, tmp_path: Path) -> None:
        """内容正则搜索命中并记录行号。"""
        (tmp_path / "code.py").write_text("import os\ntoken = 'secret123'\n", encoding="utf-8")
        result = FsSearchTool().execute(
            {"path": str(tmp_path), "pattern": "secret\\d+", "glob": "*.py"}
        )
        assert result["count"] == 1
        assert result["matches"][0]["line"] == 2
        assert "secret123" in result["matches"][0]["text"]

    def test_search_skips_binary(self, tmp_path: Path) -> None:
        """二进制文件被跳过（不产出乱码命中）。"""
        (tmp_path / "blob.bin").write_bytes(b"\x00\x01secret123\x00")
        result = FsSearchTool().execute(
            {"path": str(tmp_path), "pattern": "secret", "glob": "*.bin"}
        )
        assert result["count"] == 0


# =============================================================================
# shell.run
# =============================================================================


class TestShellRun:
    """shell.run 测试。"""

    def test_echo_command(self) -> None:
        """基本命令执行与返回码。"""
        result = ShellRunTool().execute({"command": "echo hello_agent"})
        assert result["status"] == "success"
        assert "hello_agent" in result["stdout"]

    def test_nonzero_returncode_is_error(self) -> None:
        """非零返回码标注 error 状态。"""
        result = ShellRunTool().execute({"command": "cmd /c exit 7"})
        assert result["status"] == "error"
        assert result["returncode"] == 7

    def test_powershell(self) -> None:
        """powershell 形态可用。"""
        result = ShellRunTool().execute({"command": "Write-Output ps_ok", "shell": "powershell"})
        assert "ps_ok" in result["stdout"]

    def test_cwd(self, tmp_path: Path) -> None:
        """cwd 生效。"""
        result = ShellRunTool().execute({"command": "cd", "cwd": str(tmp_path)})
        assert str(tmp_path.resolve()).lower() in result["stdout"].lower()

    def test_dangerous_blocked_by_default(self) -> None:
        """危险命令默认拦截。"""
        result = ShellRunTool().execute({"command": "format d: /q"})
        assert result["status"] == "error"
        assert "blocked_pattern" in result
        assert result["blocked_pattern"] == "format "

    def test_dangerous_allowed_explicit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """allow_dangerous=true 放行（守卫不误伤 echo 字符串）。"""
        monkeypatch.delenv("WINREVERSE_YOLO", raising=False)
        result = ShellRunTool().execute(
            {"command": "echo simulated_format_d", "allow_dangerous": False}
        )
        # 无危险词的命令不受影响
        assert result["status"] == "success"

    def test_yolo_env_allows(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """WINREVERSE_YOLO=1 全局豁免（yolo 模式语义）。"""
        monkeypatch.setenv("WINREVERSE_YOLO", "1")
        result = ShellRunTool().execute({"command": "cmd /c exit 0", "timeout": 10})
        assert result["status"] == "success"
