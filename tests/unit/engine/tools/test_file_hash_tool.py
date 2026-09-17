"""测试模块：新增只读工具 file.hash（P1-5）。

背景（2026-09-15 实测）：修复前 48 个工具里没有任何哈希能力（``grep hash`` = 0），
"样本安全处置与指纹"技能只能借 ``certutil`` / ``Get-FileHash``，而 certutil 路径一旦带引号
就被 P1-4 的转义缺陷破坏。本测试锁定 ``file.hash`` 的契约：

1. 三种算法（sha256/sha1/md5）结果与 hashlib 一致（Windows/Linux 同实现）；
2. ``algorithm=all`` 一次返回三种；
3. 只读（不改文件）、流式分块（chunk_size 生效、大文件不整块读入内存）；
4. 缺参/非法算法/文件不存在 → 规范错误结果（不抛异常穿透总线）；
5. 已注册进工具清单（LLM 可见）。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from winreverse.engine.bus import ToolRegistry
from winreverse.engine.tools import ALL_TOOLS, list_tool_names, register_all_tools
from winreverse.engine.tools.fs_tools import FileHashTool

_PAYLOAD = b"wra-file-hash-test\x00\x01\x02" * 64


@pytest.fixture
def sample(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(_PAYLOAD)
    return path


class TestFileHashTool:
    """file.hash 功能与边界。"""

    def test_default_sha256(self, sample: Path) -> None:
        result = FileHashTool().execute({"path": str(sample)})

        assert result["status"] == "success"
        assert result["algorithm"] == "sha256"
        assert result["hashes"]["sha256"] == hashlib.sha256(_PAYLOAD).hexdigest()
        assert result["size"] == len(_PAYLOAD)

    @pytest.mark.parametrize("algorithm", ["sha256", "sha1", "md5"])
    def test_each_algorithm(self, sample: Path, algorithm: str) -> None:
        result = FileHashTool().execute({"path": str(sample), "algorithm": algorithm})

        expected = hashlib.new(algorithm, _PAYLOAD).hexdigest()
        assert result["hashes"][algorithm] == expected

    def test_algorithm_all_returns_three(self, sample: Path) -> None:
        result = FileHashTool().execute({"path": str(sample), "algorithm": "ALL"})

        assert set(result["hashes"]) == {"sha256", "sha1", "md5"}
        for name, digest in result["hashes"].items():
            assert digest == hashlib.new(name, _PAYLOAD).hexdigest()

    def test_chunked_read_matches_single_pass(self, sample: Path) -> None:
        """分块读取（16 字节/块）结果一致 → 流式实现正确。"""
        result = FileHashTool().execute({"path": str(sample), "chunk_size": 16})

        assert result["hashes"]["sha256"] == hashlib.sha256(_PAYLOAD).hexdigest()
        assert result["size"] == len(_PAYLOAD)

    def test_file_is_not_modified(self, sample: Path) -> None:
        before = sample.read_bytes()
        FileHashTool().execute({"path": str(sample), "algorithm": "all"})
        assert sample.read_bytes() == before

    def test_missing_path_is_error_result(self) -> None:
        result = FileHashTool().execute({})
        assert result["status"] == "error"
        assert "path" in result["error_message"]

    def test_missing_file_is_error_result(self, tmp_path: Path) -> None:
        result = FileHashTool().execute({"path": str(tmp_path / "nope.bin")})
        assert result["status"] == "error"
        assert "FileNotFoundError" in result["error_message"]

    def test_invalid_algorithm_is_error_result(self, sample: Path) -> None:
        result = FileHashTool().execute({"path": str(sample), "algorithm": "sha512"})
        assert result["status"] == "error"
        assert "不支持的哈希算法" in result["error_message"]

    def test_non_positive_chunk_size_is_error_result(self, sample: Path) -> None:
        result = FileHashTool().execute({"path": str(sample), "chunk_size": 0})
        assert result["status"] == "error"
        assert "chunk_size" in result["error_message"]

    def test_empty_file(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.bin"
        empty.write_bytes(b"")
        result = FileHashTool().execute({"path": str(empty)})
        assert result["size"] == 0
        assert result["hashes"]["sha256"] == hashlib.sha256(b"").hexdigest()

    def test_registered_and_visible_to_llm(self) -> None:
        """新工具必须注册进清单（LLM 才看得到）。"""
        assert "file.hash" in list_tool_names()
        registry = ToolRegistry()
        register_all_tools(registry)
        assert "file.hash" in registry

    def test_tool_count_grew_by_one(self) -> None:
        """工具总数 = 修复前 47 + file.hash = 48。"""
        assert len(ALL_TOOLS) == 48
