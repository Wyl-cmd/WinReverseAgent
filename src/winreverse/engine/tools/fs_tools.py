"""winreverse.engine.tools.fs_tools — 文件读写工具（Agent 基础设施）。

让 LLM 具备通用代码/文件操作能力（对齐主流 coding agent 的文件工具集）：
- fs.read_file: 读取文件（行范围、二进制检测、大小截断）
- fs.write_file: 写文件（覆盖/追加，父目录自动创建）
- fs.edit_file: 精确字符串替换（唯一匹配校验，代码修改的标准方式）
- fs.list_dir: 列目录（名称/大小/类型，递归可选）
- fs.search: 文件名 glob + 内容正则搜索（限结果数）
- file.hash: 文件哈希（sha256/sha1/md5，P1-5 新增，只读、流式分块）

安全边界：单文件读写上限 10MB；读取疑似二进制时返回十六进制预览
而非整块解码，防止撑爆 LLM 上下文。
"""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path
from typing import Any

from winreverse.engine.tools._base import BaseTool

# 单文件读写上限（字节）
_MAX_FILE_BYTES = 10 * 1024 * 1024
# 读取默认截断（字节）
_READ_TRUNCATE = 256 * 1024
# 二进制探测窗口
_BINARY_PROBE = 8 * 1024
# 目录/搜索结果上限
_MAX_ITEMS = 500
# 支持的哈希算法（file.hash）
_HASH_ALGORITHMS: tuple[str, ...] = ("sha256", "sha1", "md5")
# 流式读取块大小（字节）
_HASH_CHUNK = 1024 * 1024


def _resolve(path_str: str) -> Path:
    """解析并校验路径（存在性由调用方处理）。"""
    return Path(path_str)


def _is_binary(data: bytes) -> bool:
    """探测是否二进制（探测窗口含 NUL 字节即视为二进制）。"""
    return b"\x00" in data[:_BINARY_PROBE]


class FsReadFileTool(BaseTool):
    """fs.read_file — 读取文件。"""

    name = "fs.read_file"
    description = (
        "读取文本文件内容（支持行范围、最大 256KB 截断）；二进制文件返回十六进制预览与 base64"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        path = _resolve(str(self._require(input_data, "path")))
        if not path.is_file():
            raise FileNotFoundError(f"文件不存在: {path}")
        size = path.stat().st_size
        if size > _MAX_FILE_BYTES:
            raise ValueError(f"文件超过 10MB 上限: {size} 字节（请用行范围/外部工具）")

        data = path.read_bytes()
        if _is_binary(data):
            return {
                "path": str(path),
                "binary": True,
                "size": size,
                "hex_preview": data[:256].hex(" "),
                "base64": base64.b64encode(data[:_READ_TRUNCATE]).decode("ascii"),
                "truncated": size > _READ_TRUNCATE,
            }

        text = data.decode("utf-8", errors="replace")
        lines = text.splitlines()
        total = len(lines)
        offset = max(1, int(input_data.get("offset", 1)))  # 行号从 1 起
        length = int(input_data.get("length", 2000))
        selected = lines[offset - 1 : offset - 1 + length]

        return {
            "path": str(path),
            "binary": False,
            "total_lines": total,
            "offset": offset,
            "lines": selected,
            "truncated": offset - 1 + length < total,
        }


class FsWriteFileTool(BaseTool):
    """fs.write_file — 写文件。"""

    name = "fs.write_file"
    description = (
        "写入文本文件（覆盖或追加，父目录自动创建，上限 10MB）；"
        "用于生成分析报告、编写脚本、保存提取结果"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        path = _resolve(str(self._require(input_data, "path")))
        content = str(self._require(input_data, "content"))
        append = bool(input_data.get("append", False))

        payload = content.encode("utf-8")
        existing = path.stat().st_size if append and path.exists() else 0
        if existing + len(payload) > _MAX_FILE_BYTES:
            raise ValueError(f"写入后超过 10MB 上限: {existing + len(payload)} 字节")

        path.parent.mkdir(parents=True, exist_ok=True)
        if append:
            with path.open("a", encoding="utf-8") as f:
                f.write(content)
        else:
            path.write_text(content, encoding="utf-8")
        return {"path": str(path), "bytes_written": len(payload), "append": append}


class FsEditFileTool(BaseTool):
    """fs.edit_file — 精确字符串替换（代码修改标准方式）。"""

    name = "fs.edit_file"
    description = (
        "对文件做精确字符串替换：old_string 必须唯一匹配（否则报错并列出匹配数），"
        "replace_all=true 时替换全部；这是修改代码/配置的标准方式"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        path = _resolve(str(self._require(input_data, "path")))
        old_string = str(self._require(input_data, "old_string"))
        new_string = str(self._require(input_data, "new_string"))
        replace_all = bool(input_data.get("replace_all", False))

        if not path.is_file():
            raise FileNotFoundError(f"文件不存在: {path}")
        data = path.read_text(encoding="utf-8")
        count = data.count(old_string)
        if count == 0:
            raise ValueError("old_string 在文件中未找到（0 次匹配）")
        if count > 1 and not replace_all:
            raise ValueError(
                f"old_string 匹配 {count} 处，不唯一；请提供更长的上下文或 replace_all=true"
            )

        if replace_all:
            updated = data.replace(old_string, new_string)
        else:
            updated = data.replace(old_string, new_string, 1)
        path.write_text(updated, encoding="utf-8")
        return {"path": str(path), "replacements": count if replace_all else 1}


class FsListDirTool(BaseTool):
    """fs.list_dir — 列目录。"""

    name = "fs.list_dir"
    description = "列出目录内容（名称/类型/大小/修改时间，recursive=true 递归子目录）"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        path = _resolve(str(self._require(input_data, "path")))
        if not path.is_dir():
            raise NotADirectoryError(f"目录不存在: {path}")
        recursive = bool(input_data.get("recursive", False))

        entries: list[dict[str, Any]] = []
        iterator = path.rglob("*") if recursive else path.iterdir()
        truncated = False
        for entry in iterator:
            if len(entries) >= _MAX_ITEMS:
                truncated = True
                break
            try:
                stat = entry.stat()
                entries.append(
                    {
                        "name": str(entry.relative_to(path)) if recursive else entry.name,
                        "type": "dir" if entry.is_dir() else "file",
                        "size": stat.st_size if entry.is_file() else 0,
                    }
                )
            except OSError:
                continue
        return {
            "path": str(path),
            "count": len(entries),
            "entries": entries,
            "truncated": truncated,
        }


class FsSearchTool(BaseTool):
    """fs.search — 文件名 glob + 内容正则搜索。"""

    name = "fs.search"
    description = (
        "在目录中搜索：pattern 为内容正则（逐行匹配），"
        "glob 过滤文件名（如 *.py / *.exe）；输出 file:line:text"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        directory = _resolve(str(self._require(input_data, "path")))
        pattern = str(self._require(input_data, "pattern"))
        glob_filter = str(input_data.get("glob", "*"))
        max_results = int(input_data.get("max_results", 100))

        if not directory.is_dir():
            raise NotADirectoryError(f"目录不存在: {directory}")
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"正则非法: {e}") from e

        results: list[dict[str, Any]] = []
        truncated = False
        for file_path in sorted(directory.rglob(glob_filter)):
            if not file_path.is_file() or file_path.stat().st_size > _MAX_FILE_BYTES:
                continue
            try:
                data = file_path.read_bytes()
            except OSError:
                continue
            if _is_binary(data):
                continue  # 二进制文件跳过内容搜索
            text = data.decode("utf-8", errors="replace")
            for lineno, line in enumerate(text.splitlines(), 1):
                if regex.search(line):
                    if len(results) >= max_results:
                        truncated = True
                        break
                    results.append(
                        {
                            "file": str(file_path),
                            "line": lineno,
                            "text": line.strip()[:300],
                        }
                    )
            if truncated:
                break
        return {
            "pattern": pattern,
            "count": len(results),
            "matches": results,
            "truncated": truncated,
        }


class FileHashTool(BaseTool):
    """file.hash — 计算文件哈希（只读，P1-5 新增）。

    输入: {
        "path": "C:\\work\\samples\\keylogger.exe",
        "algorithm": "sha256"   # 可选：sha256/sha1/md5/all（默认 sha256）
    }
    输出: {
        "path": str,
        "size": int,             # 读入字节数（同时作为证据大小核对）
        "algorithm": str,
        "hashes": {"sha256": "...", "sha1": "...", "md5": "..."}
    }

    说明：分块流式读取（默认 1MB/块），不把整个样本读进内存；
    Windows / Linux 行为一致（纯 hashlib，不依赖 certutil 或 Get-FileHash）。
    """

    name = "file.hash"
    description = (
        "计算文件哈希（sha256/sha1/md5，默认 sha256，algorithm=all 一次算三种）："
        "只读、分块流式读取、跨平台一致；用于样本指纹、证据完整性核验与去重"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        path = _resolve(str(self._require(input_data, "path")))
        algorithm = str(input_data.get("algorithm", "sha256")).strip().lower() or "sha256"
        chunk_size = int(input_data.get("chunk_size", _HASH_CHUNK))

        if algorithm == "all":
            algorithms: tuple[str, ...] = _HASH_ALGORITHMS
        elif algorithm in _HASH_ALGORITHMS:
            algorithms = (algorithm,)
        else:
            raise ValueError(
                f"不支持的哈希算法: {algorithm}（可选: {'/'.join(_HASH_ALGORITHMS)}/all）"
            )
        if chunk_size <= 0:
            raise ValueError(f"chunk_size 必须为正整数，得到 {chunk_size}")
        if not path.is_file():
            raise FileNotFoundError(f"文件不存在: {path}")

        digesters = {name: hashlib.new(name) for name in algorithms}
        size = 0
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                size += len(chunk)
                for digester in digesters.values():
                    digester.update(chunk)

        return {
            "path": str(path),
            "size": size,
            "algorithm": algorithm,
            "hashes": {name: digester.hexdigest() for name, digester in digesters.items()},
        }


# 工具实例列表
FS_TOOLS: list[BaseTool] = [
    FsReadFileTool(),
    FsWriteFileTool(),
    FsEditFileTool(),
    FsListDirTool(),
    FsSearchTool(),
    FileHashTool(),
]
