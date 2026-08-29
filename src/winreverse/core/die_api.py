"""winreverse.core.die_api — die-python 薄包装层。

仅暴露业务语义 API，隔离 die-python 版本变更对上层调用方的影响。

封装的 die-python 能力：
- 文件扫描（scan_file）— 识别壳/编译器/语言/工具链
- 字节序列扫描（scan_bytes）
- 原始结果获取（scan_file_raw / scan_bytes_raw）

返回 dict 或原始 JSON 字符串，上层按需处理。

参考：实施方案 §4.2
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import die
from die import ScanFlags

# 默认扫描 flags：JSON 输出（便于程序解析）
_DEFAULT_FLAGS: ScanFlags = ScanFlags.RESULT_AS_JSON


class DieScanError(RuntimeError):
    """DIE 扫描失败。"""


def _build_flags(deep: bool, heuristic: bool, recursive: bool) -> ScanFlags:
    """构建扫描 flags。

    Args:
        deep: 启用深度扫描（更慢但更准确）
        heuristic: 启用启发式扫描
        recursive: 启用递归扫描

    Returns:
        组合后的 ScanFlags
    """
    flags: ScanFlags = _DEFAULT_FLAGS
    if deep:
        flags |= ScanFlags.DEEP_SCAN
    if heuristic:
        flags |= ScanFlags.HEURISTIC_SCAN
    if recursive:
        flags |= ScanFlags.RECURSIVE_SCAN
    return flags


def scan_file_raw(
    file_path: str | Path,
    deep: bool = False,
    heuristic: bool = False,
    recursive: bool = False,
) -> str:
    """扫描文件，返回原始 JSON 字符串。

    Args:
        file_path: 待扫描文件路径
        deep: 启用深度扫描
        heuristic: 启用启发式扫描
        recursive: 启用递归扫描

    Returns:
        DIE 扫描结果的 JSON 字符串；无识别结果时返回空字符串

    Raises:
        DieScanError: 扫描失败
    """
    flags = _build_flags(deep, heuristic, recursive)
    try:
        result = die.scan_file(Path(file_path), flags)
    except Exception as e:
        raise DieScanError(f"DIE 扫描失败: {file_path}: {e}") from e
    return result or ""


def scan_bytes_raw(
    data: bytes,
    deep: bool = False,
    heuristic: bool = False,
    recursive: bool = False,
) -> str:
    """扫描字节序列，返回原始 JSON 字符串。

    Args:
        data: 待扫描字节序列
        deep: 启用深度扫描
        heuristic: 启用启发式扫描
        recursive: 启用递归扫描

    Returns:
        DIE 扫描结果的 JSON 字符串；无识别结果时返回空字符串

    Raises:
        DieScanError: 扫描失败
    """
    flags = _build_flags(deep, heuristic, recursive)
    # die-python 0.5.0 已知问题：scan_memory 的 Python 包装层接受 bytes/bytearray，
    # 但底层 C 函数 _ScanMemoryExA 期望 Sequence[int]。
    # 实测传入 bytes 会触发 TypeError（C 函数拒绝），传入 bytearray 可正常工作。
    # 此处用 bytearray 绕过该 bug，待 die-python 修复后可改回直接传 bytes。
    try:
        result = die.scan_memory(bytearray(data), flags)
    except Exception as e:
        raise DieScanError(f"DIE 扫描失败: {e}") from e
    return result or ""


def scan_file(
    file_path: str | Path,
    deep: bool = False,
    heuristic: bool = False,
    recursive: bool = False,
) -> dict[str, Any]:
    """扫描文件，返回解析后的字典。

    Args:
        file_path: 待扫描文件路径
        deep: 启用深度扫描
        heuristic: 启用启发式扫描
        recursive: 启用递归扫描

    Returns:
        解析后的字典，结构依 DIE 输出（含 'detects' 列表）；
        无识别结果时返回空字典

    Raises:
        DieScanError: 扫描失败或 JSON 解析失败
    """
    raw = scan_file_raw(file_path, deep, heuristic, recursive)
    if not raw:
        return {}
    try:
        return cast(dict[str, Any], json.loads(raw))
    except json.JSONDecodeError as e:
        raise DieScanError(f"DIE 结果 JSON 解析失败: {e}") from e


def scan_bytes(
    data: bytes,
    deep: bool = False,
    heuristic: bool = False,
    recursive: bool = False,
) -> dict[str, Any]:
    """扫描字节序列，返回解析后的字典。

    Args:
        data: 待扫描字节序列
        deep: 启用深度扫描
        heuristic: 启用启发式扫描
        recursive: 启用递归扫描

    Returns:
        解析后的字典；无识别结果时返回空字典

    Raises:
        DieScanError: 扫描失败或 JSON 解析失败
    """
    raw = scan_bytes_raw(data, deep, heuristic, recursive)
    if not raw:
        return {}
    try:
        return cast(dict[str, Any], json.loads(raw))
    except json.JSONDecodeError as e:
        raise DieScanError(f"DIE 结果 JSON 解析失败: {e}") from e


def get_version() -> str:
    """获取 DIE 版本号。

    Returns:
        DIE 版本字符串（如 '3.09'）
    """
    return str(die.die_version)


def get_dielib_version() -> str:
    """获取 dielib 版本号。

    Returns:
        dielib 版本字符串（如 '0.1.0'）
    """
    return str(die.dielib_version)
