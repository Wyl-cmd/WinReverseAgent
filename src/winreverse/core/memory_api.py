"""winreverse.core.memory_api — pymem 薄包装层。

仅暴露业务语义 API，隔离 pymem 版本变更对上层调用方的影响。
所有函数均接收 Pymem 实例，避免在此层维护进程状态。

封装的 pymem 能力：
- 进程附加（attach）
- 内存读写（read_int/read_bytes/read_string/write_int/write_bytes/write_string）
- 模式扫描（scan_pattern）
- 模块枚举（list_modules）

参考：实施方案 §4.2
"""

from __future__ import annotations

from typing import Any, cast

from pymem import Pymem
from pymem.exception import ProcessError, ProcessNotFound

# MODULEINFO 是 ctypes 结构体，pymem 未提供类型存根，用 Any 兼容
ModuleInfo = Any


class MemoryAccessError(RuntimeError):
    """内存访问失败的统一异常（包装 pymem 的 ProcessNotFound/ProcessError）。"""


def _resolve_pid_by_name(process_name: str) -> int:
    """按进程名解析 PID（psutil 实现）。

    规避 pymem 1.14 open_process_from_name 的编码缺陷：其进程快照解码使用
    locale.getpreferredencoding()，在中文 Windows + Python 3.12（UTF-8 模式）
    下遇到 GBK 进程名会抛 UnicodeDecodeError。psutil 不受影响，
    解析出 PID 后走 pymem 的 open_process_from_id 路径。

    Args:
        process_name: 进程名（大小写不敏感）

    Returns:
        首个匹配进程的 PID（多实例时与 pymem 行为一致取第一个）

    Raises:
        ProcessNotFound: 无匹配进程
    """
    import psutil

    name_lower = process_name.lower()
    for proc in psutil.process_iter(attrs=["name"]):
        name = proc.info.get("name") or ""
        if name.lower() == name_lower:
            return int(proc.pid)
    raise ProcessNotFound(f"未找到进程: {process_name}")


def _ensure_alive(pid: int) -> None:
    """校验目标 PID 仍然存活。

    Windows 上"已终止但句柄未释放"的 PID 仍可被 OpenProcess 成功打开，
    但后续 VirtualQueryEx/ReadProcessMemory 全部失效且无诊断信息，
    因此在附加前用 psutil 做活性校验（基于 STILL_ACTIVE 判定）。

    Args:
        pid: 目标进程 ID

    Raises:
        ProcessNotFound: 进程不存在或已退出
    """
    import psutil

    if not psutil.pid_exists(pid):
        raise ProcessNotFound(f"进程不存在或已退出: {pid}")


def attach(process_name: str) -> Pymem:
    """附加到目标进程。

    支持进程名（如 'notepad.exe'，大小写不敏感）或十进制 PID 字符串。
    按名附加内部通过 psutil 解析 PID，规避 pymem 的进程名编码缺陷；
    附加前做活性校验，避免打开已退出进程的残留句柄。

    Args:
        process_name: 进程名或 PID 字符串

    Returns:
        Pymem 实例，后续读写操作需传入此实例

    Raises:
        MemoryAccessError: 进程未找到或附加失败
    """
    try:
        if process_name.isdigit():
            pid = int(process_name)
            _ensure_alive(pid)
            return Pymem(pid)
        target_pid = _resolve_pid_by_name(process_name)
        return Pymem(target_pid)
    except ProcessNotFound as e:
        raise MemoryAccessError(f"进程未找到: {process_name}") from e
    except ProcessError as e:
        raise MemoryAccessError(f"附加进程失败: {process_name}") from e


def read_int(pm: Pymem, address: int) -> int:
    """读取 32 位有符号整数。"""
    try:
        return cast(int, pm.read_int(address))
    except Exception as e:
        raise MemoryAccessError(f"read_int 失败 @ 0x{address:X}: {e}") from e


def read_bytes(pm: Pymem, address: int, length: int) -> bytes:
    """读取字节序列。

    Args:
        pm: Pymem 实例
        address: 起始地址
        length: 读取长度（字节）

    Returns:
        读取到的字节序列
    """
    try:
        return cast(bytes, pm.read_bytes(address, length))
    except Exception as e:
        raise MemoryAccessError(f"read_bytes 失败 @ 0x{address:X} len={length}: {e}") from e


def read_string(pm: Pymem, address: int, max_len: int = 50, encoding: str = "UTF-8") -> str:
    """读取字符串。

    Args:
        pm: Pymem 实例
        address: 字符串起始地址
        max_len: 最大读取字节数（默认 50）
        encoding: 字符编码（默认 UTF-8）

    Returns:
        解码后的字符串
    """
    try:
        return cast(str, pm.read_string(address, byte=max_len, encoding=encoding))
    except Exception as e:
        raise MemoryAccessError(f"read_string 失败 @ 0x{address:X}: {e}") from e


def write_int(pm: Pymem, address: int, value: int) -> None:
    """写入 32 位有符号整数。"""
    try:
        pm.write_int(address, value)
    except Exception as e:
        raise MemoryAccessError(f"write_int 失败 @ 0x{address:X}: {e}") from e


def write_bytes(pm: Pymem, address: int, data: bytes) -> None:
    """写入字节序列。"""
    try:
        pm.write_bytes(address, data, len(data))
    except Exception as e:
        raise MemoryAccessError(f"write_bytes 失败 @ 0x{address:X} len={len(data)}: {e}") from e


def write_string(pm: Pymem, address: int, value: str, encoding: str = "UTF-8") -> None:
    """写入字符串（按指定编码转换为字节后写入）。"""
    try:
        pm.write_string(address, value, encoding=encoding)
    except Exception as e:
        raise MemoryAccessError(f"write_string 失败 @ 0x{address:X}: {e}") from e


def scan_pattern(
    pm: Pymem,
    pattern: str | bytes,
    return_multiple: bool = False,
) -> int | list[int]:
    """在进程内存中扫描模式。

    Args:
        pm: Pymem 实例
        pattern: 模式字符串（pymem 支持的格式，如 'XX XX ?? XX'）或字节序列
        return_multiple: 是否返回所有匹配地址。False 返回首个地址（int），
            True 返回全部地址列表（list[int]）

    Returns:
        匹配地址（int）或地址列表（list[int]）
    """
    try:
        result = pm.pattern_scan_all(pattern, return_multiple=return_multiple)
    except Exception as e:
        raise MemoryAccessError(f"scan_pattern 失败: {e}") from e
    if return_multiple:
        return list(result) if result else []
    # 单结果模式，pymem 返回 int 或 None
    if result is None:
        raise MemoryAccessError("scan_pattern 未找到匹配")
    return int(result)


def list_modules(pm: Pymem) -> list[ModuleInfo]:
    """列出进程加载的全部模块。

    Returns:
        MODULEINFO 结构体列表（pymem.process.MODULEINFO）
    """
    try:
        return cast(list[ModuleInfo], pm.list_modules())
    except Exception as e:
        raise MemoryAccessError(f"list_modules 失败: {e}") from e
