"""winreverse.core.pe_api — pefile 薄包装层。

仅暴露业务语义 API，隔离 pefile 版本变更对上层调用方的影响。

封装的 pefile 能力：
- PE 文件解析（parse / parse_bytes）
- 导入表查询（list_imports / suspicious_imports）
- 导出表查询（list_exports）
- 节区查询（list_sections）
- 元信息（get_entry_point / is_64bit / get_imphash）

参考：实施方案 §4.2
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

from pefile import PE as PE  # 显式 re-export：no_implicit_reexport=True 下需用 `as` 语法

# 可疑导入函数名集合（木马/注入/网络通信常用）
SUSPICIOUS_IMPORTS: frozenset[str] = frozenset(
    {
        "VirtualAllocEx",
        "VirtualProtectEx",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "OpenProcess",
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "InternetOpenA",
        "InternetOpenUrlA",
        "RegSetValueExA",
        "RegSetValueExW",
        "RegCreateKeyExA",
        "RegCreateKeyExW",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "GetAsyncKeyState",
        "BitBlt",
    }
)


def parse(file_path: str | Path) -> PE:
    """解析 PE 文件。

    Args:
        file_path: PE 文件路径

    Returns:
        pefile.PE 实例

    Raises:
        pefile.PEFormatError: 文件不是有效 PE
        OSError: 文件读取失败
    """
    return PE(str(file_path))


def parse_bytes(data: bytes) -> PE:
    """解析 PE 字节序列（用于从内存或网络流加载）。

    Args:
        data: PE 文件字节序列

    Returns:
        pefile.PE 实例
    """
    return PE(data=data)


def list_imports(pe: PE) -> list[dict[str, str]]:
    """列出 PE 导入表。

    Args:
        pe: pefile.PE 实例

    Returns:
        导入项列表，每项含 'dll' 与 'name' 字段；
        若 PE 无导入表则返回空列表
    """
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return []
    result: list[dict[str, str]] = []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode(errors="replace") if entry.dll else ""
        for imp in entry.imports:
            name = imp.name.decode(errors="replace") if imp.name else f"ordinal_{imp.ordinal}"
            result.append({"dll": dll_name, "name": name})
    return result


def list_exports(pe: PE) -> list[dict[str, str | int]]:
    """列出 PE 导出表。

    Args:
        pe: pefile.PE 实例

    Returns:
        导出项列表，每项含 'name' 与 'ordinal' 字段；
        若 PE 无导出表（如 EXE）则返回空列表
    """
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return []
    result: list[dict[str, str | int]] = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = exp.name.decode(errors="replace") if exp.name else ""
        result.append({"name": name, "ordinal": int(exp.ordinal)})
    return result


def list_sections(pe: PE) -> list[dict[str, str | int]]:
    """列出 PE 节区。

    Args:
        pe: pefile.PE 实例

    Returns:
        节区信息列表，每项含 'name' / 'virtual_size' / 'virtual_address' /
        'raw_size' / 'characteristics' 字段
    """
    result: list[dict[str, str | int]] = []
    for section in pe.sections:
        name = section.Name.decode(errors="replace").rstrip("\x00")
        result.append(
            {
                "name": name,
                "virtual_size": int(section.Misc_VirtualSize),
                "virtual_address": int(section.VirtualAddress),
                "raw_size": int(section.SizeOfRawData),
                "characteristics": int(section.Characteristics),
            }
        )
    return result


def suspicious_imports(pe: PE) -> list[str]:
    """返回可疑导入函数列表。

    检测木马/注入/网络通信常用的可疑 API，如 WriteProcessMemory、
    CreateRemoteThread、URLDownloadToFile 等。

    Args:
        pe: pefile.PE 实例

    Returns:
        命中的可疑导入函数名列表（去重）
    """
    found: set[str] = set()
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name:
                name = imp.name.decode(errors="replace")
                if name in SUSPICIOUS_IMPORTS:
                    found.add(name)
    return sorted(found)


def get_entry_point(pe: PE) -> int:
    """获取入口点 RVA（Relative Virtual Address）。"""
    return int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)


def is_64bit(pe: PE) -> bool:
    """判断 PE 是否为 64 位。

    Args:
        pe: pefile.PE 实例

    Returns:
        True 表示 64 位（Machine == IMAGE_FILE_MACHINE_AMD64）
    """
    machine = int(pe.FILE_HEADER.Machine)
    # IMAGE_FILE_MACHINE_AMD64 = 0x8664
    return machine == 0x8664


def get_imphash(pe: PE) -> str:
    """获取导入哈希（imphash）。

    imphash 是按导入函数顺序计算的 MD5，常用于恶意软件家族归类。

    Args:
        pe: pefile.PE 实例

    Returns:
        32 字符的十六进制 MD5 字符串
    """
    return cast(str, pe.get_imphash())
