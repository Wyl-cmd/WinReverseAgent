"""winreverse.forensics.sandbox_wsb — Windows Sandbox 可选增强。

定位：**即插即用原则下的可选增强**——ProcessIsolationRunner（behavior.py）
是默认行为监控后端，零配置可用；Windows Sandbox 隔离更强但需要
Pro/Enterprise 版本 + 手动启用功能，因此本模块只做：
1. 可用性检测（System32 下 WindowsSandbox.exe 是否存在）
2. .wsb 配置文件生成（样本路径 / 网络开关 / 映射目录 / 登录命令）

不主动启用任何系统功能、不要求任何环境配置。
用户若未启用 Sandbox，直接用默认的 ProcessIsolationRunner 即可。
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from xml.dom import minidom


class SandboxConfigError(ValueError):
    """wsb 配置生成失败（样本路径非法等）。"""


def is_sandbox_available() -> bool:
    """检测 Windows Sandbox 是否可用（功能已启用）。

    判定依据：System32\\WindowsSandbox.exe 存在即表示功能已启用。
    （未启用时不提示用户开启——保持零配置原则，可继续用进程隔离后端）
    """
    return Path("C:/Windows/System32/WindowsSandbox.exe").is_file()


def build_wsb_config(
    sample_path: str | Path,
    *,
    networking: bool = False,
    mapped_folder: str | Path | None = None,
    logon_command: str = "",
    memory_mb: int = 4096,
) -> str:
    """生成 Windows Sandbox 配置文件（.wsb）内容。

    默认关闭网络（木马样本引爆的安全默认），映射目录默认映射样本
    所在目录（只读由 Sandbox 自身策略控制，配置中显式只读）。

    Args:
        sample_path: 样本路径（映射进沙箱后由登录命令或手动执行）
        networking: 是否允许沙箱访问网络（默认 False）
        mapped_folder: 额外映射进沙箱的主机目录（None 映射样本所在目录）
        logon_command: 登录后自动执行的命令（如启动样本）
        memory_mb: 沙箱内存上限（MB）

    Returns:
        wsb XML 字符串（UTF-8）

    Raises:
        SandboxConfigError: 样本不存在 / 内存参数非法
    """
    sample = Path(sample_path)
    if not sample.is_file():
        raise SandboxConfigError(f"样本不存在: {sample}")
    if not 512 <= memory_mb <= 65536:
        raise SandboxConfigError(f"内存参数非法: {memory_mb}（512-65536）")

    folder = Path(mapped_folder) if mapped_folder is not None else sample.parent

    root = ET.Element("Configuration")
    ET.SubElement(root, "Networking").text = "Disable" if not networking else "Default"
    ET.SubElement(root, "MappedFolders").append(_mapped_folder_element(folder))
    ET.SubElement(root, "MemoryInMB").text = str(memory_mb)
    if logon_command:
        logon = ET.SubElement(root, "LogonCommand")
        ET.SubElement(logon, "Command").text = logon_command

    raw = ET.tostring(root, encoding="unicode")
    pretty = minidom.parseString(raw).toprettyxml(indent="  ")
    # 去掉 minidom 自带的 xml 声明行（wsb 不需要）
    lines = [line for line in pretty.splitlines() if line.strip() and not line.startswith("<?xml")]
    return "\n".join(lines)


def _mapped_folder_element(folder: Path) -> ET.Element:
    """构造只读映射目录节点。"""
    mapped = ET.Element("MappedFolder")
    ET.SubElement(mapped, "HostFolder").text = str(folder.resolve())
    ET.SubElement(mapped, "ReadOnly").text = "true"
    return mapped


def write_wsb_config(
    sample_path: str | Path,
    output_path: str | Path,
    **kwargs: object,
) -> Path:
    """生成并落盘 .wsb 文件（双击即在 Sandbox 中运行样本）。

    Returns:
        wsb 文件路径

    Raises:
        SandboxConfigError: 配置非法
    """
    content = build_wsb_config(sample_path, **kwargs)  # type: ignore[arg-type]
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    return out
