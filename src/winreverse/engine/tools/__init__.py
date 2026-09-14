"""winreverse.engine.tools — 内部工具聚合与注册入口。

汇总各工具模块的 TOOLS 列表为 ALL_TOOLS（共 47 个），并提供：
- count_tools(): 工具总数
- list_tool_names(): 全部工具名
- register_all_tools(registry): 一次性注册到 ToolRegistry

新增工具：在对应工具模块实现 ToolInterface 并加入其 TOOLS 列表，
再在本文件的 ALL_TOOLS 拼接处追加该列表即可，无需改动 bus 调度。

参考：运行说明.md §9.1（47 个 ToolInterface 清单）
"""

from __future__ import annotations

from winreverse.engine.bus import ToolRegistry
from winreverse.engine.tools._base import BaseTool
from winreverse.engine.tools.android_tools import ANDROID_TOOLS
from winreverse.engine.tools.behavior_tools import BEHAVIOR_TOOLS
from winreverse.engine.tools.die_tools import DIE_TOOLS
from winreverse.engine.tools.disasm_tool import DISASM_TOOLS
from winreverse.engine.tools.fs_tools import FS_TOOLS
from winreverse.engine.tools.memory_tools import MEMORY_TOOLS
from winreverse.engine.tools.memscan_tools import MEMSCAN_TOOLS
from winreverse.engine.tools.net_tools import NET_TOOLS
from winreverse.engine.tools.pe_tools import PE_TOOLS
from winreverse.engine.tools.shell_tools import SHELL_TOOLS
from winreverse.engine.tools.yara_tools import YARA_TOOLS

# 全量工具清单：android13 + behavior3 + die2 + disasm1 + fs5 + memory3
#             + memscan7 + net4 + pe6 + shell1 + yara2 = 47
ALL_TOOLS: list[BaseTool] = [
    *ANDROID_TOOLS,
    *BEHAVIOR_TOOLS,
    *DIE_TOOLS,
    *DISASM_TOOLS,
    *FS_TOOLS,
    *MEMORY_TOOLS,
    *MEMSCAN_TOOLS,
    *NET_TOOLS,
    *PE_TOOLS,
    *SHELL_TOOLS,
    *YARA_TOOLS,
]

__all__ = [
    "ALL_TOOLS",
    "ANDROID_TOOLS",
    "BEHAVIOR_TOOLS",
    "DIE_TOOLS",
    "DISASM_TOOLS",
    "FS_TOOLS",
    "MEMORY_TOOLS",
    "MEMSCAN_TOOLS",
    "NET_TOOLS",
    "PE_TOOLS",
    "SHELL_TOOLS",
    "YARA_TOOLS",
    "BaseTool",
    "count_tools",
    "list_tool_names",
    "register_all_tools",
]


def count_tools() -> int:
    """返回聚合的工具总数。"""
    return len(ALL_TOOLS)


def list_tool_names() -> list[str]:
    """返回全部工具的唯一标识名。"""
    return [tool.name for tool in ALL_TOOLS]


def register_all_tools(registry: ToolRegistry) -> None:
    """将全部工具注册到指定的 ToolRegistry。

    重复注册由 ToolRegistry 抛出 ValueError("工具已注册: ...")，此处不吞。

    Args:
        registry: 目标工具注册中心
    """
    for tool in ALL_TOOLS:
        registry.register(tool)
