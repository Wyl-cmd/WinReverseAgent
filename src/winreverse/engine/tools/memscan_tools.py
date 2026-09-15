"""winreverse.engine.tools.memscan_tools — 内存取证分析工具。

将 core.memdump_api（内存采集）与 core.memanalysis_api（取证分析）封装为
ToolInterface 实现，面向木马行为分析场景（内存取证 / 无文件攻击检测）。

工具清单：
- memory.regions: 枚举进程内存区域（标注可疑注入区域）
- memory.dump: 全进程内存转储（raw bin + manifest.json）
- memory.dump_minidump: 标准 minidump 转储（可交给 WinDbg/Volatility）
- memory.strings: 从转储文件提取字符串（ASCII/UTF-16LE）
- memory.iocs: 从转储文件提取 IOC（URL/IP/域名/路径/注册表）
- memory.carve_pe: 从转储文件雕刻 PE（内存映像布局）
- memory.analyze: 转储目录一键分析（字符串/IOC/熵/PE/YARA → 汇总报告）

会话约定：memory.regions / memory.dump / memory.dump_minidump 需要
先通过 memory.attach 附加目标进程并传入其返回的 pid；
文件分析类工具（strings/iocs/carve_pe/analyze）直接操作转储文件，无需附加。

参考：实施方案 §7.2、§10（木马行为分析预留）
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from winreverse.core import memanalysis_api, memdump_api
from winreverse.engine.tools._base import BaseTool
from winreverse.engine.tools.memory_tools import get_session

# 列表输出默认上限（防止巨型地址空间撑爆 LLM 上下文）
_MAX_REGION_ITEMS = 100
_MAX_IOC_ITEMS = 100
_MAX_STRING_ITEMS = 50


class MemoryRegionsTool(BaseTool):
    """memory.regions — 枚举进程内存区域。

    输入: {
        "pid": 1234,          # memory.attach 返回的进程 ID
        "include_all": false  # 可选：true 返回全部已提交区域（默认仅可疑+摘要）
    }
    输出: {
        "total": int,            # 已提交区域总数
        "suspicious_count": int, # 可疑区域数（注入代码候选）
        "suspicious": [...],     # 可疑区域明细（最多 50 条）
        "regions": [...]         # 区域列表（include_all 时返回全部，否则仅可执行区域）
    }
    """

    name = "memory.regions"
    description = (
        "枚举目标进程的虚拟内存区域，标注保护属性/类型/映射文件，"
        "并识别可疑的可执行私有内存区域（代码注入/无文件木马候选）"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        pid = int(self._require(input_data, "pid"))
        include_all = bool(input_data.get("include_all", False))
        pm = get_session(pid)
        handle = int(pm.process_handle)
        regions = memdump_api.enumerate_regions(handle, only_committed=True)
        committed = [r for r in regions if r.is_committed]
        if not committed:
            # fail-closed（与 memory.dump 的 2026-09-12 修复同口径）：句柄无效 / 目标已退出 /
            # 无权限时 enumerate_regions 会静默返回空列表，旧行为把它当"无可疑区域"上报，
            # 取证链上即产生**假阴性**证据。真机实测 2026-09-14：
            # attach 后目标进程退出 → 旧行为 status=success / total=0。
            raise memdump_api.MemoryAccessError(
                f"未枚举到任何已提交内存区域（pid={pid}）：目标句柄可能无效、进程已退出或无权限"
            )
        suspicious = [r for r in committed if r.is_suspicious]

        shown = committed if include_all else [r for r in committed if r.is_executable]
        return {
            "total": len(committed),
            "suspicious_count": len(suspicious),
            "suspicious": [r.to_dict() for r in suspicious[:_MAX_REGION_ITEMS]],
            "regions": [r.to_dict() for r in shown[:_MAX_REGION_ITEMS]],
            "truncated": len(shown) > _MAX_REGION_ITEMS,
        }


class MemoryDumpTool(BaseTool):
    """memory.dump — 全进程内存转储。

    输入: {
        "pid": 1234,               # memory.attach 返回的进程 ID
        "output_dir": "out/dump",  # 可选：输出目录（默认 output/memory_dumps/<pid>_<时间戳>）
        "min_size": 4096,          # 可选：最小区域大小（字节）
        "max_total_mb": 1024       # 可选：总转储上限（MB）
    }
    输出: DumpResult 摘要（含 manifest 路径与可疑区域计数）
    """

    name = "memory.dump"
    description = (
        "全进程内存转储：按区域导出原始内存 + manifest.json 元数据清单，"
        "供 memory.analyze / yara.scan_file / 外部取证工具后续分析"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        pid = int(self._require(input_data, "pid"))
        pm = get_session(pid)
        handle = int(pm.process_handle)

        output_dir = input_data.get("output_dir")
        if not output_dir:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = f"output/memory_dumps/{pid}_{timestamp}"
        min_size = int(input_data.get("min_size", 0x1000))
        max_total_bytes = int(input_data.get("max_total_mb", 1024)) * 1024 * 1024

        result = memdump_api.dump_process(
            handle,
            output_dir,
            min_size=min_size,
            max_total_bytes=max_total_bytes,
        )
        return result.to_dict()


class MemoryMinidumpTool(BaseTool):
    """memory.dump_minidump — 标准 minidump 转储。

    输入: {
        "pid": 1234,
        "output_path": "out/target.dmp",  # 可选（默认 output/memory_dumps/<pid>.dmp）
        "full_memory": true               # 可选：是否包含完整内存
    }
    输出: {"output_path": str}
    """

    name = "memory.dump_minidump"
    description = (
        "生成标准 minidump（.dmp，含完整内存），可交给 WinDbg / Volatility 等外部取证工具做深度分析"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        pid = int(self._require(input_data, "pid"))
        pm = get_session(pid)
        handle = int(pm.process_handle)

        output_path = input_data.get("output_path")
        if not output_path:
            output_path = f"output/memory_dumps/{pid}.dmp"
        full_memory = bool(input_data.get("full_memory", True))

        result_path = memdump_api.dump_minidump(
            handle,
            pid,
            output_path,
            full_memory=full_memory,
        )
        return {"output_path": str(result_path)}


class MemoryStringsTool(BaseTool):
    """memory.strings — 从转储文件提取字符串。

    输入: {
        "path": "out/dump/region_0000_xxx.bin",
        "min_length": 5,     # 可选
        "limit": 50          # 可选：返回条数上限
    }
    输出: {"count": int, "strings": [{"offset", "encoding", "value"}]}
    """

    name = "memory.strings"
    description = "从内存转储文件提取可读字符串（ASCII + UTF-16LE），支持最小长度过滤"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        path = self._require(input_data, "path")
        min_length = int(input_data.get("min_length", 5))
        limit = int(input_data.get("limit", _MAX_STRING_ITEMS))

        hits = memanalysis_api.extract_strings(_read_dump(path), min_length=min_length)
        shown = hits[:limit]
        return {
            "count": len(hits),
            "strings": [h.to_dict() for h in shown],
            "truncated": len(hits) > limit,
        }


class MemoryIocsTool(BaseTool):
    """memory.iocs — 从转储文件提取 IOC。

    输入: {
        "path": "out/dump/region_0000_xxx.bin",
        "min_length": 5,    # 可选：字符串最小长度
        "limit": 100        # 可选：返回条数上限
    }
    输出: {"count": int, "iocs": [{"kind", "value", "offset"}], "by_kind": {...}}
    """

    name = "memory.iocs"
    description = (
        "从内存转储文件提取失陷指标 IOC（URL / IP / 域名 / 邮箱 / Windows 路径 / 注册表键），"
        "用于木马 C2 地址与持久化线索排查"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        path = self._require(input_data, "path")
        min_length = int(input_data.get("min_length", 5))
        limit = int(input_data.get("limit", _MAX_IOC_ITEMS))

        iocs = memanalysis_api.extract_iocs(_read_dump(path), min_length=min_length)
        by_kind: dict[str, int] = {}
        for hit in iocs:
            by_kind[hit.kind] = by_kind.get(hit.kind, 0) + 1
        return {
            "count": len(iocs),
            "iocs": [h.to_dict() for h in iocs[:limit]],
            "by_kind": by_kind,
            "truncated": len(iocs) > limit,
        }


class MemoryCarvePeTool(BaseTool):
    """memory.carve_pe — 从转储文件雕刻 PE。

    输入: {
        "path": "out/dump/region_0000_xxx.bin",
        "output_dir": "out/carved",  # 可选：落盘目录（不传则仅报告不落盘）
        "max_count": 16              # 可选
    }
    输出: {"count": int, "pes": [CarvedPE...], "written_files": [...]}
    """

    name = "memory.carve_pe"
    description = (
        "从内存转储中雕刻 PE 文件（识别注入到私有内存的 DLL/EXE/shellcode 载体），"
        "可选落盘供 pefile / DIE / 反编译工具后续分析"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        path = self._require(input_data, "path")
        max_count = int(input_data.get("max_count", 16))

        data = _read_dump(path)
        pes = memanalysis_api.carve_pe(data, max_count=max_count)
        written: list[str] = []
        output_dir = input_data.get("output_dir")
        if output_dir:
            written = [
                str(p)
                for p in memanalysis_api.carve_pe_to_files(data, output_dir, max_count=max_count)
            ]
        return {
            "count": len(pes),
            "pes": [pe.to_dict() for pe in pes],
            "written_files": written,
        }


class MemoryAnalyzeTool(BaseTool):
    """memory.analyze — 转储目录一键分析。

    输入: {
        "dump_dir": "out/dump",        # memory.dump 的输出目录（需含 manifest.json）
        "rules_path": "rules.yar",     # 可选：YARA 规则文件
        "top_strings": 20,             # 可选
        "carve": true                  # 可选：是否雕刻 PE
    }
    输出: DumpAnalysisReport 完整字典（字符串/IOC/熵/PE/YARA/可疑区域）
    """

    name = "memory.analyze"
    description = (
        "内存转储一键取证分析：汇总各区域的字符串、IOC、熵（加密/加壳识别）、"
        "雕刻 PE、可疑注入区域，可选 YARA 规则扫描，产出结构化报告"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        dump_dir = self._require(input_data, "dump_dir")
        rules_path = input_data.get("rules_path")
        top_strings = int(input_data.get("top_strings", 20))
        carve = bool(input_data.get("carve", True))

        report = memanalysis_api.analyze_dump_dir(
            dump_dir,
            rules_path=rules_path,
            top_strings=top_strings,
            carve=carve,
        )
        return report.to_dict()


def _read_dump(path: str) -> bytes:
    """读取转储文件内容。

    Args:
        path: 转储文件路径

    Returns:
        文件字节内容

    Raises:
        FileNotFoundError: 文件不存在
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"转储文件不存在: {file_path}")
    return file_path.read_bytes()


# 工具实例列表
MEMSCAN_TOOLS: list[BaseTool] = [
    MemoryRegionsTool(),
    MemoryDumpTool(),
    MemoryMinidumpTool(),
    MemoryStringsTool(),
    MemoryIocsTool(),
    MemoryCarvePeTool(),
    MemoryAnalyzeTool(),
]
