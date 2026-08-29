"""winreverse.engine.tools.pe_tools — PE 分析工具集。

将 core.pe_api 的函数封装为 ToolInterface 实现，注册到 ToolRegistry。
每个工具接收 file_path 参数，内部独立解析 PE 文件。

工具清单：
- pe.parse: 解析 PE 文件，返回基本元信息
- pe.imports: 查询导入表
- pe.exports: 查询导出表
- pe.sections: 查询节区
- pe.suspicious_imports: 检测可疑导入
- pe.meta: 获取元信息（entry_point / is_64bit / imphash）

参考：实施方案 §7.2
"""

from __future__ import annotations

from typing import Any

from winreverse.core import pe_api
from winreverse.engine.tools._base import BaseTool


class PEParseTool(BaseTool):
    """pe.parse — 解析 PE 文件，返回基本元信息。

    输入: {"file_path": "<PE 文件路径>"}
    输出: {"status": "success", "entry_point": int, "is_64bit": bool,
           "imphash": str, "num_sections": int, "num_imports": int}
    """

    name = "pe.parse"
    description = "解析 PE 文件，返回入口点、位数、imphash、节区数、导入数等基本元信息"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        file_path = self._require(input_data, "file_path")
        pe = pe_api.parse(file_path)
        return {
            "entry_point": pe_api.get_entry_point(pe),
            "is_64bit": pe_api.is_64bit(pe),
            "imphash": pe_api.get_imphash(pe),
            "num_sections": len(pe_api.list_sections(pe)),
            "num_imports": len(pe_api.list_imports(pe)),
        }


class PEImportsTool(BaseTool):
    """pe.imports — 查询 PE 导入表。

    输入: {"file_path": "<PE 文件路径>"}
    输出: {"status": "success", "imports": [{"dll": str, "name": str}, ...]}
    """

    name = "pe.imports"
    description = "查询 PE 文件导入表，返回所有导入的 DLL 与函数名"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        file_path = self._require(input_data, "file_path")
        pe = pe_api.parse(file_path)
        imports = pe_api.list_imports(pe)
        return {"imports": imports, "count": len(imports)}


class PEExportsTool(BaseTool):
    """pe.exports — 查询 PE 导出表。

    输入: {"file_path": "<PE 文件路径>"}
    输出: {"status": "success", "exports": [{"name": str, "ordinal": int}, ...]}
    """

    name = "pe.exports"
    description = "查询 PE 文件导出表，返回所有导出的函数名与序号"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        file_path = self._require(input_data, "file_path")
        pe = pe_api.parse(file_path)
        exports = pe_api.list_exports(pe)
        return {"exports": exports, "count": len(exports)}


class PESectionsTool(BaseTool):
    """pe.sections — 查询 PE 节区。

    输入: {"file_path": "<PE 文件路径>"}
    输出: {"status": "success", "sections": [{"name": str, "virtual_size": int, ...}, ...]}
    """

    name = "pe.sections"
    description = "查询 PE 文件节区，返回各节区的名称、虚拟大小、虚拟地址等"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        file_path = self._require(input_data, "file_path")
        pe = pe_api.parse(file_path)
        sections = pe_api.list_sections(pe)
        return {"sections": sections, "count": len(sections)}


class PESuspiciousImportsTool(BaseTool):
    """pe.suspicious_imports — 检测可疑导入。

    输入: {"file_path": "<PE 文件路径>"}
    输出: {"status": "success", "suspicious": ["WriteProcessMemory", ...]}
    """

    name = "pe.suspicious_imports"
    description = "检测 PE 文件中的可疑导入（注入/网络/键盘记录等常用 API）"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        file_path = self._require(input_data, "file_path")
        pe = pe_api.parse(file_path)
        suspicious = pe_api.suspicious_imports(pe)
        return {"suspicious": suspicious, "count": len(suspicious)}


class PEMetaTool(BaseTool):
    """pe.meta — 获取 PE 元信息。

    输入: {"file_path": "<PE 文件路径>"}
    输出: {"status": "success", "entry_point": int, "is_64bit": bool, "imphash": str}
    """

    name = "pe.meta"
    description = "获取 PE 文件元信息：入口点 RVA、位数、导入哈希"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        file_path = self._require(input_data, "file_path")
        pe = pe_api.parse(file_path)
        return {
            "entry_point": pe_api.get_entry_point(pe),
            "is_64bit": pe_api.is_64bit(pe),
            "imphash": pe_api.get_imphash(pe),
        }


# 工具实例列表，供 register_all_tools 使用
PE_TOOLS: list[BaseTool] = [
    PEParseTool(),
    PEImportsTool(),
    PEExportsTool(),
    PESectionsTool(),
    PESuspiciousImportsTool(),
    PEMetaTool(),
]
