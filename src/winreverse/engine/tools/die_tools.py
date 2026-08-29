"""winreverse.engine.tools.die_tools — DIE 扫描工具。

将 core.die_api 封装为 ToolInterface 实现。

工具清单：
- die.scan_file: 用 Detect It Easy 扫描文件，识别壳/编译器/语言
- die.scan_memory: 用 DIE 扫描字节序列

参考：实施方案 §7.2
"""

from __future__ import annotations

import base64
from typing import Any

from winreverse.core import die_api
from winreverse.engine.tools._base import BaseTool


class DieScanFileTool(BaseTool):
    """die.scan_file — 用 DIE 扫描文件。

    输入: {
        "file_path": "<待扫描文件路径>",
        "deep": false,       # 可选，启用深度扫描
        "heuristic": false,  # 可选，启用启发式扫描
        "recursive": false   # 可选，启用递归扫描
    }
    输出: {
        "status": "success",
        "result": {...},  # DIE 解析后的字典（含 'detects' 列表）
        "version": str
    }
    """

    name = "die.scan_file"
    description = "用 Detect It Easy 扫描文件，识别壳/编译器/语言/工具链"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        file_path = self._require(input_data, "file_path")
        deep = bool(input_data.get("deep", False))
        heuristic = bool(input_data.get("heuristic", False))
        recursive = bool(input_data.get("recursive", False))

        result = die_api.scan_file(file_path, deep, heuristic, recursive)
        return {
            "result": result,
            "version": die_api.get_version(),
        }


class DieScanMemoryTool(BaseTool):
    """die.scan_memory — 用 DIE 扫描字节序列。

    输入: {
        "data": "<base64 编码的字节序列>",
        "deep": false,       # 可选
        "heuristic": false,  # 可选
        "recursive": false   # 可选
    }
    输出: {
        "status": "success",
        "result": {...},
        "version": str
    }
    """

    name = "die.scan_memory"
    description = "用 Detect It Easy 扫描字节序列（内存数据），识别壳/编译器/语言"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        data_raw = self._require(input_data, "data")
        deep = bool(input_data.get("deep", False))
        heuristic = bool(input_data.get("heuristic", False))
        recursive = bool(input_data.get("recursive", False))

        # 解析 data 参数
        if isinstance(data_raw, str):
            data = base64.b64decode(data_raw)
        elif isinstance(data_raw, (list, bytes, bytearray)):
            data = bytes(data_raw)
        else:
            return {
                "status": "error",
                "error_message": f"data 参数类型不支持: {type(data_raw).__name__}",
            }

        result = die_api.scan_bytes(data, deep, heuristic, recursive)
        return {
            "result": result,
            "version": die_api.get_version(),
        }


# 工具实例列表
DIE_TOOLS: list[BaseTool] = [DieScanFileTool(), DieScanMemoryTool()]
