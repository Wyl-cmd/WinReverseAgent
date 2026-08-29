"""winreverse.engine.tools.yara_tools — YARA 扫描工具。

将 core.yara_api 封装为 ToolInterface 实现。

工具清单：
- yara.scan_file: 用 YARA 规则扫描文件
- yara.scan_memory: 用 YARA 规则扫描字节序列

参考：实施方案 §7.2
"""

from __future__ import annotations

import base64
from typing import Any

from winreverse.core import yara_api
from winreverse.engine.tools._base import BaseTool


class YaraScanFileTool(BaseTool):
    """yara.scan_file — 用 YARA 规则扫描文件。

    输入: {
        "rule_text": "rule test { condition: true }",  # YARA 规则源码
        "file_path": "<待扫描文件路径>"
    }
    输出: {
        "status": "success",
        "matches": [{"rule": str, "namespace": str, "tags": [...], "meta": {...}}, ...],
        "count": int
    }
    """

    name = "yara.scan_file"
    description = "用 YARA 规则源码扫描指定文件，返回命中的规则列表"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        rule_text = self._require(input_data, "rule_text")
        file_path = self._require(input_data, "file_path")

        rules = yara_api.compile_source(rule_text)
        matches = yara_api.scan_file(rules, file_path)
        return {
            "matches": [
                {
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "tags": m.tags,
                    "meta": m.meta,
                }
                for m in matches
            ],
            "count": len(matches),
        }


class YaraScanMemoryTool(BaseTool):
    """yara.scan_memory — 用 YARA 规则扫描字节序列。

    输入: {
        "rule_text": "rule test { condition: true }",  # YARA 规则源码
        "data": "<base64 编码的字节序列>"
    }
    输出: {
        "status": "success",
        "matches": [{"rule": str, "namespace": str, "tags": [...], "meta": {...}}, ...],
        "count": int
    }
    """

    name = "yara.scan_memory"
    description = "用 YARA 规则源码扫描字节序列（内存数据），返回命中的规则列表"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        rule_text = self._require(input_data, "rule_text")
        data_raw = self._require(input_data, "data")

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

        rules = yara_api.compile_source(rule_text)
        matches = yara_api.scan_bytes(rules, data)
        return {
            "matches": [
                {
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "tags": m.tags,
                    "meta": m.meta,
                }
                for m in matches
            ],
            "count": len(matches),
        }


# 工具实例列表
YARA_TOOLS: list[BaseTool] = [YaraScanFileTool(), YaraScanMemoryTool()]
