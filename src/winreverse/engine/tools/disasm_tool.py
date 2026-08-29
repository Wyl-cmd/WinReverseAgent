"""winreverse.engine.tools.disasm_tool — 反汇编工具。

将 core.disasm_api 封装为 ToolInterface 实现。

工具清单：
- disasm: 反汇编字节序列（支持 x86/x64/arm/arm64/thumb/mips 架构）

参考：实施方案 §7.2
"""

from __future__ import annotations

from typing import Any

from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_MIPS,
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_ARM,
    CS_MODE_THUMB,
)

from winreverse.core import disasm_api
from winreverse.engine.tools._base import BaseTool

# 架构名到 (arch, mode) 的映射。
# 直接引用 capstone 常量，避免硬编码数字带来的同步风险
# （capstone 各常量值跨版本可能调整，曾因硬编码导致 CS_ERR_MODE 错误）。
_ARCH_MAP: dict[str, tuple[int, int]] = {
    "x86": (CS_ARCH_X86, CS_MODE_32),
    "x64": (CS_ARCH_X86, CS_MODE_64),
    "arm": (CS_ARCH_ARM, CS_MODE_ARM),
    "arm64": (CS_ARCH_ARM64, CS_MODE_ARM),
    "thumb": (CS_ARCH_ARM, CS_MODE_THUMB),
    "mips": (CS_ARCH_MIPS, CS_MODE_32),
}


class DisasmTool(BaseTool):
    """disasm — 反汇编字节序列。

    输入: {
        "code": "<base64 编码的字节序列>",
        "arch": "x64",  # x86/x64/arm/arm64/thumb/mips
        "base_addr": 0  # 可选，默认 0
    }
    输出: {
        "status": "success",
        "instructions": [
            {"address": int, "mnemonic": str, "op_str": str, "size": int},
            ...
        ],
        "count": int
    }

    Note:
        code 参数支持 base64 编码字符串或直接的字节列表（list[int]）。
        base64 方式便于 JSON 传输；字节列表方式便于测试。
    """

    name = "disasm"
    description = "反汇编字节序列，支持 x86/x64/arm/arm64/thumb/mips 架构"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        import base64

        code_raw = self._require(input_data, "code")
        arch_name = self._require(input_data, "arch")
        base_addr = input_data.get("base_addr", 0)

        # 解析 code 参数
        if isinstance(code_raw, str):
            # base64 编码字符串
            code = base64.b64decode(code_raw)
        elif isinstance(code_raw, list):
            # 字节列表
            code = bytes(code_raw)
        elif isinstance(code_raw, (bytes, bytearray)):
            code = bytes(code_raw)
        else:
            return {
                "status": "error",
                "error_message": f"code 参数类型不支持: {type(code_raw).__name__}",
            }

        # 解析架构
        if arch_name not in _ARCH_MAP:
            return {
                "status": "error",
                "error_message": (
                    f"不支持的架构: {arch_name}（支持: {', '.join(_ARCH_MAP.keys())}）"
                ),
            }
        arch, mode = _ARCH_MAP[arch_name]

        instructions = disasm_api.disasm(code, arch, mode, int(base_addr))
        return {
            "instructions": [
                {
                    "address": ins.address,
                    "mnemonic": ins.mnemonic,
                    "op_str": ins.op_str,
                    "size": ins.size,
                }
                for ins in instructions
            ],
            "count": len(instructions),
        }


# 工具实例列表
DISASM_TOOLS: list[BaseTool] = [DisasmTool()]
