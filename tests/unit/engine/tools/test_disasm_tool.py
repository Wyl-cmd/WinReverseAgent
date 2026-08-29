"""测试模块：winreverse.engine.tools.disasm_tool

测试反汇编工具。
"""

from __future__ import annotations

import base64
from unittest.mock import patch

import pytest

from winreverse.core.disasm_api import DisasmInstruction
from winreverse.engine.tools.disasm_tool import DISASM_TOOLS, DisasmTool


@pytest.fixture
def mock_disasm_instruction() -> DisasmInstruction:
    """mock 的反汇编指令。"""
    return DisasmInstruction(
        address=0x1000,
        mnemonic="mov",
        op_str="rbp, rsp",
        size=3,
        bytes=b"\x48\x89\xe5",
    )


class TestDisasmTool:
    """disasm 工具测试。"""

    def test_success_with_bytes(self, mock_disasm_instruction: DisasmInstruction) -> None:
        """成功反汇编字节序列（bytes 输入）。"""
        with patch(
            "winreverse.engine.tools.disasm_tool.disasm_api.disasm",
            return_value=[mock_disasm_instruction],
        ) as mock_disasm:
            tool = DisasmTool()
            result = tool.execute(
                {
                    "code": b"\x48\x89\xe5",
                    "arch": "x64",
                    "base_addr": 0x1000,
                }
            )

        assert result["status"] == "success"
        assert result["count"] == 1
        assert result["instructions"][0]["address"] == 0x1000
        assert result["instructions"][0]["mnemonic"] == "mov"
        assert result["instructions"][0]["op_str"] == "rbp, rsp"
        assert result["instructions"][0]["size"] == 3
        mock_disasm.assert_called_once()

    def test_success_with_base64(self, mock_disasm_instruction: DisasmInstruction) -> None:
        """成功反汇编 base64 编码输入。"""
        code_b64 = base64.b64encode(b"\x48\x89\xe5").decode("ascii")
        with patch(
            "winreverse.engine.tools.disasm_tool.disasm_api.disasm",
            return_value=[mock_disasm_instruction],
        ):
            tool = DisasmTool()
            result = tool.execute({"code": code_b64, "arch": "x64"})

        assert result["status"] == "success"
        assert result["count"] == 1

    def test_success_with_list(self, mock_disasm_instruction: DisasmInstruction) -> None:
        """成功反汇编字节列表输入。"""
        with patch(
            "winreverse.engine.tools.disasm_tool.disasm_api.disasm",
            return_value=[mock_disasm_instruction],
        ):
            tool = DisasmTool()
            result = tool.execute({"code": [0x48, 0x89, 0xE5], "arch": "x86"})

        assert result["status"] == "success"

    def test_missing_code(self) -> None:
        """缺少 code 参数时返回 error。"""
        tool = DisasmTool()
        result = tool.execute({"arch": "x64"})
        assert result["status"] == "error"
        assert "code" in result["error_message"]

    def test_missing_arch(self) -> None:
        """缺少 arch 参数时返回 error。"""
        tool = DisasmTool()
        result = tool.execute({"code": b"\x90"})
        assert result["status"] == "error"
        assert "arch" in result["error_message"]

    def test_unsupported_arch(self) -> None:
        """不支持的架构返回 error。"""
        tool = DisasmTool()
        result = tool.execute({"code": b"\x90", "arch": "mips64"})
        assert result["status"] == "error"
        assert "不支持的架构" in result["error_message"]

    def test_default_base_addr(self, mock_disasm_instruction: DisasmInstruction) -> None:
        """base_addr 默认为 0。"""
        with patch(
            "winreverse.engine.tools.disasm_tool.disasm_api.disasm",
            return_value=[mock_disasm_instruction],
        ) as mock_disasm:
            tool = DisasmTool()
            result = tool.execute({"code": b"\x90", "arch": "x64"})

        assert result["status"] == "success"
        # 验证 base_addr 默认为 0
        # disasm_api.disasm 签名: disasm(code, arch, mode, base_addr)
        # base_addr 是第 4 个位置参数（索引 3）
        call_args = mock_disasm.call_args
        assert call_args[0][3] == 0

    def test_empty_code(self) -> None:
        """空字节序列返回 0 条指令。"""
        with patch(
            "winreverse.engine.tools.disasm_tool.disasm_api.disasm",
            return_value=[],
        ):
            tool = DisasmTool()
            result = tool.execute({"code": b"", "arch": "x64"})

        assert result["status"] == "success"
        assert result["count"] == 0
        assert result["instructions"] == []


class TestDisasmToolsList:
    """DISASM_TOOLS 列表测试。"""

    def test_registered(self) -> None:
        """DISASM_TOOLS 应包含 1 个工具。"""
        assert len(DISASM_TOOLS) == 1
        assert DISASM_TOOLS[0].name == "disasm"
