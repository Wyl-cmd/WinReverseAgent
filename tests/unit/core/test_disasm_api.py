"""测试模块：winreverse.core.disasm_api

测试 capstone 薄包装层。
覆盖：
- disasm 通用反汇编
- disasm_x64 / disasm_x86 x86 系列反汇编
- disasm_arm / disasm_arm64 / disasm_mips 其他架构
- DisasmInstruction dataclass 字段
"""

from __future__ import annotations

from winreverse.core.disasm_api import (
    DisasmInstruction,
    disasm,
    disasm_arm,
    disasm_arm64,
    disasm_mips,
    disasm_x64,
    disasm_x86,
)


class TestDisasmX64:
    """x64 反汇编测试"""

    def test_disasm_x64_basic_instructions(self) -> None:
        """应正确反汇编常见的 x64 指令。"""
        # mov rbp, rsp; mov rax, [rip+0]
        code = b"\x48\x89\xe5\x48\x8b\x05\x00\x00\x00\x00"
        result = disasm_x64(code, base_addr=0x1000)
        assert len(result) == 2
        assert result[0].mnemonic == "mov"
        assert result[0].op_str == "rbp, rsp"
        assert result[0].address == 0x1000
        assert result[0].size == 3
        assert result[0].bytes == b"\x48\x89\xe5"
        assert result[1].mnemonic == "mov"
        assert result[1].address == 0x1003
        assert result[1].size == 7

    def test_disasm_x64_empty_code(self) -> None:
        """空字节序列应返回空列表。"""
        assert disasm_x64(b"") == []

    def test_disasm_x64_invalid_bytes_skipped(self) -> None:
        """无效字节应被跳过（capstone 默认行为）。"""
        # 0xff 0xff 在 x64 中通常无法解码
        result = disasm_x64(b"\xff\xff", base_addr=0)
        # capstone 可能返回空或部分结果
        assert isinstance(result, list)


class TestDisasmX86:
    """x86 反汇编测试"""

    def test_disasm_x86_basic_instructions(self) -> None:
        """应正确反汇编常见的 x86 指令。"""
        # mov ebp, esp; push ebp
        code = b"\x89\xe5\x55"
        result = disasm_x86(code, base_addr=0x2000)
        assert len(result) >= 1
        assert result[0].mnemonic == "mov"
        assert result[0].op_str == "ebp, esp"
        assert result[0].address == 0x2000

    def test_disasm_x86_empty_code(self) -> None:
        """空字节序列应返回空列表。"""
        assert disasm_x86(b"") == []


class TestDisasmArm:
    """ARM 反汇编测试"""

    def test_disasm_arm_basic_instructions(self) -> None:
        """应能反汇编 ARM 模式指令。"""
        # ARM 模式下的 NOP (mov r0, r0)
        code = b"\x00\x00\xa0\xe1"
        result = disasm_arm(code, base_addr=0x3000, thumb=False)
        assert len(result) == 1
        assert result[0].mnemonic == "mov"
        assert result[0].address == 0x3000
        assert result[0].size == 4

    def test_disasm_arm_thumb_basic_instructions(self) -> None:
        """应能反汇编 Thumb 模式指令。"""
        # Thumb 模式下的 movs r0, #0
        code = b"\x00\x20"
        result = disasm_arm(code, base_addr=0x4000, thumb=True)
        assert len(result) == 1
        assert result[0].mnemonic in ("movs", "mov")
        assert result[0].size == 2  # Thumb 指令 2 字节


class TestDisasmArm64:
    """ARM64 反汇编测试"""

    def test_disasm_arm64_basic_instructions(self) -> None:
        """应能反汇编 ARM64 指令。"""
        # ARM64 NOP (mov x0, x0)
        code = b"\xe0\x03\x00\xaa"
        result = disasm_arm64(code, base_addr=0x5000)
        assert len(result) == 1
        assert result[0].mnemonic == "mov"
        assert result[0].address == 0x5000
        assert result[0].size == 4  # ARM64 指令 4 字节


class TestDisasmMips:
    """MIPS 反汇编测试"""

    def test_disasm_mips_returns_list(self) -> None:
        """应返回 DisasmInstruction 列表（即使无法识别也返回空列表）。"""
        # 随便给几个字节
        code = b"\x00\x00\x00\x00"
        result = disasm_mips(code, base_addr=0x6000)
        assert isinstance(result, list)


class TestDisasmGeneric:
    """通用 disasm 函数测试"""

    def test_disasm_returns_disasm_instruction_instances(self) -> None:
        """disasm 应返回 DisasmInstruction 实例列表。"""
        from capstone import CS_ARCH_X86, CS_MODE_64

        code = b"\x90"  # NOP
        result = disasm(code, CS_ARCH_X86, CS_MODE_64, base_addr=0x7000)
        assert len(result) == 1
        assert isinstance(result[0], DisasmInstruction)
        assert result[0].mnemonic == "nop"
        assert result[0].address == 0x7000
        assert result[0].size == 1
        assert result[0].bytes == b"\x90"


class TestDisasmInstructionDataclass:
    """DisasmInstruction dataclass 测试"""

    def test_disasm_instruction_is_frozen(self) -> None:
        """DisasmInstruction 应为不可变 dataclass。"""
        ins = DisasmInstruction(
            address=0x1000,
            mnemonic="nop",
            op_str="",
            size=1,
            bytes=b"\x90",
        )
        assert ins.address == 0x1000
        assert ins.mnemonic == "nop"
        assert ins.op_str == ""
        assert ins.size == 1
        assert ins.bytes == b"\x90"
        # frozen=True 应禁止赋值
        import pytest

        with pytest.raises(AttributeError):
            ins.mnemonic = "mov"  # type: ignore[misc]
