"""winreverse.core.disasm_api — capstone 薄包装层。

仅暴露业务语义 API，隔离 capstone 版本变更对上层调用方的影响。

封装的 capstone 能力：
- x86 / x64 反汇编（disasm_x86 / disasm_x64）
- 通用反汇编（disasm，支持 ARM/ARM64/MIPS 等架构）

返回 DisasmInstruction dataclass，避免上层直接依赖 capstone 类型。

参考：实施方案 §4.2
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_MIPS,
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_ARM,
    CS_MODE_THUMB,
    Cs,
)


@dataclass(frozen=True)
class DisasmInstruction:
    """反汇编指令数据类。

    封装 capstone Instruction 的核心字段，避免上层直接依赖 capstone 类型。

    Attributes:
        address: 指令地址
        mnemonic: 助记符（如 'mov' / 'call' / 'jmp'）
        op_str: 操作数字符串（如 'rbp, rsp'）
        size: 指令字节长度
        bytes: 指令字节序列
    """

    address: int
    mnemonic: str
    op_str: str
    size: int
    bytes: bytes


def disasm(
    code: bytes,
    arch: int,
    mode: int,
    base_addr: int = 0,
) -> list[DisasmInstruction]:
    """通用反汇编函数。

    Args:
        code: 待反汇编的字节序列
        arch: capstone 架构常量（如 CS_ARCH_X86 / CS_ARCH_ARM）
        mode: capstone 模式常量（如 CS_MODE_64 / CS_MODE_ARM）
        base_addr: 基地址（指令地址 = base_addr + offset）

    Returns:
        DisasmInstruction 列表；无法识别的字节自动跳过
    """
    md = Cs(arch, mode)
    return [
        DisasmInstruction(
            address=int(ins.address),
            mnemonic=cast(str, ins.mnemonic),
            op_str=cast(str, ins.op_str),
            size=int(ins.size),
            bytes=bytes(ins.bytes),
        )
        for ins in md.disasm(code, base_addr)
    ]


def disasm_x64(code: bytes, base_addr: int = 0) -> list[DisasmInstruction]:
    """x64 反汇编（CS_ARCH_X86 + CS_MODE_64）。

    Args:
        code: 待反汇编的字节序列
        base_addr: 基地址

    Returns:
        DisasmInstruction 列表
    """
    return disasm(code, CS_ARCH_X86, CS_MODE_64, base_addr)


def disasm_x86(code: bytes, base_addr: int = 0) -> list[DisasmInstruction]:
    """x86 反汇编（CS_ARCH_X86 + CS_MODE_32）。

    Args:
        code: 待反汇编的字节序列
        base_addr: 基地址

    Returns:
        DisasmInstruction 列表
    """
    return disasm(code, CS_ARCH_X86, CS_MODE_32, base_addr)


def disasm_arm(code: bytes, base_addr: int = 0, thumb: bool = False) -> list[DisasmInstruction]:
    """ARM 反汇编（CS_ARCH_ARM + CS_MODE_ARM/CS_MODE_THUMB）。

    Args:
        code: 待反汇编的字节序列
        base_addr: 基地址
        thumb: True 使用 Thumb 模式，False 使用 ARM 模式

    Returns:
        DisasmInstruction 列表
    """
    mode = CS_MODE_THUMB if thumb else CS_MODE_ARM
    return disasm(code, CS_ARCH_ARM, mode, base_addr)


def disasm_arm64(code: bytes, base_addr: int = 0) -> list[DisasmInstruction]:
    """ARM64 反汇编（CS_ARCH_ARM64 + CS_MODE_ARM）。

    Args:
        code: 待反汇编的字节序列
        base_addr: 基地址

    Returns:
        DisasmInstruction 列表
    """
    return disasm(code, CS_ARCH_ARM64, CS_MODE_ARM, base_addr)


def disasm_mips(code: bytes, base_addr: int = 0) -> list[DisasmInstruction]:
    """MIPS 反汇编（CS_ARCH_MIPS + CS_MODE_32）。

    Args:
        code: 待反汇编的字节序列
        base_addr: 基地址

    Returns:
        DisasmInstruction 列表
    """
    return disasm(code, CS_ARCH_MIPS, CS_MODE_32, base_addr)
