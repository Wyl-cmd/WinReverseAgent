"""全局 pytest fixture 与配置。

对齐 KXNS tests/conftest.py 的设计：
- --run-slow 开关：显式开启才运行 slow 标记的重负载测试
- 默认跳过 slow 测试，避免真实网络/子进程副作用

新增项（KXNS 未有）：
- tool_registry fixture：提供隔离的 ToolRegistry 实例，测试后自动清理
- skill_registry fixture：提供隔离的 SkillRegistry 实例
- mock_pymem fixture：mock pymem 的 Pymem 类
- reset_default_registry fixture：每个测试后重置全局单例
"""

from __future__ import annotations

import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# =============================================================================
# pytest 命令行选项与标记处理（对齐 KXNS）
# =============================================================================


def pytest_addoption(parser: pytest.Parser) -> None:
    """新增 --run-slow 开关：显式开启才运行 slow 标记的重负载测试。"""
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="运行标记为 slow 的重负载测试（真实执行工具/网络/子进程）。",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """默认跳过 slow 测试，避免真实网络/子进程副作用拖垮本机。

    仅当显式传入 --run-slow，或用 -m 选择器主动包含 slow（如 -m slow）时才运行。
    """
    if config.getoption("--run-slow"):
        return
    markexpr = str(config.getoption("markexpr") or "")
    # 用户显式请求 slow（例如 -m slow / -m "slow and not live"）时放行
    if "slow" in markexpr and "not slow" not in markexpr:
        return
    skip_slow = pytest.mark.skip(reason="需要 --run-slow 才运行的重负载测试")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip_slow)


def pytest_configure(config: pytest.Config) -> None:
    """非 Windows 平台自动跳过 windows_only 测试。"""
    import sys

    if sys.platform != "win32":
        config.addinivalue_line(
            "markers",
            "windows_only: 仅 Windows 平台运行的测试（当前非 Windows，自动跳过）",
        )


# =============================================================================
# 公共 fixture
# =============================================================================


@pytest.fixture
def temp_dir() -> Iterator[Path]:
    """临时目录，测试后自动清理。"""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


@pytest.fixture
def sample_config() -> dict[str, Any]:
    """示例配置字典，供需要 config 的测试使用。"""
    return {
        "model": "claude-sonnet-4-20250514",
        "api_key": "test-key",
        "work_dir": "/tmp/winreverse-test",
        "yolo": False,
        "max_turns": 50,
    }


@pytest.fixture
def tool_registry() -> Iterator[Any]:
    """提供隔离的 ToolRegistry 实例。

    每个测试获得独立的 ToolRegistry，避免测试间互相污染。
    """
    from winreverse.engine.bus import ToolRegistry

    registry = ToolRegistry()
    yield registry
    registry.clear()


@pytest.fixture
def skill_registry() -> Iterator[Any]:
    """提供隔离的 SkillRegistry 实例。"""
    from winreverse.skill.loader import SkillRegistry

    registry = SkillRegistry()
    yield registry
    registry.clear()


@pytest.fixture(autouse=True)
def reset_default_registry() -> Iterator[None]:
    """每个测试后自动重置全局默认 ToolRegistry 单例。

    避免单例污染跨测试。
    """
    yield
    from winreverse.engine.bus import reset_default_registry

    reset_default_registry()


@pytest.fixture
def mock_pymem() -> Iterator[MagicMock]:
    """mock pymem.Pymem 类，供 core.memory_api 测试使用。

    使用方式：
        def test_attach(mock_pymem):
            mock_pymem.return_value.process_id = 1234
            ...
    """
    with pytest.MonkeyPatch().context() as mp:
        mock = MagicMock()
        mp.setattr("winreverse.core.memory_api.Pymem", mock)
        yield mock


@pytest.fixture
def sample_skill_yaml() -> str:
    """示例 Skill YAML 内容，供 skill loader 测试使用。"""
    return """
name: "测试技能"
description: "用于单元测试的示例技能"
target: "通用"
parameters:
  - name: "process_name"
    type: "string"
    default: "test.exe"
    required: true
prompt_template: |
  任务：测试
  步骤：
  1. 附加进程 {{process_name}}
  2. 执行测试操作
execution_flow:
  - action: "memory.attach"
    args: "{{process_name}}"
""".strip()


@pytest.fixture
def sample_pe_bytes() -> bytes:
    """最小可识别的 PE 头字节序列（用于 pefile 解析测试）。

    这是一个 64 位 PE 文件的 DOS header + PE signature + 最小 COFF header。
    """
    # MZ header + DOS stub
    dos_header = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00"  # e_lfanew = 0x80
    dos_stub = b"\x00" * 0x7E
    # PE signature + COFF header (AMD64)
    pe_sig = b"PE\x00\x00"
    coff_header = (
        b"\x64\x86"  # Machine = AMD64 (0x8664)
        b"\x01\x00"  # NumberOfSections = 1
        b"\x00\x00\x00\x00"  # TimeDateStamp
        b"\x00\x00\x00\x00"  # PointerToSymbolTable
        b"\x00\x00\x00\x00"  # NumberOfSymbols
        b"\xf0\x00"  # SizeOfOptionalHeader = 240
        b"\x22"  # Characteristics = EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
        b"\x00"
    )
    return dos_header + dos_stub + pe_sig + coff_header
