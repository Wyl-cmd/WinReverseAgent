"""冒烟测试：验证包可正常导入。

这是最基础的测试，确保项目结构与 pyproject.toml 配置正确。
如果此测试失败，说明环境配置有问题，后续测试都无意义。
"""

from __future__ import annotations

import pytest


def test_package_importable() -> None:
    """主包 winreverse 可导入。"""
    import winreverse

    assert hasattr(winreverse, "__version__")
    assert isinstance(winreverse.__version__, str)


def test_kosong_workspace_importable() -> None:
    """workspace 成员包 kosong 可导入，且暴露核心 LLM 抽象。"""
    import kosong

    # KXNS 的 kosong 包未定义 __version__，通过 __all__ 验证导出完整性
    assert hasattr(kosong, "__all__")
    assert len(kosong.__all__) >= 20  # 核心导出至少 20 个符号
    # 验证关键导出项
    assert "generate" in kosong.__all__
    assert "ProviderRuntime" in kosong.__all__
    assert "Message" in kosong.__all__


def test_engine_subpackage_importable() -> None:
    """engine 子包可导入，且暴露核心契约。"""
    from winreverse.engine import bus, mcp_adapter, sandbox_runner

    assert hasattr(bus, "ToolInterface")
    assert hasattr(bus, "ToolRegistry")
    assert hasattr(mcp_adapter, "MCPConfig")
    assert hasattr(sandbox_runner, "SandboxRunner")


def test_skill_subpackage_importable() -> None:
    """skill 子包可导入，且暴露核心契约。"""
    from winreverse.skill import loader

    assert hasattr(loader, "Skill")
    assert hasattr(loader, "SkillLoader")
    assert hasattr(loader, "SkillRegistry")


def test_soul_subpackage_importable() -> None:
    """soul 子包可导入，且暴露核心契约。"""
    from winreverse.soul import (
        AgentState,
    )

    # 验证枚举值
    assert AgentState.IDLE.value == "idle"
    assert AgentState.RUNNING.value == "running"
    assert AgentState.FINISHED.value == "finished"


def test_pytest_markers_registered(pytestconfig: pytest.Config) -> None:
    """测试标记已注册（live/slow/windows_only/requires_admin）。"""
    markers = pytestconfig.getini("markers")
    marker_names = [m.split(":")[0].strip() for m in markers]
    assert "live" in marker_names
    assert "slow" in marker_names
    assert "windows_only" in marker_names
    assert "requires_admin" in marker_names
