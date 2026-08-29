"""测试模块：winreverse.tui.app.SettingsApp

覆盖：
- SettingsApp 初始化（默认配置 / 自定义配置 / project_root）
- compose 创建的 TabbedContent 与 3 个 TabPane（id 为 llm-config / skill-list / tool-center）
- action_save 调用 save_config 并触发 notify
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from textual.widgets import TabbedContent, TabPane

from winreverse.config import AppConfig, LLMConfig
from winreverse.tui.app import SettingsApp
from winreverse.tui.screens.llm_config import LLMConfigPane
from winreverse.tui.screens.skill_list import SkillListPane
from winreverse.tui.screens.tool_center import ToolCenterPane


def test_app_init_with_default_config() -> None:
    """无参数初始化时，config 应为 AppConfig 实例。"""
    app = SettingsApp()
    assert isinstance(app.config, AppConfig)


def test_app_init_with_custom_config() -> None:
    """传入自定义 AppConfig 时应被采用。"""
    custom = AppConfig(llm=LLMConfig(provider="openai", model="gpt-4"))
    app = SettingsApp(config=custom)
    assert app.config is custom
    assert app.config.llm.provider == "openai"


def test_app_init_with_project_root() -> None:
    """传入 project_root 时应被采用。"""
    root = Path("/tmp/some-project")
    app = SettingsApp(project_root=root)
    assert app.project_root == root


async def test_app_compose_creates_tabs() -> None:
    """compose 应创建 TabbedContent 与 3 个 TabPane。"""
    app = SettingsApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        # TabbedContent 存在
        assert app.query_one(TabbedContent) is not None
        # 3 个 TabPane 都存在（按 id 查询）
        assert app.query_one("#llm-config", TabPane) is not None
        assert app.query_one("#skill-list", TabPane) is not None
        assert app.query_one("#tool-center", TabPane) is not None
        # 各 Pane 类型正确
        assert app.query_one(LLMConfigPane) is not None
        assert app.query_one(SkillListPane) is not None
        assert app.query_one(ToolCenterPane) is not None


async def test_app_action_save() -> None:
    """action_save 应调用 save_config 并触发 notify。"""
    app = SettingsApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        # mock save_config 避免写真实文件，mock notify 避免触发通知副作用
        with (
            patch("winreverse.tui.app.save_config") as mock_save,
            patch.object(app, "notify") as mock_notify,
        ):
            app.action_save()
            mock_save.assert_called_once()
            mock_notify.assert_called_once()


async def test_app_has_status_bar() -> None:
    """compose 应创建底部状态栏。"""
    app = SettingsApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        status = app.query_one("#settings-status-bar")
        assert status is not None
        # 状态栏应显示配置文件信息（通过 _render_status_bar 验证内容）
        from textual.widgets import Static

        assert isinstance(status, Static)
        # 直接验证 _render_status_bar 返回值包含关键字
        content = app._render_status_bar()
        assert "配置文件" in content


async def test_app_action_tab_switch() -> None:
    """action_tab 应切换到指定 Tab。"""
    app = SettingsApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        tabbed = app.query_one(TabbedContent)
        # 初始 Tab 应为 llm-config
        assert tabbed.active == "llm-config"

        # 切换到 skill-list
        app.action_tab("skill-list")
        await pilot.pause()
        assert tabbed.active == "skill-list"

        # 切换到 tool-center
        app.action_tab("tool-center")
        await pilot.pause()
        assert tabbed.active == "tool-center"

        # 切换回 llm-config
        app.action_tab("llm-config")
        await pilot.pause()
        assert tabbed.active == "llm-config"


async def test_app_bindings_include_tab_shortcuts() -> None:
    """BINDINGS 应包含 1/2/3 数字键用于 Tab 切换。"""
    app = SettingsApp()
    keys = [b.key for b in app.BINDINGS]
    assert "1" in keys
    assert "2" in keys
    assert "3" in keys
    assert "q" in keys
    assert "s" in keys


async def test_app_render_status_bar() -> None:
    """_render_status_bar 应包含配置文件名和 LLM 信息。"""
    from winreverse.config import LLMConfig

    custom = AppConfig(llm=LLMConfig(provider="openai", model="gpt-4"))
    app = SettingsApp(config=custom)
    result = app._render_status_bar()
    assert "配置文件" in result
    assert "openai" in result
    assert "gpt-4" in result
