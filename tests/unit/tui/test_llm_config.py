"""测试模块：winreverse.tui.screens.llm_config.LLMConfigPane

覆盖：
- LLMConfigPane 初始化
- compose 创建的 Input / Select widget
- apply_to_config 将界面值回写到 AppConfig
- apply_to_config 在未修改时保留默认值
"""

from __future__ import annotations

from textual.widgets import Input

from winreverse.config import AppConfig
from winreverse.tui.app import SettingsApp
from winreverse.tui.screens.llm_config import LLMConfigPane


def test_pane_init() -> None:
    """LLMConfigPane 初始化应保存 config 引用。"""
    config = AppConfig()
    pane = LLMConfigPane(config)
    assert pane.config is config


async def test_pane_compose() -> None:
    """compose 应创建所需的 Input 与 Select widget。"""
    app = SettingsApp(config=AppConfig())
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(LLMConfigPane)
        # 验证 Select（provider）
        # 验证 Input widget（model / api-key / base-url / max-tokens / temperature）
        assert pane.query_one("#model", Input) is not None
        assert pane.query_one("#api-key", Input) is not None
        assert pane.query_one("#base-url", Input) is not None
        assert pane.query_one("#max-tokens", Input) is not None
        assert pane.query_one("#temperature", Input) is not None


async def test_apply_to_config() -> None:
    """修改界面值后，apply_to_config 应正确更新 AppConfig。"""
    app = SettingsApp(config=AppConfig())
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(LLMConfigPane)
        # 修改界面值
        pane.query_one("#model", Input).value = "gpt-4o"
        pane.query_one("#api-key", Input).value = "sk-test"
        pane.query_one("#base-url", Input).value = "https://api.openai.com/v1"
        pane.query_one("#max-tokens", Input).value = "4096"
        pane.query_one("#temperature", Input).value = "0.5"
        # 应用到新 config
        new_config = AppConfig()
        pane.apply_to_config(new_config)
        assert new_config.llm.model == "gpt-4o"
        assert new_config.llm.api_key == "sk-test"
        assert new_config.llm.base_url == "https://api.openai.com/v1"
        assert new_config.llm.max_tokens == 4096
        assert new_config.llm.temperature == 0.5


async def test_apply_to_config_preserves_defaults() -> None:
    """未修改界面值时，apply_to_config 应保留默认配置值。"""
    app = SettingsApp(config=AppConfig())
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(LLMConfigPane)
        new_config = AppConfig()
        pane.apply_to_config(new_config)
        # 默认值应保持
        assert new_config.llm.provider == "openai"
        assert new_config.llm.model == ""
        assert new_config.llm.api_key == ""
        assert new_config.llm.base_url == ""
        assert new_config.llm.max_tokens == 8192
        assert new_config.llm.temperature == 0.7
