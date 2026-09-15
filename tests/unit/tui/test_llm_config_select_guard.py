"""被测模块: winreverse.tui.screens.llm_config._get_select_value（真机 coverage 缺 138-141）。

覆盖点: 挂载真实 Select 后查询成功、值为非空字符串时返回该值（138-140）；
Select 处于空白（allow_blank 的 value=None）时回退默认值（141）。
LLMConfigPane 自身未 compose Select，故在 run_test 内动态 mount 构造真实 widget。
"""

from __future__ import annotations

from textual.widgets import Select

from winreverse.config import AppConfig
from winreverse.tui.app import SettingsApp
from winreverse.tui.screens.llm_config import LLMConfigPane


async def test_get_select_value_returns_widget_value() -> None:
    """存在 Select 且值为非空字符串时返回该值而非默认（138-140）。"""
    app = SettingsApp(config=AppConfig())
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(LLMConfigPane)
        await pane.mount(Select([("Anthropic", "anthropic")], value="anthropic", id="provider"))
        await pilot.pause()
        assert pane._get_select_value("provider", "openai") == "anthropic"


async def test_get_select_value_blank_falls_back_to_default() -> None:
    """Select 处于空白（value=None）时回退默认值（141）。"""
    app = SettingsApp(config=AppConfig())
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(LLMConfigPane)
        await pane.mount(Select([("Anthropic", "anthropic")], allow_blank=True, id="provider"))
        await pilot.pause()
        assert pane._get_select_value("provider", "openai") == "openai"
