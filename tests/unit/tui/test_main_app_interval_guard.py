"""回归：MainApp 的 1s 定时器回调在 screen DOM 缺失/重建窗口内不得抛异常。

来源（2026-09-14 真机实测）：guest 全量轮（带覆盖率、CPU 争用）偶发失败，
原始输出为 Textual 致命错误：

    NoMatches: No nodes match '#context-bar' on Screen(id='_default')

隔离复现（清空默认 screen 子节点后直接调用回调）可稳定重放同一异常，
故补两例确定性回归：回调在目标控件不存在时必须静默跳过（no-op）。
"""

from __future__ import annotations

import pytest

from winreverse.tui.main_app import MainApp


class TestIntervalCallbacksTolerateMissingDom:
    """定时器回调应对"控件尚未挂载 / 正在拆除"的窗口免疫。"""

    @pytest.mark.asyncio
    async def test_context_bar_callback_is_noop_when_widget_absent(self) -> None:
        """#context-bar 不存在时 _update_context_bar 应直接返回。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.screen.query("#context-bar"), "前置条件：默认 screen 应含 #context-bar"

            app.screen.remove_children()
            await pilot.pause()
            assert not app.screen.query("#context-bar"), "前置条件：子节点已清空"

            app._update_context_bar()  # 修复前抛 NoMatches

    @pytest.mark.asyncio
    async def test_header_callback_is_noop_when_widget_absent(self) -> None:
        """#header-bar 不存在时 _update_header 应直接返回。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.screen.query("#header-bar"), "前置条件：默认 screen 应含 #header-bar"

            app.screen.remove_children()
            await pilot.pause()
            assert not app.screen.query("#header-bar"), "前置条件：子节点已清空"

            app._update_header()  # 修复前抛 NoMatches
