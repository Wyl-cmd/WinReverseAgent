"""被测模块: winreverse.tui.panels 收尾路径（真机 coverage 缺 6 行）。

覆盖点: ToolPanel.on_tool_result 未分组工具早退、FindingsPanel 超过 5 条时
只渲染最近 5 条、add_finding 未知严重度归入 info、EventLog.events 批量重置
逐条回放、clear_events 清空、ContextBar 用量 60%~触发比例之间黄色警示带。
Linux 可实跑（依 WINREVERSE_TASKS.md L5-L6 不加平台守卫）。
"""

from __future__ import annotations

import asyncio

from rich.text import Text

from winreverse.tui.panels import (
    ContextBar,
    EventLog,
    FindingDisplay,
    FindingsPanel,
    ToolPanel,
)


class TestToolPanelUnknownTool:
    def test_on_tool_result_unknown_tool_keeps_state(self) -> None:
        """无法归组的工具名（如 fs.read）早退，五组工具状态保持 idle（276）。"""
        panel = ToolPanel()
        before = {key: (t.status, t.detail) for key, t in panel.tools.items()}
        panel.on_tool_result("fs.read", is_error=True, output="boom")
        after = {key: (t.status, t.detail) for key, t in panel.tools.items()}
        assert before == after
        assert all(status == "idle" for status, _ in after.values())


class TestFindingsPanelWindow:
    def test_render_shows_only_last_five_of_six(self) -> None:
        """发现超过 5 条时只渲染最近 5 条，最旧一条不出现（346）。"""
        panel = FindingsPanel()
        for i in range(6):
            panel.add_finding(FindingDisplay(severity="high", title=f"发现{i}"))
        rendered = panel._render_findings(panel.findings)
        assert "发现0" not in rendered
        for i in range(1, 6):
            assert f"发现{i}" in rendered

    def test_add_finding_unknown_severity_counts_as_info(self) -> None:
        """未知严重度计入 info 桶而不是丢统计（364）。"""
        panel = FindingsPanel()
        panel.add_finding(FindingDisplay(severity="weird", title="怪严重度"))
        assert panel.severity_map["info"] == 1
        assert panel.severity_map["high"] == 0


class TestEventLogBulkReset:
    def test_events_setter_replays_each_event(self) -> None:
        """events 整体重置时逐条回放写入（401）。"""
        log = EventLog()
        batch = [
            {"event_type": "milestone", "detail": "第一条", "timestamp": "t1"},
            {"event_type": "error", "detail": "第二条", "timestamp": "t2"},
        ]
        log.events = batch
        assert log.events == batch
        assert log._events[1]["detail"] == "第二条"

    def test_clear_events_empties_log(self) -> None:
        """clear_events 清空事件列表（432）。"""
        log = EventLog()
        log.add_event({"event_type": "thought", "detail": "待清除"})
        log.clear_events()
        assert log.events == []


class TestContextBarYellowBand:
    def test_snapshot_between_60pct_and_trigger_renders_yellow(self) -> None:
        """用量处于 [60%, 触发比例) 区间时整条黄色警示（477）。"""
        from winreverse.tui.main_app import MainApp

        snapshot = {
            "messages": 8,
            "used_tokens": 70000,
            "max_context_size": 100000,
            "remaining_tokens": 30000,
            "usage_ratio": 0.7,
            "trigger_ratio": 0.8,
            "compaction_count": 1,
            "total_usage": {"input": 6000, "output": 900, "steps": 3},
        }

        async def _check() -> Text:
            app = MainApp()
            async with app.run_test() as pilot:
                bar = app.query_one("#context-bar", ContextBar)
                bar.set_snapshot(snapshot)
                await pilot.pause()
                return bar.render()  # type: ignore[return-value]

        rendered = asyncio.run(_check())
        assert "70%" in str(rendered)
        assert any(span.style == "yellow" for span in rendered.spans)
