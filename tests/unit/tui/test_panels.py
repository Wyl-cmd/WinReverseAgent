"""测试模块：winreverse.tui.panels

覆盖面板组件的核心功能：
- PhaseBar：阶段进度条渲染与状态切换
- ToolPanel：工具状态面板的工具调用事件处理
- FindingsPanel：发现面板的添加与统计
- EventLog：事件日志的添加与渲染
"""

from __future__ import annotations

from winreverse.tui.panels import (
    EventLog,
    FindingDisplay,
    FindingsPanel,
    PhaseBar,
    ToolPanel,
    _truncate,
)


class TestTruncate:
    """_truncate 辅助函数测试。"""

    def test_short_string_unchanged(self) -> None:
        """短字符串应原样返回。"""
        assert _truncate("hello", 10) == "hello"

    def test_long_string_truncated(self) -> None:
        """长字符串应截断并加省略号。"""
        result = _truncate("abcdefghijk", 8)
        assert result == "abcde..."
        assert len(result) == 8


class TestPhaseBar:
    """PhaseBar 阶段进度条测试。"""

    def test_init_has_four_phases(self) -> None:
        """初始化应有 4 个阶段，全部 pending。"""
        bar = PhaseBar()
        assert len(bar.phases) == 4
        assert all(p.status == "pending" for p in bar.phases)
        assert bar.phases[0].name == "解析"
        assert bar.phases[1].name == "扫描"
        assert bar.phases[2].name == "分析"
        assert bar.phases[3].name == "报告"

    def test_set_phase_activates_target(self) -> None:
        """set_phase 应激活指定阶段。"""
        bar = PhaseBar()
        bar.set_phase("解析")
        assert bar.phases[0].status == "active"
        assert bar.phases[1].status == "pending"

    def test_set_phase_marks_previous_done(self) -> None:
        """set_phase 应将之前 active 的阶段标记为 done。"""
        bar = PhaseBar()
        bar.set_phase("解析")
        bar.set_phase("扫描")
        assert bar.phases[0].status == "done"
        assert bar.phases[1].status == "active"

    def test_reset_all_pending(self) -> None:
        """reset 应将所有阶段重置为 pending。"""
        bar = PhaseBar()
        bar.set_phase("解析")
        bar.reset()
        assert all(p.status == "pending" for p in bar.phases)

    def test_render_phases_markup(self) -> None:
        """_render_phases 应生成正确的 markup。"""
        bar = PhaseBar()
        result = bar._render_phases(bar.phases)
        assert "解析" in result
        assert "扫描" in result


class TestToolPanel:
    """ToolPanel 工具状态面板测试。"""

    def test_init_has_five_tools(self) -> None:
        """初始化应有 5 个工具组，全部 idle。"""
        panel = ToolPanel()
        assert len(panel.tools) == 5
        assert all(t.status == "idle" for t in panel.tools.values())

    def test_on_tool_call_pe(self) -> None:
        """pe.parse 调用应更新 PE 解析器状态为 active。"""
        panel = ToolPanel()
        panel.on_tool_call("pe.parse", {"file_path": "test.exe"})
        assert panel.tools["pe"].status == "active"
        assert "pe.parse" in panel.tools["pe"].detail

    def test_on_tool_call_memory(self) -> None:
        """memory.attach 调用应更新内存扫描器状态。"""
        panel = ToolPanel()
        panel.on_tool_call("memory.attach", {"process_name": "game.exe"})
        assert panel.tools["memory"].status == "active"

    def test_on_tool_result_success(self) -> None:
        """工具成功完成应更新状态为 complete。"""
        panel = ToolPanel()
        panel.on_tool_call("pe.parse", {"file_path": "test.exe"})
        panel.on_tool_result("pe.parse", is_error=False, output="成功")
        assert panel.tools["pe"].status == "complete"

    def test_on_tool_result_error(self) -> None:
        """工具出错应更新状态为 error。"""
        panel = ToolPanel()
        panel.on_tool_call("pe.parse", {"file_path": "test.exe"})
        panel.on_tool_result("pe.parse", is_error=True, output="文件不存在")
        assert panel.tools["pe"].status == "error"

    def test_on_tool_call_unknown_tool(self) -> None:
        """未知工具调用不应影响任何工具组。"""
        panel = ToolPanel()
        panel.on_tool_call("unknown.tool", {})
        assert all(t.status == "idle" for t in panel.tools.values())

    def test_reset_all_idle(self) -> None:
        """reset 应将所有工具状态重置为 idle。"""
        panel = ToolPanel()
        panel.on_tool_call("pe.parse", {})
        panel.reset()
        assert all(t.status == "idle" for t in panel.tools.values())

    def test_resolve_tool_group(self) -> None:
        """_resolve_tool_group 应正确解析工具组。"""
        panel = ToolPanel()
        assert panel._resolve_tool_group("pe.parse") == "pe"
        assert panel._resolve_tool_group("memory.read") == "memory"
        assert panel._resolve_tool_group("yara.scan_file") == "yara"
        assert panel._resolve_tool_group("die.scan_file") == "die"
        assert panel._resolve_tool_group("disasm") == "disasm"
        assert panel._resolve_tool_group("unknown") is None


class TestFindingsPanel:
    """FindingsPanel 发现面板测试。"""

    def test_init_empty(self) -> None:
        """初始化应为空，所有严重度计数为 0。"""
        panel = FindingsPanel()
        assert len(panel.findings) == 0
        assert panel.severity_map["critical"] == 0
        assert panel.severity_map["high"] == 0

    def test_add_finding(self) -> None:
        """添加发现应更新列表和计数。"""
        panel = FindingsPanel()
        panel.add_finding(FindingDisplay(severity="high", title="可疑 API"))
        assert len(panel.findings) == 1
        assert panel.severity_map["high"] == 1

    def test_add_multiple_findings(self) -> None:
        """添加多条发现应正确统计。"""
        panel = FindingsPanel()
        panel.add_finding(FindingDisplay(severity="critical", title="严重"))
        panel.add_finding(FindingDisplay(severity="high", title="高危"))
        panel.add_finding(FindingDisplay(severity="high", title="高危2"))
        assert len(panel.findings) == 3
        assert panel.severity_map["critical"] == 1
        assert panel.severity_map["high"] == 2

    def test_reset_clears_all(self) -> None:
        """reset 应清空所有发现。"""
        panel = FindingsPanel()
        panel.add_finding(FindingDisplay(severity="high", title="test"))
        panel.reset()
        assert len(panel.findings) == 0
        assert panel.severity_map["high"] == 0

    def test_render_shows_counts(self) -> None:
        """_render_findings 应显示严重度计数。"""
        panel = FindingsPanel()
        panel.add_finding(FindingDisplay(severity="critical", title="严重"))
        result = panel._render_findings(panel.findings)
        assert "严重" in result
        assert "1" in result


class TestEventLog:
    """EventLog 事件日志测试。"""

    def test_init_empty(self) -> None:
        """初始化应为空。"""
        log = EventLog()
        assert len(log.events) == 0

    def test_add_event(self) -> None:
        """添加事件应更新列表。"""
        log = EventLog()
        log.add_event(
            {"event_type": "milestone", "detail": "启动", "timestamp": "2026-01-01T12:00:00"}
        )
        assert len(log.events) == 1
        assert log.events[0]["event_type"] == "milestone"

    def test_render_shows_events(self) -> None:
        """事件完整保留并可查询（RichLog 滚动渲染）。"""
        log = EventLog()
        log.add_event(
            {"event_type": "milestone", "detail": "任务完成", "timestamp": "2026-01-01T12:00:00"}
        )
        assert len(log._events) == 1
        assert log._events[0]["detail"] == "任务完成"

    def test_events_full_text_kept(self) -> None:
        """长文本完整保留（RichLog 可滚动，不截断）。"""
        log = EventLog()
        long_text = "A" * 500
        log.add_event({"event_type": "thought", "detail": long_text})
        assert log._events[-1]["detail"] == long_text
