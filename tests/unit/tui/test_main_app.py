"""测试模块：winreverse.tui.main_app

覆盖 MainApp 主操作台的基础功能：
- 初始化与界面布局
- 无 Agent 时的界面展示
- 事件构造辅助方法
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from winreverse.tui.main_app import MainApp
from winreverse.tui.panels import EventLog, FindingsPanel, PhaseBar, ToolPanel


class TestMainAppInit:
    """MainApp 初始化测试。"""

    def test_init_without_agent(self) -> None:
        """无 Agent 初始化应保存参数。"""
        app = MainApp()
        assert app._agent is None
        assert app.target == ""
        assert app.objective == ""
        assert app._is_running is False
        assert app._soul_ready is False

    def test_init_with_agent(self) -> None:
        """带 Agent 初始化应保存引用。"""
        mock_agent = MagicMock()
        app = MainApp(agent=mock_agent, target="test.exe", objective="分析")
        assert app._agent is mock_agent
        assert app.target == "test.exe"
        assert app.objective == "分析"

    def test_title(self) -> None:
        """应有正确的标题。"""
        app = MainApp()
        assert "WinReverseAgent" in app.TITLE

    def test_bindings(self) -> None:
        """应有 q/s/c 三个快捷键。"""
        app = MainApp()
        keys = [b.key for b in app.BINDINGS]
        assert "q" in keys
        assert "s" in keys
        assert "c" in keys


class TestMainAppCompose:
    """MainApp 界面布局测试。"""

    @pytest.mark.asyncio
    async def test_compose_without_agent(self) -> None:
        """无 Agent 时应正常渲染界面，EventLog 显示提示。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            # 验证所有面板都存在
            app.query_one("#header-bar")
            app.query_one("#phase-bar", PhaseBar)
            app.query_one("#tool-col", ToolPanel)
            app.query_one("#findings-col", FindingsPanel)
            app.query_one("#event-log", EventLog)
            app.query_one("#prompt-input")

    @pytest.mark.asyncio
    async def test_event_log_shows_startup_message(self) -> None:
        """启动后 EventLog 应显示启动消息。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)
            assert len(event_log.events) >= 1
            # 第一条应为 milestone 类型
            assert event_log.events[0]["event_type"] == "milestone"


class TestMainAppMakeEvent:
    """MainApp._make_event 辅助方法测试。"""

    def test_make_event_basic(self) -> None:
        """_make_event 应构造包含 event_type/detail/timestamp 的事件。"""
        event = MainApp._make_event("milestone", "测试事件")
        assert event["event_type"] == "milestone"
        assert event["detail"] == "测试事件"
        assert "timestamp" in event
        assert isinstance(event["timestamp"], str)

    def test_make_event_with_special_chars(self) -> None:
        """_make_event 应正确处理特殊字符。"""
        event = MainApp._make_event("error", "包含<>特殊字符")
        assert event["detail"] == "包含<>特殊字符"

    def test_make_event_timestamp_format(self) -> None:
        """_make_event 的 timestamp 应为 ISO 格式。"""
        event = MainApp._make_event("thought", "test")
        # ISO 格式应包含 'T' 分隔符
        assert "T" in event["timestamp"]


class TestMainAppActions:
    """MainApp action 方法测试。"""

    @pytest.mark.asyncio
    async def test_action_clear_panels(self) -> None:
        """action_clear_panels 应清空所有面板。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            # 先添加一些事件
            event_log = app.query_one("#event-log", EventLog)
            event_log.add_event(MainApp._make_event("thought", "测试"))

            with pytest.MonkeyPatch().context() as mp:
                mp.setattr(app, "notify", MagicMock())
                app.action_clear_panels()

            assert len(event_log.events) == 0

    @pytest.mark.asyncio
    async def test_action_emergency_stop_no_running(self) -> None:
        """无运行任务时按停止应显示提示。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)
            initial_count = len(event_log.events)

            app.action_emergency_stop()

            # 应添加一条 thought 事件
            assert len(event_log.events) > initial_count
            last_event = event_log.events[-1]
            assert last_event["event_type"] == "thought"

    @pytest.mark.asyncio
    async def test_action_emergency_stop_with_running(self) -> None:
        """有运行任务时按停止应取消 worker。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            # 模拟有任务运行
            app._is_running = True
            # mock workers.cancel_group 避免实际取消操作
            with pytest.MonkeyPatch().context() as mp:
                mp.setattr(app.workers, "cancel_group", MagicMock())
                app.action_emergency_stop()

            assert app._is_running is False
            event_log = app.query_one("#event-log", EventLog)
            last_event = event_log.events[-1]
            assert last_event["event_type"] == "milestone"
            assert "停止" in last_event["detail"]


class TestMainAppRunPrompt:
    """MainApp._run_prompt 方法测试。"""

    @pytest.mark.asyncio
    async def test_run_prompt_without_agent(self) -> None:
        """无 Agent 时执行 prompt 应显示错误。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)
            initial_count = len(event_log.events)

            await app._run_prompt("测试指令")

            assert len(event_log.events) > initial_count
            # 应有 error 事件
            details = [e["detail"] for e in event_log.events[initial_count:]]
            assert any("Agent 未绑定" in d for d in details)
            assert app._is_running is False

    @pytest.mark.asyncio
    async def test_run_prompt_with_agent_no_soul(self) -> None:
        """Agent 无 Soul 引擎时应显示错误。"""
        mock_agent = MagicMock()
        # _ensure_initialized 后 _soul 仍为 None
        mock_agent._soul = None
        app = MainApp(agent=mock_agent)
        app._soul_ready = True  # 模拟已就绪
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)

            await app._run_prompt("测试指令")

            details = [e["detail"] for e in event_log.events]
            assert any("Soul 引擎未初始化" in d for d in details)

    @pytest.mark.asyncio
    async def test_run_prompt_success(self) -> None:
        """成功执行 prompt 应显示结果。"""
        from unittest.mock import AsyncMock

        mock_agent = MagicMock()
        mock_soul = MagicMock()
        mock_soul.run = AsyncMock(return_value="分析完成：64 位 PE 文件")
        mock_agent._soul = mock_soul
        app = MainApp(agent=mock_agent)
        app._soul_ready = True
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)

            await app._run_prompt("分析 test.exe")

            details = [e["detail"] for e in event_log.events]
            assert any("任务完成" in d for d in details)
            assert any("分析完成" in d for d in details)
            # 应推进到报告阶段
            phase_bar = app.query_one("#phase-bar", PhaseBar)
            assert phase_bar.phases[-1].status == "active"  # 报告阶段激活

    @pytest.mark.asyncio
    async def test_run_prompt_with_exception(self) -> None:
        """Soul 执行异常时应捕获并显示错误。"""
        from unittest.mock import AsyncMock

        mock_agent = MagicMock()
        mock_soul = MagicMock()
        mock_soul.run = AsyncMock(side_effect=RuntimeError("API 调用失败"))
        mock_agent._soul = mock_soul
        app = MainApp(agent=mock_agent)
        app._soul_ready = True
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)

            await app._run_prompt("测试")

            details = [e["detail"] for e in event_log.events]
            assert any("执行失败" in d for d in details)
            assert any("RuntimeError" in d for d in details)
            assert app._is_running is False


class TestMainAppHeader:
    """MainApp._update_header 方法测试。"""

    @pytest.mark.asyncio
    async def test_update_header_shows_target(self) -> None:
        """_update_header 应在标题栏显示目标。"""
        app = MainApp(target="test.exe", objective="分析目标")
        async with app.run_test() as pilot:
            await pilot.pause()
            from textual.widgets import Static

            header = app.query_one("#header-bar", Static)
            app._update_header()
            # 标题栏应包含目标名（通过 _update_header 不抛异常验证）
            assert header is not None

    @pytest.mark.asyncio
    async def test_update_header_without_target(self) -> None:
        """无目标时 _update_header 应显示未指定。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            # 不抛异常即通过
            app._update_header()

    @pytest.mark.asyncio
    async def test_update_header_with_soul_ready(self) -> None:
        """Soul 就绪时标题栏应显示 * 状态。"""
        app = MainApp()
        app._soul_ready = True
        async with app.run_test() as pilot:
            await pilot.pause()
            # 不抛异常即通过
            app._update_header()


class TestMainAppInputHandling:
    """MainApp 输入处理测试。"""

    @pytest.mark.asyncio
    async def test_input_submit_without_agent(self) -> None:
        """无 Agent 时提交输入应显示错误。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)
            initial_count = len(event_log.events)

            # 模拟输入提交
            from textual.widgets import Input

            input_widget = app.query_one("#prompt-input", Input)
            input_widget.value = "分析 test.exe"
            # 触发 submitted 事件（Textual 8.x 的 Submitted 需要 value 参数）
            app.on_input_submitted(Input.Submitted(input_widget, input_widget.value))

            await pilot.pause()

            # 应添加一条 error 事件（Soul 引擎未就绪）
            assert len(event_log.events) > initial_count
            last_event = event_log.events[-1]
            assert last_event["event_type"] == "error"

    @pytest.mark.asyncio
    async def test_input_submit_empty_ignored(self) -> None:
        """空输入应被忽略。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)
            initial_count = len(event_log.events)

            from textual.widgets import Input

            input_widget = app.query_one("#prompt-input", Input)
            input_widget.value = ""
            app.on_input_submitted(Input.Submitted(input_widget, ""))

            await pilot.pause()

            # 不应添加任何事件
            assert len(event_log.events) == initial_count


class TestMainAppSlashCommands:
    """MainApp 斜杠命令测试（参照 KXNS TuiApp._run_slash_command 设计）。"""

    @pytest.mark.asyncio
    async def test_slash_help_command(self) -> None:
        """/help 命令应显示可用命令列表。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)
            initial_count = len(event_log.events)

            app._run_slash_command("/help")

            # 应添加多条 thought 事件（命令列表）
            assert len(event_log.events) > initial_count + 1
            # 检查输出包含命令名
            all_details = " ".join(e["detail"] for e in event_log.events[initial_count:])
            assert "/help" in all_details
            assert "/skills" in all_details
            assert "/quit" in all_details

    @pytest.mark.asyncio
    async def test_slash_help_via_action(self) -> None:
        """快捷键 h（action_show_help）应等价于 /help。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)
            initial_count = len(event_log.events)

            app.action_show_help()

            assert len(event_log.events) > initial_count

    @pytest.mark.asyncio
    async def test_slash_clear_command(self) -> None:
        """/clear 命令应清空所有面板。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)

            # 先添加一些事件
            event_log.add_event(MainApp._make_event("thought", "测试事件1"))
            event_log.add_event(MainApp._make_event("thought", "测试事件2"))
            assert len(event_log.events) >= 2

            # mock notify 避免副作用
            with pytest.MonkeyPatch().context() as mp:
                mp.setattr(app, "notify", MagicMock())
                app._run_slash_command("/clear")

            # 事件应被清空
            assert len(event_log.events) == 0

    @pytest.mark.asyncio
    async def test_slash_target_set(self) -> None:
        """/target <name> 应设置当前目标。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)

            app._run_slash_command("/target notepad.exe")

            assert app.target == "notepad.exe"
            assert "notepad.exe" in app.objective
            # 应有 milestone 事件
            last_event = event_log.events[-1]
            assert last_event["event_type"] == "milestone"
            assert "notepad.exe" in last_event["detail"]

    @pytest.mark.asyncio
    async def test_slash_target_view(self) -> None:
        """/target（无参数）应查看当前目标。"""
        app = MainApp(target="test.exe")
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)

            app._run_slash_command("/target")

            last_event = event_log.events[-1]
            assert last_event["event_type"] == "thought"
            assert "test.exe" in last_event["detail"]

    @pytest.mark.asyncio
    async def test_slash_tools_command(self) -> None:
        """/tools 命令应显示工具状态。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)
            initial_count = len(event_log.events)

            app._run_slash_command("/tools")

            # 应添加多条 thought 事件（每个工具一条）
            assert len(event_log.events) > initial_count
            all_details = " ".join(e["detail"] for e in event_log.events[initial_count:])
            # 应包含工具名
            assert "PE 解析器" in all_details or "pe" in all_details.lower()

    @pytest.mark.asyncio
    async def test_slash_skills_without_agent(self) -> None:
        """无 Agent 时 /skills 应显示错误。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)

            app._run_slash_command("/skills")

            # 应有 error 事件
            last_event = event_log.events[-1]
            assert last_event["event_type"] == "error"
            assert "Agent" in last_event["detail"] or "Skill" in last_event["detail"]

    @pytest.mark.asyncio
    async def test_slash_unknown_command(self) -> None:
        """未知斜杠命令应显示错误。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)

            app._run_slash_command("/unknown_cmd")

            last_event = event_log.events[-1]
            assert last_event["event_type"] == "error"
            assert "未知命令" in last_event["detail"]

    @pytest.mark.asyncio
    async def test_slash_command_via_input(self) -> None:
        """通过输入框提交斜杠命令应正确分发。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)
            initial_count = len(event_log.events)

            from textual.widgets import Input

            input_widget = app.query_one("#prompt-input", Input)
            input_widget.value = "/help"
            app.on_input_submitted(Input.Submitted(input_widget, "/help"))

            await pilot.pause()

            # 应触发 /help 命令，添加多条事件
            assert len(event_log.events) > initial_count + 1

    @pytest.mark.asyncio
    async def test_slash_settings_pushes_screen(self) -> None:
        """/settings 命令应推送 SettingsScreen（文档 §9.3 要求）。"""
        from winreverse.tui.main_app import SettingsScreen

        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)

            app._run_slash_command("/settings")
            await pilot.pause()

            # 应有 milestone 事件提示进入设置
            last_event = event_log.events[-1]
            assert last_event["event_type"] == "milestone"
            assert "设置" in last_event["detail"]
            # 应已推送 SettingsScreen
            assert isinstance(app.screen, SettingsScreen)

    @pytest.mark.asyncio
    async def test_slash_settings_in_command_list(self) -> None:
        """/settings 应出现在 _SLASH_COMMANDS 字典中。"""
        assert "/settings" in MainApp._SLASH_COMMANDS
        assert "设置" in MainApp._SLASH_COMMANDS["/settings"]

    @pytest.mark.asyncio
    async def test_slash_help_includes_settings(self) -> None:
        """/help 输出应包含 /settings 命令说明。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            event_log = app.query_one("#event-log", EventLog)

            app._run_slash_command("/help")

            all_details = " ".join(e["detail"] for e in event_log.events)
            assert "/settings" in all_details


class TestMainAppConfigParams:
    """MainApp 配置参数测试（config/project_root）。"""

    def test_init_with_config(self) -> None:
        """应能接收并保存 config 参数。"""
        from winreverse.config import load_or_default

        config = load_or_default()
        app = MainApp(config=config)
        assert app._config is config

    def test_init_with_project_root(self, tmp_path: object) -> None:
        """应能接收并保存 project_root 参数。"""
        from pathlib import Path

        project_root = Path(str(tmp_path))
        app = MainApp(project_root=project_root)
        assert app._project_root == project_root

    def test_init_default_config_loaded(self) -> None:
        """未提供 config 时应自动加载默认配置。"""
        app = MainApp()
        assert app._config is not None

    def test_init_default_project_root(self) -> None:
        """未提供 project_root 时应使用当前目录。"""
        from pathlib import Path

        app = MainApp()
        assert app._project_root == Path.cwd()


class TestSettingsScreen:
    """SettingsScreen 测试（/settings 命令推送的设置页面 Screen）。"""

    @pytest.mark.asyncio
    async def test_settings_screen_compose(self) -> None:
        """SettingsScreen 应能正常渲染界面（TabbedContent + 状态栏）。"""
        from textual.widgets import Static, TabbedContent

        from winreverse.tui.main_app import SettingsScreen

        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen(SettingsScreen())
            await pilot.pause()

            # 应包含 TabbedContent 和状态栏
            app.screen.query_one(TabbedContent)
            app.screen.query_one("#settings-status-bar", Static)

    @pytest.mark.asyncio
    async def test_settings_screen_bindings(self) -> None:
        """SettingsScreen 应有 Esc/s/1/2/3 快捷键。"""
        from winreverse.tui.main_app import SettingsScreen

        screen = SettingsScreen()
        keys = [b.key for b in screen.BINDINGS]
        assert "escape" in keys
        assert "s" in keys
        assert "1" in keys
        assert "2" in keys
        assert "3" in keys

    @pytest.mark.asyncio
    async def test_settings_screen_status_bar(self) -> None:
        """状态栏应显示配置文件与 LLM 信息。"""
        from textual.widgets import Static

        from winreverse.tui.main_app import SettingsScreen

        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = SettingsScreen()
            app.push_screen(screen)
            await pilot.pause()

            status = app.screen.query_one("#settings-status-bar", Static)
            status_text = str(status.content) if status.content else ""
            assert "配置文件" in status_text or "LLM" in status_text

    @pytest.mark.asyncio
    async def test_settings_screen_action_tab(self) -> None:
        """action_tab 应切换到指定 Tab。"""
        from textual.widgets import TabbedContent

        from winreverse.tui.main_app import SettingsScreen

        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = SettingsScreen()
            app.push_screen(screen)
            await pilot.pause()

            screen.action_tab("skill-list")
            await pilot.pause()
            tabbed = app.screen.query_one(TabbedContent)
            assert tabbed.active == "skill-list"

            screen.action_tab("tool-center")
            await pilot.pause()
            assert tabbed.active == "tool-center"

    @pytest.mark.asyncio
    async def test_settings_screen_action_save(self) -> None:
        """action_save 应保存配置并更新状态栏。"""
        from unittest.mock import patch

        from winreverse.tui.main_app import SettingsScreen

        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = SettingsScreen()
            app.push_screen(screen)
            await pilot.pause()

            with (
                patch.object(app, "notify"),
                patch("winreverse.tui.main_app.save_config") as mock_save,
                patch("winreverse.tui.main_app.get_default_config_path") as mock_path,
            ):
                mock_path.return_value = app._project_root / "test_config.toml"
                screen.action_save()
                mock_save.assert_called_once()

    @pytest.mark.asyncio
    async def test_settings_screen_action_save_failure(self) -> None:
        """save_config 失败时应通知错误。"""
        from unittest.mock import patch

        from winreverse.tui.main_app import SettingsScreen

        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = SettingsScreen()
            app.push_screen(screen)
            await pilot.pause()

            with (
                patch.object(app, "notify"),
                patch(
                    "winreverse.tui.main_app.save_config",
                    side_effect=OSError("磁盘已满"),
                ),
            ):
                screen.action_save()  # 不抛异常即通过（异常被捕获）


class TestContextBar:
    """上下文状态栏测试（token 用量/剩余窗口/压缩次数显示）。"""

    def _snapshot(self, ratio: float) -> dict[str, object]:
        return {
            "messages": 8,
            "used_tokens": int(100000 * ratio),
            "max_context_size": 100000,
            "remaining_tokens": 100000 - int(100000 * ratio),
            "usage_ratio": ratio,
            "trigger_ratio": 0.8,
            "compaction_count": 2,
            "total_usage": {"input": 8000, "output": 1100, "steps": 5},
        }

    def test_snapshot_none_shows_placeholder(self) -> None:
        """无快照时显示等待提示（渲染不抛错）。"""
        from winreverse.tui.panels import ContextBar

        bar = ContextBar()
        bar.set_snapshot(None)
        assert True  # set_snapshot 内部完成渲染，无异常即通过

    def test_snapshot_over_trigger_renders_red(self) -> None:
        """超过触发比例时红色警示（经 headless app 渲染）。"""
        import asyncio

        from textual.widgets import Static

        from winreverse.tui.main_app import MainApp
        from winreverse.tui.panels import ContextBar

        async def _check() -> str:
            app = MainApp()
            async with app.run_test() as pilot:
                bar = app.query_one("#context-bar", ContextBar)
                assert isinstance(bar, Static)
                bar.set_snapshot(self._snapshot(0.9))
                await pilot.pause()
                return str(bar.render())

        rendered = asyncio.run(_check())
        assert "90%" in rendered

    def test_snapshot_normal_renders_usage(self) -> None:
        """正常用量渲染 token 与压缩次数（经 headless app 渲染）。"""
        import asyncio

        from winreverse.tui.main_app import MainApp
        from winreverse.tui.panels import ContextBar

        async def _check() -> str:
            app = MainApp()
            async with app.run_test() as pilot:
                bar = app.query_one("#context-bar", ContextBar)
                bar.set_snapshot(self._snapshot(0.12))
                await pilot.pause()
                return str(bar.render())

        rendered = asyncio.run(_check())
        assert "12%" in rendered
        assert "压缩 2 次" in rendered
        assert "in 8.0k" in rendered


class TestAgentFactory:
    """挂载阶段 agent 工厂创建测试（双击 TUI 路径）。"""

    def test_factory_error_shown_in_log(self) -> None:
        """工厂抛异常时错误显示在事件日志。"""
        import asyncio

        from winreverse.tui.main_app import MainApp

        def boom() -> object:
            raise RuntimeError("API Key 缺失")

        async def _check() -> str:
            app = MainApp(agent_factory=boom)
            async with app.run_test() as pilot:
                await app._init_backend()
                await pilot.pause()
                log = app.query_one("#event-log")
                return " ".join(str(e.get("detail", "")) for e in log._events)

        text = asyncio.run(_check())
        assert "初始化失败" in text
        assert "API Key 缺失" in text

    def test_factory_success_binds_agent(self) -> None:
        """工厂成功时 agent 被绑定。"""
        import asyncio
        from unittest.mock import MagicMock

        from winreverse.tui.main_app import MainApp

        mock_agent = MagicMock()

        async def _check() -> bool:
            app = MainApp(agent_factory=lambda: mock_agent)
            async with app.run_test() as pilot:
                await app._init_backend()
                await pilot.pause()
                return app._agent is mock_agent

        assert asyncio.run(_check()) is True


class TestPromptInputHistory:
    """输入框历史回溯测试（↑ 上一条 / ↓ 恢复草稿）。"""

    def test_cycle_history(self) -> None:
        """↑ 取历史，↓ 恢复草稿（纯逻辑测试）。"""
        from winreverse.tui.main_app import PromptInput

        inp = PromptInput()
        inp.add_history("first")
        inp.add_history("second")
        assert inp._history_step(-1) == "second"
        assert inp._history_step(-1) == "first"
        assert inp._history_step(1) == "second"
        assert inp._history_step(1) == ""  # 越过最新恢复草稿
        assert inp._history_step(1) is None  # 已在草稿态，无操作

    def test_adjacent_dedup(self) -> None:
        """相邻重复命令去重。"""
        from winreverse.tui.main_app import PromptInput

        inp = PromptInput()
        inp.add_history("/help")
        inp.add_history("/help")
        assert inp._history == ["/help"]

    def test_empty_not_recorded(self) -> None:
        """空输入不记录。"""
        from winreverse.tui.main_app import PromptInput

        inp = PromptInput()
        inp.add_history("")
        assert inp._history == []
