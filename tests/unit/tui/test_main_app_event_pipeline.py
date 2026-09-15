"""测试模块：winreverse.tui.main_app — 事件回调管线与尾部分支。

覆盖点：_on_text_event / _on_tool_event（tool_call 与 tool_result 成败两弧）、
_advance_phase_for_tool 前缀分发、_extract_findings 提取策略、
on_input_submitted 的 id 守卫与忙碌守卫及 run_worker 启动、
_cmd_skills 成功/空/异常三弧、_cmd_context 两弧（含 /context 分发行）、
/quit 分支、_init_backend 工厂返 None 与 401/404 提示弧、
_run_prompt 取消弧、_setup_soul_with_callback 无 agent 早退、
launch_main_app 参数转发、PromptInput 键盘历史接线（_on_key/history_prev/next 及空表/最老弧）。
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual import events
from textual.widgets import Input

from winreverse.tui.main_app import MainApp, PromptInput, launch_main_app
from winreverse.tui.panels import EventLog, FindingsPanel, PhaseBar, ToolPanel


def _details(log: EventLog) -> list[str]:
    """提取事件日志的全部 detail 文本。"""
    return [str(e.get("detail", "")) for e in log.events]


class TestToolEventPipeline:
    """_on_text_event / _on_tool_event / _advance_phase_for_tool 回调分发。"""

    @pytest.mark.asyncio
    async def test_on_text_event_appends_thought(self) -> None:
        """AI 发言回调应将完整文本作为 thought 事件写入日志。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            log = app.query_one("#event-log", EventLog)
            count = len(log.events)

            app._on_text_event("正在定位导入表…")

            assert len(log.events) == count + 1
            assert log.events[-1]["event_type"] == "thought"
            assert log.events[-1]["detail"] == "正在定位导入表…"

    @pytest.mark.asyncio
    async def test_on_tool_event_tool_call_updates_panel_log_phase(self) -> None:
        """tool_call 事件应更新工具面板、记录日志并推进解析阶段。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            log = app.query_one("#event-log", EventLog)
            count = len(log.events)

            app._on_tool_event(
                {"type": "tool_call", "name": "pe.parse", "args": {"path": "samples/t.exe"}}
            )

            tool_panel = app.query_one("#tool-col", ToolPanel)
            assert tool_panel.tools["pe"].status == "active"
            assert "pe.parse" in tool_panel.tools["pe"].detail
            new_events = _details(log)[count:]
            assert any("pe.parse(" in d for d in new_events)
            phase_bar = app.query_one("#phase-bar", PhaseBar)
            active = [p.name for p in phase_bar.phases if p.status == "active"]
            assert "解析" in active

    @pytest.mark.asyncio
    async def test_on_tool_event_result_success_logs_completion(self) -> None:
        """tool_result 成功事件应记录完成日志且不产生 finding。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            log = app.query_one("#event-log", EventLog)
            count = len(log.events)

            app._on_tool_event(
                {"type": "tool_result", "name": "pe.parse", "is_error": False, "output": "ok"}
            )

            new_events = log.events[count:]
            assert new_events[-1]["event_type"] == "tool_result"
            assert "pe.parse 完成" in new_events[-1]["detail"]
            assert app.query_one("#findings-col", FindingsPanel).findings == []

    @pytest.mark.asyncio
    async def test_on_tool_event_result_error_logs_failure(self) -> None:
        """tool_result 失败事件应记录 error 日志（截断至 60 字符）。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            log = app.query_one("#event-log", EventLog)
            count = len(log.events)

            app._on_tool_event(
                {
                    "type": "tool_result",
                    "name": "memory.dump",
                    "is_error": True,
                    "output": "x" * 100,
                }
            )

            new_events = log.events[count:]
            assert new_events[-1]["event_type"] == "error"
            assert "memory.dump 失败" in new_events[-1]["detail"]
            # 输出在错误日志中截断到 60 字符
            assert len(new_events[-1]["detail"]) < 100

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("tool_name", "expected_phase"),
        [
            ("pe.parse", "解析"),
            ("memory.strings", "扫描"),
            ("yara.scan_file", "分析"),
            ("die.detect", "分析"),
            ("fs.read_text", None),
        ],
    )
    async def test_advance_phase_prefix_dispatch(
        self, tool_name: str, expected_phase: str | None
    ) -> None:
        """阶段推进按工具名前缀分发，未匹配前缀不改变阶段。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            phase_bar = app.query_one("#phase-bar", PhaseBar)

            app._advance_phase_for_tool(tool_name)

            active = [p.name for p in phase_bar.phases if p.status == "active"]
            if expected_phase is None:
                assert active == []
            else:
                assert active == [expected_phase]


class TestExtractFindings:
    """_extract_findings 的提取策略（可疑 API / YARA 匹配 / 抑制条件）。"""

    @pytest.mark.asyncio
    async def test_suspicious_import_line_becomes_high_finding(self) -> None:
        """pe.suspicious_imports 输出含可疑 API 行时应产生 high finding。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            findings = app.query_one("#findings-col", FindingsPanel)

            # 空行与花括号行应被跳过（continue 弧），只有可疑 API 行入库
            app._extract_findings(
                "pe.suspicious_imports", "\n- VirtualAlloc\n{\n}\n- MessageBoxW\n", False
            )

            assert len(findings.findings) == 1
            assert findings.findings[0].severity == "high"
            assert "VirtualAlloc" in findings.findings[0].title

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("output", "expected_severity"),
        [("rule malware_family matched", "critical"), ("rule demo_1 matched", "medium")],
    )
    async def test_yara_match_severity_depends_on_keyword(
        self, output: str, expected_severity: str
    ) -> None:
        """yara.* 输出含 match 时产生 finding，malware 字样升级 critical。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            findings = app.query_one("#findings-col", FindingsPanel)

            app._extract_findings("yara.scan_file", output, False)

            assert len(findings.findings) == 1
            assert findings.findings[0].severity == expected_severity

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("tool_name", "output", "is_error"),
        [
            ("pe.suspicious_imports", "- VirtualAlloc", True),  # 出错不提取
            ("pe.suspicious_imports", "", False),  # 空输出不提取
            ("pe.parse", "- VirtualAlloc", False),  # 非 suspicious_imports 工具不提取
            ("yara.scan_file", "no hits here", False),  # 无 match 关键字不提取
        ],
    )
    async def test_extract_suppressed_cases(
        self, tool_name: str, output: str, is_error: bool
    ) -> None:
        """错误/空输出/工具不匹配/无关键字时均不产生 finding。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            findings = app.query_one("#findings-col", FindingsPanel)

            app._extract_findings(tool_name, output, is_error)

            assert findings.findings == []


class TestInputSubmittedGuards:
    """on_input_submitted 的 id 守卫 / 忙碌守卫 / worker 启动。"""

    @pytest.mark.asyncio
    async def test_non_prompt_input_ignored(self) -> None:
        """非 prompt-input 的提交事件应被忽略（不产生任何事件）。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            log = app.query_one("#event-log", EventLog)
            count = len(log.events)

            other = Input(id="other-input")
            app.on_input_submitted(Input.Submitted(other, "hello"))

            assert len(log.events) == count

    @pytest.mark.asyncio
    async def test_busy_guard_rejects_second_prompt(self) -> None:
        """_is_running 时再次提交应报忙而不启动新任务。"""
        app = MainApp(agent=MagicMock())
        app._soul_ready = True
        app._is_running = True
        async with app.run_test() as pilot:
            await pilot.pause()
            log = app.query_one("#event-log", EventLog)
            count = len(log.events)

            def fake_run_worker(coro: object, **kwargs: object) -> None:
                coro.close()  # 不真正执行，仅需验证未走到启动

            with pytest.MonkeyPatch().context() as mp:
                mp.setattr(app, "run_worker", fake_run_worker)
                widget = app.query_one("#prompt-input", Input)
                app.on_input_submitted(Input.Submitted(widget, "再跑一个"))

            assert app._is_running is True
            new_events = log.events[count:]
            assert new_events[-1]["event_type"] == "error"
            assert "有任务正在执行" in new_events[-1]["detail"]

    @pytest.mark.asyncio
    async def test_ready_prompt_starts_worker_and_completes(self) -> None:
        """就绪后提交应启动 worker 并在完成时推进报告阶段。"""
        mock_agent = MagicMock()
        mock_agent._soul.run = AsyncMock(return_value="结论：无恶意行为")
        app = MainApp(agent=mock_agent)
        app._soul_ready = True
        async with app.run_test() as pilot:
            await pilot.pause()
            log = app.query_one("#event-log", EventLog)
            count = len(log.events)

            captured: dict[str, object] = {}

            def fake_run_worker(coro: object, **kwargs: object) -> None:
                captured["coro"] = coro

            with pytest.MonkeyPatch().context() as mp:
                mp.setattr(app, "run_worker", fake_run_worker)
                widget = app.query_one("#prompt-input", Input)
                app.on_input_submitted(Input.Submitted(widget, "分析样本"))
            await captured["coro"]  # type: ignore[index]

            assert app._is_running is False
            new_details = _details(log)[count:]
            assert any("任务完成" in d for d in new_details)
            assert any("结论：无恶意行为" in d for d in new_details)
            phase_bar = app.query_one("#phase-bar", PhaseBar)
            assert [p.name for p in phase_bar.phases if p.status == "active"] == ["报告"]


class TestSlashCommandTails:
    """/context 与 /quit 分支及 _cmd_skills 成功/空/异常三弧。"""

    @pytest.mark.asyncio
    async def test_slash_context_without_agent(self) -> None:
        """/context 在无 agent 任务时应提示先发送指令。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            log = app.query_one("#event-log", EventLog)
            count = len(log.events)

            app._run_slash_command("/context")

            new_details = _details(log)[count:]
            assert any("尚无运行中的 Agent 任务" in d for d in new_details)

    @pytest.mark.asyncio
    async def test_slash_context_with_snapshot(self) -> None:
        """/context 在有 agent 实例时应输出 token 用量与调用统计。"""
        mock_agent = MagicMock()
        mock_agent._soul.last_agent.context_snapshot.return_value = {
            "messages": 3,
            "used_tokens": 100,
            "max_context_size": 1000,
            "usage_ratio": 0.1,
            "remaining_tokens": 900,
            "compaction_count": 2,
            "total_usage": {"input": 60, "output": 40, "steps": 2},
        }
        app = MainApp(agent=mock_agent)
        async with app.run_test() as pilot:
            await pilot.pause()
            log = app.query_one("#event-log", EventLog)

            app._cmd_context()

            joined = "\n".join(_details(log))
            assert "上下文: 3 条消息" in joined
            assert "10%" in joined
            assert "压缩 2 次" in joined
            assert "LLM 用量: input 60 tokens" in joined

    @pytest.mark.asyncio
    async def test_slash_quit_exits_app(self) -> None:
        """/quit 应记录再见事件并退出应用。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            log = app.query_one("#event-log", EventLog)
            count = len(log.events)

            with pytest.MonkeyPatch().context() as mp:
                exit_mock = MagicMock()
                mp.setattr(app, "exit", exit_mock)
                app._run_slash_command("/quit")

            exit_mock.assert_called_once()
            assert log.events[count + 1]["detail"] == "再见"

    @pytest.mark.asyncio
    async def test_cmd_skills_lists_registered(self) -> None:
        """/skills 在 agent 就绪时应列出全部注册 Skill。"""
        mock_agent = MagicMock()
        mock_agent._skill_registry.list_skills.return_value = [
            {"name": "pe_basic", "description": "PE 基础解析"},
            {"name": "mem_scan", "description": "内存扫描"},
        ]
        app = MainApp(agent=mock_agent)
        async with app.run_test() as pilot:
            await pilot.pause()
            log = app.query_one("#event-log", EventLog)

            app._cmd_skills()

            joined = "\n".join(_details(log))
            assert "已注册 Skill（共 2 个）" in joined
            assert "- pe_basic: PE 基础解析" in joined
            assert "- mem_scan: 内存扫描" in joined

    @pytest.mark.asyncio
    async def test_cmd_skills_empty_registry(self) -> None:
        """/skills 注册表为空时应提示未找到。"""
        mock_agent = MagicMock()
        mock_agent._skill_registry.list_skills.return_value = []
        app = MainApp(agent=mock_agent)
        async with app.run_test() as pilot:
            await pilot.pause()
            log = app.query_one("#event-log", EventLog)
            count = len(log.events)

            app._cmd_skills()

            assert any("未找到已注册的 Skill" in d for d in _details(log)[count:])

    @pytest.mark.asyncio
    async def test_cmd_skills_init_failure(self) -> None:
        """/skills 初始化失败时应记录错误而不抛出。"""
        mock_agent = MagicMock()
        mock_agent._ensure_initialized.side_effect = RuntimeError("bad key")
        app = MainApp(agent=mock_agent)
        async with app.run_test() as pilot:
            await pilot.pause()
            log = app.query_one("#event-log", EventLog)
            count = len(log.events)

            app._cmd_skills()  # 不应抛异常

            new_events = log.events[count:]
            assert new_events[-1]["event_type"] == "error"
            assert "加载 Skill 失败" in new_events[-1]["detail"]


class TestInitBackendTails:
    """_init_backend 的工厂返 None 早退与 401/404 提示弧。"""

    @pytest.mark.asyncio
    async def test_factory_returning_none_keeps_unready(self) -> None:
        """工厂返回 None 时应静默早退，不误报就绪或失败。"""
        app = MainApp(agent_factory=lambda: None)
        async with app.run_test() as pilot:
            await pilot.pause()

            await app._init_backend()

            assert app._agent is None
            assert app._soul_ready is False
            details = _details(app.query_one("#event-log", EventLog))
            assert not any("初始化失败" in d for d in details)
            assert not any("Soul 引擎就绪" in d for d in details)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("message", "expected_hint"),
        [
            ("HTTP 401 Unauthorized", "API Key 无效"),
            ("model 404 not found", "模型或端点不存在"),
        ],
    )
    async def test_factory_error_hint_variants(self, message: str, expected_hint: str) -> None:
        """工厂异常消息含 401/404 时应附对应设置指引。"""
        app = MainApp(agent_factory=lambda: (_ for _ in ()).throw(RuntimeError(message)))
        async with app.run_test() as pilot:
            await pilot.pause()

            await app._init_backend()

            details = _details(app.query_one("#event-log", EventLog))
            assert app._soul_ready is False
            assert any("初始化失败" in d and expected_hint in d for d in details)

    @pytest.mark.asyncio
    async def test_run_prompt_cancelled_marks_not_running(self) -> None:
        """soul.run 被取消时应记录任务已取消并复位运行态。"""
        mock_agent = MagicMock()
        mock_agent._soul.run = AsyncMock(side_effect=asyncio.CancelledError())
        app = MainApp(agent=mock_agent)
        app._soul_ready = True
        async with app.run_test() as pilot:
            await pilot.pause()
            log = app.query_one("#event-log", EventLog)
            count = len(log.events)

            await app._run_prompt("长任务")

            assert app._is_running is False
            new_events = log.events[count:]
            assert new_events[-1]["event_type"] == "milestone"
            assert new_events[-1]["detail"] == "任务已取消"

    def test_setup_soul_callback_without_agent_is_noop(self) -> None:
        """无 agent 时 _setup_soul_with_callback 应直接返回不报错。"""
        app = MainApp()
        app._setup_soul_with_callback()  # 无 app 上下文也不应触碰 DOM


class TestLaunchMainAppForwarding:
    """launch_main_app 入口的参数转发。"""

    def test_launch_forwards_params_and_runs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """构造参数应原样传入 MainApp 且 run 恰好执行一次。"""
        created: dict[str, MainApp] = {}

        def fake_run(self: MainApp) -> None:
            created["app"] = self

        monkeypatch.setattr(MainApp, "run", fake_run)
        launch_main_app(target="sample.exe", objective="分析")
        assert created["app"].target == "sample.exe"
        assert created["app"].objective == "分析"


class TestPromptInputKeyWiring:
    """PromptInput 键盘历史接线（_on_key / history_prev / history_next）。

    value 是 reactive 属性，赋值/读取需 active app 上下文 → 经 run_test 内真实控件驱动。
    """

    @pytest.mark.asyncio
    async def test_key_up_down_cycle(self) -> None:
        """↑ 取历史、↓ 恢复草稿（经 _on_key 接线）。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            inp = app.query_one("#prompt-input", PromptInput)
            inp.add_history("first cmd")
            inp.value = "draft"

            await inp._on_key(events.Key("up", None))
            assert inp.value == "first cmd"

            await inp._on_key(events.Key("down", None))
            assert inp.value == "draft"

            await inp._on_key(events.Key("a", "a"))  # 其他按键不接管、不报错

    @pytest.mark.asyncio
    async def test_history_prev_next_with_ui_state(self) -> None:
        """history_prev/next 应同步 value 与光标位置。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            inp = app.query_one("#prompt-input", PromptInput)
            inp.add_history("one")
            inp.add_history("two")

            inp.history_prev()
            assert inp.value == "two"
            assert inp.cursor_position == len("two")

            inp.history_prev()
            assert inp.value == "one"

            inp.history_prev()  # 已到最老一条，再按不动
            assert inp.value == "one"

            inp.history_next()
            assert inp.value == "two"

            inp.history_next()  # 越过最新恢复草稿
            assert inp.value == ""
            assert inp.cursor_position == 0

    @pytest.mark.asyncio
    async def test_history_prev_on_empty_keeps_value(self) -> None:
        """空历史时 history_prev 应为无操作。"""
        app = MainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            inp = app.query_one("#prompt-input", PromptInput)
            inp.value = "typed"
            inp.history_prev()
            assert inp.value == "typed"


class TestSetupSoulCallbackInstallsHooks:
    """_setup_soul_with_callback 在 soul 就绪时安装回调。"""

    def test_installs_callbacks_on_soul(self) -> None:
        """soul 存在时应替换 toolset 并挂载文本/工具回调。"""
        soul = SimpleNamespace(
            _registry=object(),
            _toolset=object(),
            _runtime=SimpleNamespace(toolset=object()),
        )
        mock_agent = MagicMock()
        mock_agent._soul = soul
        app = MainApp(agent=mock_agent)

        app._setup_soul_with_callback()

        assert soul._on_tool_event == app._on_tool_event
        assert soul._on_text_event == app._on_text_event
        assert soul._runtime.toolset is soul._toolset
