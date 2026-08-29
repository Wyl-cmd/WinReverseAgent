"""winreverse.tui.main_app — 主操作台 TUI 应用。

参照 KXNS Hunter CLI 的 TuiApp 设计，适配 Windows 逆向场景。
六区域布局：
    ┌─ Header（WinReverse Agent + 目标 + 计时）─────────────┐
    ├─ PhaseBar（逆向阶段：解析 → 扫描 → 分析 → 报告）──────┤
    ├──────────────┬──────────────────────────────────────┤
    │ ToolPanel    │ FindingsPanel                        │
    │ (工具状态)   │ (发现/结果)                          │
    ├──────────────┴──────────────────────────────────────┤
    │ EventLog（事件日志）                                 │
    ├─────────────────────────────────────────────────────┤
    │ Input（输入框：自然语言/斜杠命令）                   │
    └─ Footer（快捷键）───────────────────────────────────┘

数据流：
1. 用户在 Input 输入提示词
2. run_worker 异步执行 soul.run(prompt)
3. SoulToolsetAdapter 通过 on_tool_event 回调实时推送工具调用事件
4. 事件分发到 ToolPanel / EventLog / FindingsPanel
5. soul.run() 返回最终结果，显示在 EventLog

参考：KXNS src/kxns/ui/tui/app.py
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Footer, Header, Input, Static, TabbedContent, TabPane

from winreverse.config import (
    AppConfig,
    get_default_config_path,
    load_or_default,
    save_config,
)
from winreverse.tui.panels import (
    ContextBar,
    EventLog,
    FindingDisplay,
    FindingsPanel,
    PhaseBar,
    ToolPanel,
)
from winreverse.tui.screens.llm_config import LLMConfigPane
from winreverse.tui.screens.skill_list import SkillListPane
from winreverse.tui.screens.tool_center import ToolCenterPane


class MainApp(App[None]):
    """WinReverseAgent 主操作台 TUI 应用。

    参照 KXNS Hunter CLI 的六区域布局，提供逆向工作的实时可视化界面。
    用户输入自然语言指令，Agent 自动调用逆向工具，实时展示工具状态、发现与事件日志。

    Attributes:
        agent: Agent 实例（业务编排层，含 Soul 引擎）
        target: 当前目标（文件路径或进程名）
        objective: 任务目标描述
    """

    TITLE = "WinReverseAgent 主操作台"
    SUB_TITLE = "Windows 逆向工程 AI Agent"

    CSS = """
    Screen {
        layout: vertical;
    }
    #header-bar {
        height: 3;
        padding: 0 1;
    }
    #phase-bar {
        height: 3;
        padding: 0 1;
    }
    #context-bar {
        height: 1;
        padding: 0 1;
        background: #1a1a2e;
    }
    #main-area {
        layout: horizontal;
        height: 1fr;
    }
    #tool-col {
        width: 45%;
        padding: 0 1;
        border-right: solid #808080;
    }
    #findings-col {
        width: 55%;
        padding: 0 1;
    }
    #event-log {
        height: 35%;
        padding: 0 1;
        border-top: solid #808080;
    }
    #prompt-input {
        dock: bottom;
        height: 3;
        padding: 0 1;
        border-top: solid #808080;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "退出", show=True),
        Binding("s", "emergency_stop", "停止", show=True),
        Binding("c", "clear_panels", "清屏", show=True),
        Binding("h", "show_help", "帮助", show=True),
    ]

    # 斜杠命令白名单（参照 KXNS TUI_SCAN_SLASH_ALIASES 设计）
    _SLASH_COMMANDS: dict[str, str] = {
        "/help": "显示可用命令与快捷键",
        "/skills": "列出已注册的 Skill",
        "/tools": "显示逆向工具状态",
        "/target": "设置或查看当前目标（如 /target notepad.exe）",
        "/settings": "进入可视化设置页面（LLM/Skill/工具管理）",
        "/context": "查看上下文状态（token 用量/剩余窗口/压缩次数）",
        "/clear": "清空所有面板内容",
        "/quit": "退出主操作台",
    }

    def __init__(
        self,
        agent: Any | None = None,
        target: str = "",
        objective: str = "",
        config: AppConfig | None = None,
        project_root: Path | None = None,
        agent_factory: Any = None,
    ) -> None:
        """初始化主操作台。

        Args:
            agent: Agent 实例（业务编排层），None 时可在挂载后由 agent_factory 创建
            target: 当前目标（文件路径或进程名）
            objective: 任务目标描述
            config: 应用配置（/settings 命令使用），None 时从默认路径加载
            project_root: 项目根目录（/settings 命令定位 manifest），None 时使用当前目录
            agent_factory: Agent 工厂（无 agent 时于挂载阶段调用创建，错误显示在事件日志）
        """
        super().__init__()
        self._agent = agent
        self._agent_factory = agent_factory
        self.target = target
        self.objective = objective
        self.start_time = time.monotonic()
        self._is_running = False
        self._soul_ready = False
        # 配置与项目根目录（供 /settings 跳转使用）
        if config is None:
            config = load_or_default()
        self._config = config
        self._project_root = project_root if project_root is not None else Path.cwd()

    def compose(self) -> ComposeResult:
        """构建六区域界面布局。"""
        yield Header()
        yield Static(id="header-bar")
        yield PhaseBar(id="phase-bar")
        yield ContextBar(id="context-bar")
        with Horizontal(id="main-area"):
            yield ToolPanel(id="tool-col")
            yield FindingsPanel(id="findings-col")
        yield EventLog(id="event-log")
        yield PromptInput(
            placeholder="输入逆向指令，或 /help 查看命令（↑↓ 翻历史 /skills /tools /target）",
            id="prompt-input",
        )
        yield Footer()

    def on_mount(self) -> None:
        """界面挂载时初始化。"""
        self._update_header()
        self.set_interval(1.0, self._update_header)
        self._update_context_bar()
        self.set_interval(1.0, self._update_context_bar)

        event_log = self.query_one("#event-log", EventLog)
        event_log.add_event(self._make_event("milestone", "WinReverseAgent 主操作台已启动"))

        if self._agent is not None or self._agent_factory is not None:
            event_log.add_event(self._make_event("thought", "正在初始化 Soul 引擎..."))
            self.run_worker(self._init_backend(), name="init-backend", group="backend")
        else:
            event_log.add_event(self._make_event("thought", "未绑定 Agent，仅展示界面"))

    async def _init_backend(self) -> None:
        """初始化 Soul 引擎后端。"""
        try:
            if self._agent is None and self._agent_factory is not None:
                event_log = self.query_one("#event-log", EventLog)
                event_log.add_event(
                    self._make_event("thought", "正在创建 Agent（读取配置与 API Key）...")
                )
                self._agent = self._agent_factory()
            if self._agent is None:
                return
            self._agent._ensure_initialized()

            # 创建带事件回调的 Soul 引擎
            self._setup_soul_with_callback()

            self._soul_ready = True
            event_log = self.query_one("#event-log", EventLog)
            event_log.add_event(self._make_event("milestone", "Soul 引擎就绪"))

            tool_panel = self.query_one("#tool-col", ToolPanel)
            _ = tool_panel  # 触发渲染

        except Exception as e:
            hint = ""
            text = str(e)
            if "401" in text or "Unauthorized" in text:
                hint = "（API Key 无效，可用 /settings 修改后重试）"
            elif "404" in text:
                hint = "（模型或端点不存在，可用 /settings 修改）"
            event_log = self.query_one("#event-log", EventLog)
            event_log.add_event(
                self._make_event("error", f"初始化失败: {type(e).__name__}: {str(e)[:120]} {hint}")
            )

    def _setup_soul_with_callback(self) -> None:
        """为 Soul 引擎安装工具事件回调。

        最小改动策略：不替换整个 Soul 实例，只替换其 toolset 适配器，
        注入 on_tool_event 回调用于 TUI 实时更新。
        """
        if self._agent is None:
            return
        soul = getattr(self._agent, "_soul", None)
        if soul is None:
            return

        # 创建带回调的新 toolset
        from winreverse.soul.toolset import SoulToolsetAdapter

        registry = soul._registry
        new_toolset = SoulToolsetAdapter(
            registry,
            on_tool_event=self._on_tool_event,
        )
        soul._toolset = new_toolset
        soul._on_tool_event = self._on_tool_event

        # 更新 runtime 的 toolset
        soul._runtime.toolset = new_toolset

        # AI 发言实时回调（每轮 assistant 文本）
        soul._on_text_event = self._on_text_event

    def _on_text_event(self, text: str) -> None:
        """AI 每轮发言的实时回调（完整文本写入可滚动日志）。"""
        event_log = self.query_one("#event-log", EventLog)
        event_log.add_event(self._make_event("thought", text))

    def _on_tool_event(self, event: dict[str, Any]) -> None:
        """工具调用事件回调（由 SoulToolsetAdapter 触发）。

        Args:
            event: 事件字典，包含 type/name/args/is_error/output 等字段
        """
        event_type = event.get("type", "")
        tool_name = event.get("name", "")

        if event_type == "tool_call":
            args = event.get("args", {})
            # 更新工具面板
            tool_panel = self.query_one("#tool-col", ToolPanel)
            tool_panel.on_tool_call(tool_name, args)
            # 记录事件日志
            event_log = self.query_one("#event-log", EventLog)
            arg_str = ", ".join(f"{k}={str(v)[:20]}" for k, v in list(args.items())[:2])
            event_log.add_event(self._make_event("tool_call", f"{tool_name}({arg_str})"))
            # 推进阶段
            self._advance_phase_for_tool(tool_name)

        elif event_type == "tool_result":
            is_error = event.get("is_error", False)
            output = event.get("output", "")
            # 更新工具面板
            tool_panel = self.query_one("#tool-col", ToolPanel)
            tool_panel.on_tool_result(tool_name, is_error, output)
            # 记录事件日志
            event_log = self.query_one("#event-log", EventLog)
            if is_error:
                event_log.add_event(self._make_event("error", f"{tool_name} 失败: {output[:60]}"))
            else:
                event_log.add_event(self._make_event("tool_result", f"{tool_name} 完成"))
            # 尝试从结果中提取发现
            self._extract_findings(tool_name, output, is_error)

    def _advance_phase_for_tool(self, tool_name: str) -> None:
        """根据工具调用推进逆向阶段。

        Args:
            tool_name: 工具调用名
        """
        phase_bar = self.query_one("#phase-bar", PhaseBar)
        if tool_name.startswith("pe."):
            phase_bar.set_phase("解析")
        elif tool_name.startswith("memory."):
            phase_bar.set_phase("扫描")
        elif tool_name.startswith("yara.") or tool_name.startswith("die."):
            phase_bar.set_phase("分析")

    def _extract_findings(self, tool_name: str, output: str, is_error: bool) -> None:
        """从工具调用结果中提取发现项。

        简单策略：可疑 API 工具的结果提取为 finding。

        Args:
            tool_name: 工具调用名
            output: 工具输出
            is_error: 是否出错
        """
        if is_error or not output:
            return

        findings_panel = self.query_one("#findings-col", FindingsPanel)

        # pe.suspicious_imports 的结果中包含可疑 API
        if tool_name == "pe.suspicious_imports":
            # 简单解析：输出中包含函数名的行
            for line in output.split("\n"):
                line = line.strip()
                if not line or line in ("{", "}", "[", "]"):
                    continue
                # 提取函数名（简单策略：包含 "name" 字段的行）
                if "RegCreateKey" in line or "WriteProcessMemory" in line or "VirtualAlloc" in line:
                    findings_panel.add_finding(
                        FindingDisplay(
                            severity="high",
                            title=f"可疑 API: {line[:40]}",
                            target="PE 导入表",
                        )
                    )

        # yara.scan_file 的结果中包含匹配规则
        if tool_name.startswith("yara.") and "match" in output.lower():
            findings_panel.add_finding(
                FindingDisplay(
                    severity="critical" if "malware" in output.lower() else "medium",
                    title="YARA 规则匹配",
                    target="文件扫描",
                )
            )

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """处理用户输入提交。"""
        if event.input.id != "prompt-input":
            return

        prompt = event.value.strip()
        if not prompt:
            return

        if isinstance(event.input, PromptInput):
            event.input.add_history(prompt)
        event.input.value = ""

        # 斜杠命令分发（参照 KXNS _run_slash_command 设计）
        if prompt.startswith("/"):
            self._run_slash_command(prompt)
            return

        if self._agent is None or not self._soul_ready:
            event_log = self.query_one("#event-log", EventLog)
            event_log.add_event(self._make_event("error", "Soul 引擎未就绪，无法执行任务"))
            return

        if self._is_running:
            event_log = self.query_one("#event-log", EventLog)
            event_log.add_event(self._make_event("error", "有任务正在执行，按 's' 停止后重试"))
            return

        self.run_worker(
            self._run_prompt(prompt),
            name=f"prompt-{time.monotonic()}",
            group="prompt",
        )

    def _run_slash_command(self, prompt: str) -> None:
        """执行斜杠命令（参照 KXNS TuiApp._run_slash_command 设计）。

        支持的命令：
        - /help：显示可用命令与快捷键
        - /skills：列出已注册的 Skill
        - /tools：显示逆向工具状态
        - /target [name]：设置或查看当前目标
        - /clear：清空所有面板内容
        - /quit：退出主操作台

        Args:
            prompt: 用户输入的完整命令（如 '/help' 或 '/target notepad.exe'）
        """
        event_log = self.query_one("#event-log", EventLog)
        parts = prompt.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        event_log.add_event(self._make_event("milestone", f">>> {prompt[:60]}"))

        if cmd == "/help":
            self._cmd_help()
        elif cmd == "/skills":
            self._cmd_skills()
        elif cmd == "/tools":
            self._cmd_tools()
        elif cmd == "/target":
            self._cmd_target(arg)
        elif cmd == "/settings":
            self._cmd_settings()
        elif cmd == "/context":
            self._cmd_context()
        elif cmd == "/clear":
            self.action_clear_panels()
        elif cmd == "/quit":
            event_log.add_event(self._make_event("milestone", "再见"))
            self.exit()
        else:
            event_log.add_event(
                self._make_event("error", f"未知命令: {cmd}。输入 /help 查看可用命令")
            )

    def _cmd_help(self) -> None:
        """显示帮助信息。"""
        event_log = self.query_one("#event-log", EventLog)
        event_log.add_event(self._make_event("thought", "可用斜杠命令："))
        for cmd, desc in self._SLASH_COMMANDS.items():
            event_log.add_event(self._make_event("thought", f"  {cmd:<10} - {desc}"))
        event_log.add_event(
            self._make_event("thought", "快捷键：q 退出 / s 停止 / c 清屏 / h 帮助")
        )

    def _cmd_skills(self) -> None:
        """列出已注册的 Skill。"""
        event_log = self.query_one("#event-log", EventLog)
        if self._agent is None:
            event_log.add_event(self._make_event("error", "Agent 未绑定，无法列出 Skill"))
            return
        try:
            self._agent._ensure_initialized()
            skills = self._agent._skill_registry.list_skills()
        except Exception as e:
            event_log.add_event(self._make_event("error", f"加载 Skill 失败: {e}"))
            return
        if not skills:
            event_log.add_event(self._make_event("thought", "未找到已注册的 Skill"))
            return
        event_log.add_event(self._make_event("thought", f"已注册 Skill（共 {len(skills)} 个）："))
        for skill in skills:
            event_log.add_event(
                self._make_event("thought", f"  - {skill['name']}: {skill['description']}")
            )

    def _cmd_tools(self) -> None:
        """显示逆向工具状态。"""
        event_log = self.query_one("#event-log", EventLog)
        tool_panel = self.query_one("#tool-col", ToolPanel)
        event_log.add_event(self._make_event("thought", "逆向工具状态："))
        for _key, status in tool_panel.tools.items():
            event_log.add_event(
                self._make_event(
                    "thought",
                    f"  [{status.status}] {status.name}: {status.detail}",
                )
            )

    def _cmd_target(self, arg: str) -> None:
        """设置或查看当前目标。"""
        event_log = self.query_one("#event-log", EventLog)
        if arg:
            self.target = arg
            self.objective = f"分析目标: {arg}"
            event_log.add_event(self._make_event("milestone", f"目标已设置为: {arg}"))
        else:
            target_display = self.target or "(未指定)"
            event_log.add_event(self._make_event("thought", f"当前目标: {target_display}"))

    def _cmd_settings(self) -> None:
        """进入可视化设置页面（参照文档 §9.3）。

        通过 push_screen 推送 SettingsScreen，复用 SettingsApp 的核心组件
        （LLMConfigPane / SkillListPane / ToolCenterPane），退出后返回主操作台。
        """
        event_log = self.query_one("#event-log", EventLog)
        event_log.add_event(self._make_event("milestone", "进入设置页面（按 Esc 返回主操作台）"))
        self.push_screen(SettingsScreen(config=self._config, project_root=self._project_root))

    def _cmd_context(self) -> None:
        """斜杠命令 /context：输出详细上下文状态报告。"""
        event_log = self.query_one("#event-log", EventLog)
        agent = getattr(self._agent, "_soul", None)
        agent_instance = getattr(agent, "last_agent", None) if agent is not None else None
        if agent_instance is None:
            event_log.add_event(
                self._make_event("thought", "尚无运行中的 Agent 任务（先发送一条指令）")
            )
            return
        snap = agent_instance.context_snapshot()
        event_log.add_event(
            self._make_event(
                "thought",
                f"上下文: {snap['messages']} 条消息, "
                f"{snap['used_tokens']}/{snap['max_context_size']} token "
                f"({snap['usage_ratio'] * 100:.0f}%), "
                f"剩余 {snap['remaining_tokens']}, "
                f"自动压缩 {snap['compaction_count']} 次",
            )
        )
        usage = snap.get("total_usage", {})
        event_log.add_event(
            self._make_event(
                "thought",
                f"LLM 用量: input {usage.get('input', 0)} tokens, "
                f"output {usage.get('output', 0)} tokens, "
                f"共 {usage.get('steps', 0)} 次调用",
            )
        )

    def action_show_help(self) -> None:
        """快捷键 h：显示帮助。"""
        self._cmd_help()

    async def _run_prompt(self, prompt: str) -> None:
        """异步执行用户输入的提示词。

        Args:
            prompt: 用户输入的提示词
        """
        self._is_running = True
        event_log = self.query_one("#event-log", EventLog)
        event_log.add_event(self._make_event("milestone", f">>> {prompt[:60]}"))

        # 重置面板状态
        tool_panel = self.query_one("#tool-col", ToolPanel)
        tool_panel.reset()
        phase_bar = self.query_one("#phase-bar", PhaseBar)
        phase_bar.reset()

        try:
            if self._agent is None:
                event_log.add_event(self._make_event("error", "Agent 未绑定"))
                return
            soul = getattr(self._agent, "_soul", None)
            if soul is None:
                event_log.add_event(self._make_event("error", "Soul 引擎未初始化"))
                return

            result = await soul.run(prompt)

            event_log.add_event(self._make_event("milestone", "任务完成"))
            # 完整回复写入可滚动日志（RichLog，不截断）
            event_log.add_event(self._make_event("thought", result))

            # 推进到报告阶段
            phase_bar.set_phase("报告")

        except asyncio.CancelledError:
            event_log.add_event(self._make_event("milestone", "任务已取消"))
        except Exception as e:
            event_log.add_event(
                self._make_event("error", f"执行失败: {type(e).__name__}: {str(e)[:80]}")
            )
        finally:
            self._is_running = False

    def _update_header(self) -> None:
        """更新顶部标题栏（显示目标与计时）。"""
        elapsed = time.monotonic() - self.start_time
        mins = int(elapsed) // 60
        secs = int(elapsed) % 60
        elapsed_str = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"

        status = "*" if self._soul_ready else "o"
        header_widget = self.query_one("#header-bar", Static)
        target_display = self.target or "(未指定)"
        objective_display = self.objective or "逆向分析"
        header_widget.update(
            f" [bold blue]WinReverse Agent[/] {status}  "
            f"[bold]{target_display}[/]  "
            f"[grey50]{objective_display}[/]  "
            f"[grey50]{elapsed_str}[/]"
        )

    def _update_context_bar(self) -> None:
        """轮询 Agent 上下文快照并刷新状态栏（token/窗口/压缩/用量）。"""
        context_bar = self.query_one("#context-bar", ContextBar)
        agent = getattr(self._agent, "_soul", None)
        agent_instance = getattr(agent, "last_agent", None) if agent is not None else None
        if agent_instance is None:
            context_bar.set_snapshot(None)
            return
        try:
            context_bar.set_snapshot(agent_instance.context_snapshot())
        except Exception:
            context_bar.set_snapshot(None)

    def action_emergency_stop(self) -> None:
        """紧急停止当前任务。"""
        event_log = self.query_one("#event-log", EventLog)
        if not self._is_running:
            event_log.add_event(self._make_event("thought", "当前无运行中的任务"))
            return

        # 取消所有 prompt group 的 worker
        self.workers.cancel_group(self, "prompt")
        self._is_running = False
        event_log.add_event(self._make_event("milestone", "已请求停止当前任务"))

    def action_clear_panels(self) -> None:
        """清空所有面板内容。"""
        event_log = self.query_one("#event-log", EventLog)
        event_log.events = []

        findings_panel = self.query_one("#findings-col", FindingsPanel)
        findings_panel.reset()

        tool_panel = self.query_one("#tool-col", ToolPanel)
        tool_panel.reset()

        phase_bar = self.query_one("#phase-bar", PhaseBar)
        phase_bar.reset()

        self.app.notify("面板已清空", severity="information", timeout=2)

    @staticmethod
    def _make_event(event_type: str, detail: str) -> dict[str, Any]:
        """构造事件字典。

        Args:
            event_type: 事件类型
            detail: 事件详情

        Returns:
            事件字典
        """
        return {
            "event_type": event_type,
            "detail": detail,
            "timestamp": datetime.now().isoformat(),
        }


def launch_main_app(
    agent: Any | None = None,
    target: str = "",
    objective: str = "",
    config: AppConfig | None = None,
    project_root: Path | None = None,
    agent_factory: Any = None,
) -> None:
    """启动主操作台 TUI。

    Args:
        agent: Agent 实例，None 时仅展示界面
        target: 当前目标
        objective: 任务目标
        config: 应用配置（/settings 命令使用），None 时从默认路径加载
        project_root: 项目根目录（/settings 命令定位 manifest），None 时使用当前目录
    """
    app = MainApp(
        agent=agent,
        target=target,
        objective=objective,
        config=config,
        project_root=project_root,
        agent_factory=agent_factory,
    )
    app.run()


class SettingsScreen(Screen[None]):
    """设置页面 Screen（供 MainApp 通过 push_screen 进入）。

    复用 SettingsApp 的核心组件（LLMConfigPane / SkillListPane / ToolCenterPane），
    提供与独立 SettingsApp 一致的功能，但作为 Screen 嵌入主操作台。
    按 Esc 返回主操作台。

    Attributes:
        config: 当前应用配置
        project_root: 项目根目录
    """

    CSS = """
    SettingsScreen {
        layout: vertical;
    }
    SettingsScreen > TabbedContent {
        height: 1fr;
    }
    SettingsScreen #settings-status-bar {
        height: 1;
        dock: bottom;
        padding: 0 1;
        color: $text-muted;
        background: $panel;
    }
    """

    BINDINGS = [
        Binding("escape", "app.pop_screen", "返回", show=True),
        Binding("s", "save", "保存配置", show=True),
        Binding("1", "tab('llm-config')", "LLM", show=True),
        Binding("2", "tab('skill-list')", "Skill", show=True),
        Binding("3", "tab('tool-center')", "工具", show=True),
    ]

    def __init__(
        self,
        config: AppConfig | None = None,
        project_root: Path | None = None,
    ) -> None:
        """初始化设置 Screen。

        Args:
            config: 应用配置，None 时从默认路径加载
            project_root: 项目根目录，None 时使用当前目录
        """
        super().__init__()
        self.config = config if config is not None else load_or_default()
        self.project_root = project_root if project_root is not None else Path.cwd()

    def compose(self) -> ComposeResult:
        """构建界面布局：标题 + TabbedContent + 状态栏。"""
        yield Static(
            "[bold]WinReverseAgent 设置[/bold]  (Esc 返回主操作台)",
            id="settings-title",
        )
        with TabbedContent():
            with TabPane("LLM 配置 (1)", id="llm-config"):
                yield LLMConfigPane(self.config)
            with TabPane("Skill 列表 (2)", id="skill-list"):
                yield SkillListPane(self.config, self.project_root)
            with TabPane("工具管理 (3)", id="tool-center"):
                yield ToolCenterPane(self.project_root)
        yield Static(self._render_status_bar(), id="settings-status-bar")

    def _render_status_bar(self) -> str:
        """渲染底部状态栏。"""
        config_path = get_default_config_path()
        provider = self.config.llm.provider
        model = self.config.llm.model or "(未设置)"
        return (
            f" 配置文件: {config_path.name}  |  "
            f"LLM: {provider}/{model}  |  "
            f"按 's' 保存，'Esc' 返回，'1/2/3' 切换 Tab"
        )

    def action_save(self) -> None:
        """保存配置到 config.toml。"""
        llm_pane = self.query_one(LLMConfigPane)
        llm_pane.apply_to_config(self.config)

        config_path = get_default_config_path()
        try:
            save_config(self.config, config_path)
            status = self.query_one("#settings-status-bar", Static)
            status.update(self._render_status_bar())
            self.app.notify(
                f"配置已保存到 {config_path}",
                title="保存成功",
                severity="information",
                timeout=3,
            )
        except Exception as e:
            self.app.notify(f"保存失败: {e}", title="错误", severity="error", timeout=5)

    def action_tab(self, tab_id: str) -> None:
        """切换到指定 Tab（快捷键 1/2/3）。"""
        tabbed = self.query_one(TabbedContent)
        tabbed.active = tab_id


class PromptInput(Input):
    """支持 ↑/↓ 历史回溯的输入框（模拟主流终端行为）。"""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._history: list[str] = []
        self._history_index: int | None = None
        self._draft = ""

    def add_history(self, value: str) -> None:
        """提交后记录历史（相邻去重）。"""
        if value and (not self._history or self._history[-1] != value):
            self._history.append(value)
        self._history_index = None

    async def _on_key(self, event: events.Key) -> None:
        """↑ 取上一条历史，↓ 回到草稿/下一条。"""
        if event.key == "up":
            event.stop()
            self.history_prev()
        elif event.key == "down":
            event.stop()
            self.history_next()

    def history_prev(self) -> None:
        """历史回溯上一步。"""
        text = self._history_step(-1)
        if text is not None:
            self.value = text
            self.cursor_position = len(text)

    def history_next(self) -> None:
        """历史回溯下一步（越过最新时恢复草稿）。"""
        text = self._history_step(1)
        if text is not None:
            self.value = text
            self.cursor_position = len(text)

    def _history_step(self, delta: int) -> str | None:
        """历史索引步进的纯逻辑（不触碰 UI 属性，可独立测试）。

        Args:
            delta: -1 上一步，+1 下一步

        Returns:
            应设置的文本；None 表示无操作（恢复草稿由 next 的 None 语义处理）
        """
        if delta < 0:
            if not self._history:
                return None
            if self._history_index is None:
                self._draft = self.value
                self._history_index = len(self._history)
            if self._history_index > 0:
                self._history_index -= 1
                return self._history[self._history_index]
            return None
        if self._history_index is None:
            return None
        self._history_index += 1
        if self._history_index >= len(self._history):
            self._history_index = None
            return self._draft
        return self._history[self._history_index]
