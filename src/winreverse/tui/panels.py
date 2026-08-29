"""winreverse.tui.panels — 主操作台面板组件。

参照 KXNS Hunter CLI 的 TUI 面板设计，适配 Windows 逆向场景：
- PhaseBar：逆向阶段进度条（解析 → 扫描 → 分析 → 报告）
- ToolPanel：工具状态面板（显示逆向工具的调用状态，替代 KXNS 的 AgentPanel）
- FindingsPanel：发现面板（可疑 API / YARA 匹配 / 内存地址 / 壳识别）
- EventLog：事件日志（工具调用 / thought / 结果）

设计原则（抄写优先）：
- 直接抄写 KXNS app.py 的面板渲染逻辑，做逆向场景适配
- 使用 textual.reactive 实现自动刷新
- 面板间通过 MainApp 协调数据流

参考：KXNS src/kxns/ui/tui/app.py
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.text import Text
from textual.reactive import reactive
from textual.widgets import RichLog, Static

# =============================================================================
# 常量定义
# =============================================================================

# 逆向阶段顺序（参照 KXNS 的 PHASE_NAMES，适配逆向工作流）
PHASE_NAMES = ["解析", "扫描", "分析", "报告"]

# 工具状态图标
TOOL_STATUS_ICONS = {
    "idle": ("o", "grey50"),
    "active": ("*", "bold blue"),
    "complete": ("+", "green"),
    "error": ("x", "red"),
}

# 发现严重度颜色
SEVERITY_COLORS = {
    "critical": "red",
    "high": "orange3",
    "medium": "yellow",
    "low": "blue",
    "info": "grey50",
}

# 发现严重度中文标签
SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}


def _truncate(s: str, max_len: int = 50) -> str:
    """截断字符串到指定长度，超出加省略号。"""
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


# =============================================================================
# 数据模型
# =============================================================================


@dataclass
class ToolStatus:
    """单个工具的状态信息。

    Attributes:
        name: 工具显示名（如 'PE 解析器'）
        status: 状态（idle/active/complete/error）
        detail: 状态详情
    """

    name: str = ""
    status: str = "idle"
    detail: str = "等待"


@dataclass
class FindingDisplay:
    """单条发现的可视化数据。

    Attributes:
        severity: 严重度（critical/high/medium/low/info）
        title: 标题
        target: 目标（如 API 名、地址）
    """

    severity: str = "info"
    title: str = ""
    target: str = ""


# =============================================================================
# PhaseBar — 逆向阶段进度条
# =============================================================================


@dataclass
class PhaseInfo:
    """阶段信息。

    Attributes:
        name: 阶段名
        status: 状态（pending/active/done）
    """

    name: str = ""
    status: str = "pending"


class PhaseBar(Static):
    """逆向阶段进度条。

    显示当前逆向工作的阶段进度：解析 → 扫描 → 分析 → 报告。
    参照 KXNS PhaseBar，适配逆向工作流。
    """

    phases: reactive[list[PhaseInfo]] = reactive([])

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.phases = [PhaseInfo(name=n, status="pending") for n in PHASE_NAMES]

    def watch_phases(self, phases: list[PhaseInfo]) -> None:
        """phases 变化时自动刷新渲染。"""
        self.update(self._render_phases(phases))

    def _render_phases(self, phases: list[PhaseInfo]) -> str:
        """渲染阶段进度条。"""
        parts: list[str] = []
        for p in phases:
            if p.status == "done":
                parts.append(f"[on green][black]{p.name} +[/][/]")
            elif p.status == "active":
                parts.append(f"[on blue][black]* {p.name}[/][/]")
            else:
                parts.append(f"[grey50]{p.name}[/]")
        return " -> ".join(parts)

    def set_phase(self, name: str) -> None:
        """设置当前激活的阶段。

        Args:
            name: 阶段名（解析/扫描/分析/报告）
        """
        new_phases: list[PhaseInfo] = []
        for p in self.phases:
            if p.name == name:
                new_phases.append(PhaseInfo(name=p.name, status="active"))
            elif p.status == "active":
                new_phases.append(PhaseInfo(name=p.name, status="done"))
            else:
                new_phases.append(PhaseInfo(name=p.name, status=p.status))
        self.phases = new_phases

    def reset(self) -> None:
        """重置所有阶段为 pending。"""
        self.phases = [PhaseInfo(name=n, status="pending") for n in PHASE_NAMES]


# =============================================================================
# ToolPanel — 工具状态面板
# =============================================================================


class ToolPanel(Static):
    """工具状态面板。

    显示逆向工具的调用状态（替代 KXNS 的 AgentPanel）。
    当 LLM 调用工具时，对应工具状态变为 active；
    调用完成后变为 complete 或 error。

    内置工具分组：
    - PE 解析器：pe.parse / pe.imports / pe.sections 等
    - 内存扫描器：memory.attach / memory.read / memory.write
    - YARA 引擎：yara.scan_file / yara.scan_memory
    - DIE 识别器：die.scan_file / die.scan_memory
    - 反汇编器：disasm
    """

    tools: reactive[dict[str, ToolStatus]] = reactive({})

    # 工具名 → 显示名映射
    TOOL_DISPLAY = {
        "pe": "PE 解析器",
        "memory": "内存扫描器",
        "yara": "YARA 引擎",
        "die": "DIE 识别器",
        "disasm": "反汇编器",
    }

    # 工具调用名前缀 → 工具组映射
    TOOL_PREFIX_MAP = {
        "pe.": "pe",
        "memory.": "memory",
        "yara.": "yara",
        "die.": "die",
        "disasm": "disasm",
    }

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.tools = {
            key: ToolStatus(name=name, status="idle", detail="等待")
            for key, name in self.TOOL_DISPLAY.items()
        }

    def watch_tools(self, tools: dict[str, ToolStatus]) -> None:
        """tools 变化时自动刷新渲染。"""
        self.update(self._render_tools(tools))

    def _render_tools(self, tools: dict[str, ToolStatus]) -> str:
        """渲染工具状态列表。"""
        lines = ["[bold]逆向工具[/bold]"]
        for key in self.TOOL_DISPLAY:
            t = tools.get(key, ToolStatus(name=key, status="idle", detail=""))
            icon, style = TOOL_STATUS_ICONS.get(t.status, ("o", "grey50"))
            lines.append(f"  [{style}]{icon} {t.name}[/]")
            lines.append(f"  [grey50]{_truncate(t.detail, 35)}[/]")
        return "\n".join(lines)

    def _resolve_tool_group(self, tool_name: str) -> str | None:
        """根据工具调用名解析所属工具组。

        Args:
            tool_name: 工具调用名（如 'pe.parse'）

        Returns:
            工具组名（如 'pe'），未匹配返回 None
        """
        for prefix, group in self.TOOL_PREFIX_MAP.items():
            if tool_name.startswith(prefix):
                return group
        return None

    def on_tool_call(self, tool_name: str, args: dict[str, Any]) -> None:
        """工具调用开始时更新状态。

        Args:
            tool_name: 工具调用名
            args: 调用参数
        """
        group = self._resolve_tool_group(tool_name)
        if group is None:
            return
        new_tools = dict(self.tools)
        old = new_tools.get(group, ToolStatus(name=group))
        # 构造简短的参数摘要
        arg_summary = self._format_args(args)
        new_tools[group] = ToolStatus(
            name=old.name,
            status="active",
            detail=f"{tool_name} {arg_summary}",
        )
        self.tools = new_tools

    def on_tool_result(self, tool_name: str, is_error: bool, output: str) -> None:
        """工具调用结束时更新状态。

        Args:
            tool_name: 工具调用名
            is_error: 是否出错
            output: 输出摘要
        """
        group = self._resolve_tool_group(tool_name)
        if group is None:
            return
        new_tools = dict(self.tools)
        old = new_tools.get(group, ToolStatus(name=group))
        new_tools[group] = ToolStatus(
            name=old.name,
            status="error" if is_error else "complete",
            detail=_truncate(output, 35) if is_error else "完成",
        )
        self.tools = new_tools

    @staticmethod
    def _format_args(args: dict[str, Any]) -> str:
        """格式化参数字典为简短字符串。"""
        if not args:
            return ""
        parts: list[str] = []
        for key, value in list(args.items())[:2]:
            parts.append(f"{key}={_truncate(str(value), 20)}")
        return ", ".join(parts)

    def reset(self) -> None:
        """重置所有工具状态为 idle。"""
        self.tools = {
            key: ToolStatus(name=name, status="idle", detail="等待")
            for key, name in self.TOOL_DISPLAY.items()
        }


# =============================================================================
# FindingsPanel — 发现面板
# =============================================================================


class FindingsPanel(Static):
    """发现面板。

    展示逆向分析中发现的可疑项（参照 KXNS FindingsPanel）。
    包括：可疑 API、YARA 匹配、内存地址、壳识别等。
    """

    findings: reactive[list[FindingDisplay]] = reactive([])
    severity_map: reactive[dict[str, int]] = reactive({})

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.findings = []
        self.severity_map = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def watch_findings(self, findings: list[FindingDisplay]) -> None:
        """findings 变化时自动刷新渲染。"""
        self.update(self._render_findings(findings))

    def _render_findings(self, findings: list[FindingDisplay]) -> str:
        """渲染发现列表。"""
        lines = ["[bold]发现[/bold]"]

        c = self.severity_map.get("critical", 0)
        h = self.severity_map.get("high", 0)
        m = self.severity_map.get("medium", 0)
        low = self.severity_map.get("low", 0)

        lines.append(
            f"  [red]严重[/red] {c}  [orange3]高危[/orange3] {h}  "
            f"[yellow]中危[/yellow] {m}  [blue]低危[/blue] {low}"
        )
        lines.append("")

        # 显示最近 5 条发现
        start = 0
        if len(findings) > 5:
            start = len(findings) - 5
        for f in findings[start:]:
            color = SEVERITY_COLORS.get(f.severity, "grey50")
            lines.append(f"  [{color}]*[/] {_truncate(f.title, 40)}")

        if not findings:
            lines.append("  [grey50]暂无发现[/]")

        return "\n".join(lines)

    def add_finding(self, finding: FindingDisplay) -> None:
        """添加一条发现。"""
        new_findings = [*list(self.findings), finding]
        new_map = dict(self.severity_map)
        sev = finding.severity.lower()
        if sev in new_map:
            new_map[sev] += 1
        else:
            new_map["info"] += 1
        self.findings = new_findings
        self.severity_map = new_map

    def reset(self) -> None:
        """清空所有发现。"""
        self.findings = []
        self.severity_map = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}


# =============================================================================
# EventLog — 事件日志
# =============================================================================


class EventLog(RichLog):
    """事件日志面板（可滚动 RichLog，长文本不丢失）。

    显示工具调用、AI 回复、里程碑等事件流；AI 回复与长报告
    完整写入（max_lines 滚动保留最近 2000 行）。
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(markup=True, highlight=True, wrap=True, max_lines=2000, **kwargs)
        self._events: list[dict[str, Any]] = []

    @property
    def events(self) -> list[dict[str, Any]]:
        """已记录的事件列表（清屏兼容旧接口）。"""
        return self._events

    @events.setter
    def events(self, value: list[dict[str, Any]]) -> None:
        """整体重置事件（/clear 用）。"""
        self._events = list(value)
        self.clear()
        for e in self._events:
            self._write_event(e)

    _EVENT_STYLES = {
        "error": "bold red",
        "milestone": "bold green",
        "thought": "",
        "tool_call": "cyan",
        "tool_result": "grey50",
    }

    def add_event(self, event: dict[str, Any]) -> None:
        """记录并渲染一条事件（完整文本，不截断）。"""
        self._events.append(event)
        self._write_event(event)

    def _write_event(self, event: dict[str, Any]) -> None:
        event_type = str(event.get("event_type", ""))
        detail = str(event.get("detail", ""))
        ts = str(event.get("timestamp", ""))
        if len(ts) >= 19:
            ts = ts[11:19]
        style = self._EVENT_STYLES.get(event_type, "")
        prefix = {
            "error": "[bold red]✗[/] ",
            "milestone": "[bold green]●[/] ",
        }.get(event_type, "  ")
        body = f"[{style}]{detail}[/]" if style else detail
        self.write(f"[grey50]{ts}[/] {prefix}{body}")

    def clear_events(self) -> None:
        """清空全部事件。"""
        self.events = []


class ContextBar(Static):
    """上下文状态栏：token 用量 / 剩余窗口 / 压缩次数 / LLM token 消耗。

    数据来自 Agent.context_snapshot()（由 MainApp 定时轮询推送），
    用量超过压缩触发比例时整条变红警示。
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__("", **kwargs)

    def set_snapshot(self, snapshot: dict[str, Any] | None) -> None:
        """推送一次上下文快照（None 显示未运行状态）。"""
        if not snapshot:
            self.update(" [grey50]上下文: -- / -- （等待任务启动；斜杠命令 /context 查看详情）[/]")
            return
        used = snapshot["used_tokens"]
        max_size = snapshot["max_context_size"]
        remaining = snapshot["remaining_tokens"]
        ratio = snapshot["usage_ratio"]
        trigger = snapshot["trigger_ratio"]
        compactions = snapshot["compaction_count"]
        usage = snapshot.get("total_usage", {})
        messages = snapshot.get("messages", 0)

        bar_width = 20
        filled = int(min(ratio, 1.0) * bar_width)
        bar = "█" * filled + "░" * (bar_width - filled)

        def _fmt(n: int) -> str:
            return f"{n / 1000:.1f}k" if n >= 1000 else str(n)

        text = (
            f" 上下文 [{bar}] {_fmt(used)}/{_fmt(max_size)}"
            f" ({ratio * 100:.0f}%)  剩余 {_fmt(remaining)}"
            f"  |  消息 {messages}  压缩 {compactions} 次"
            f"  |  tokens in {_fmt(usage.get('input', 0))}"
            f" / out {_fmt(usage.get('output', 0))}"
        )
        # 超过触发比例 → 红色警示；接近（>60%）→ 黄色
        if ratio >= trigger:
            self.update(Text(text, style="bold red"))
        elif ratio >= 0.6:
            self.update(Text(text, style="yellow"))
        else:
            self.update(Text(text, style="green"))
