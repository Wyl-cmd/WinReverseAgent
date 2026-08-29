"""winreverse.tui.app — Textual TUI 主应用。

基于 Textual 的 TabbedContent 实现 Tab 切换界面，包含：
- LLM 配置 Tab（查看/编辑 provider/model/api_key 等）
- Skill 列表 Tab（查看已注册 Skill）
- 工具管理 Tab（外部工具 + Python 依赖的版本校验与更新）

参考：实施方案 §9.3
"""

from __future__ import annotations

from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Header, Static, TabbedContent, TabPane

from winreverse.config import AppConfig, get_default_config_path, load_or_default, save_config
from winreverse.tui.screens.llm_config import LLMConfigPane
from winreverse.tui.screens.skill_list import SkillListPane
from winreverse.tui.screens.tool_center import ToolCenterPane


class SettingsApp(App[None]):
    """WinReverseAgent 可视化设置页面主应用。

    基于 Textual 的 Tabbed 界面，提供配置管理与工具状态查看。

    Attributes:
        config: 当前应用配置（可在界面中编辑，通过 action_save 保存）
        project_root: 项目根目录（用于定位 tools/manifest.yaml 等文件）
    """

    TITLE = "WinReverseAgent 设置"
    SUB_TITLE = "可视化配置管理"

    CSS = """
    SettingsApp {
        layout: vertical;
    }
    SettingsApp > TabbedContent {
        height: 1fr;
    }
    SettingsApp > TabbedContent > ContentTabs {
        height: 3;
        dock: top;
    }
    SettingsApp #settings-status-bar {
        height: 1;
        dock: bottom;
        padding: 0 1;
        color: $text-muted;
        background: $panel;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "退出", show=True),
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
        """初始化 TUI 应用。

        Args:
            config: 应用配置，None 时从默认路径加载
            project_root: 项目根目录，None 时使用当前目录
        """
        super().__init__()
        self.config = config if config is not None else load_or_default()
        self.project_root = project_root if project_root is not None else Path.cwd()

    def compose(self) -> ComposeResult:
        """构建界面布局：Header + TabbedContent + Footer + 状态栏。"""
        yield Header()
        with TabbedContent():
            with TabPane("LLM 配置 (1)", id="llm-config"):
                yield LLMConfigPane(self.config)
            with TabPane("Skill 列表 (2)", id="skill-list"):
                yield SkillListPane(self.config, self.project_root)
            with TabPane("工具管理 (3)", id="tool-center"):
                yield ToolCenterPane(self.project_root)
        yield Static(self._render_status_bar(), id="settings-status-bar")
        yield Footer()

    def _render_status_bar(self) -> str:
        """渲染底部状态栏。"""
        config_path = get_default_config_path()
        provider = self.config.llm.provider
        model = self.config.llm.model or "(未设置)"
        return (
            f" 配置文件: {config_path.name}  |  "
            f"LLM: {provider}/{model}  |  "
            f"按 's' 保存，'q' 退出，'1/2/3' 切换 Tab"
        )

    def action_save(self) -> None:
        """保存配置到 config.toml。

        从 LLM 配置页收集最新的配置值，写入默认配置文件路径。
        """
        llm_pane = self.query_one(LLMConfigPane)
        llm_pane.apply_to_config(self.config)

        config_path = get_default_config_path()
        try:
            save_config(self.config, config_path)
            # 刷新状态栏
            status = self.query_one("#settings-status-bar", Static)
            status.update(self._render_status_bar())
            self.notify(
                f"配置已保存到 {config_path}",
                title="保存成功",
                severity="information",
                timeout=3,
            )
        except Exception as e:
            self.notify(f"保存失败: {e}", title="错误", severity="error", timeout=5)

    def action_tab(self, tab_id: str) -> None:
        """切换到指定 Tab（快捷键 1/2/3）。"""
        tabbed = self.query_one(TabbedContent)
        tabbed.active = tab_id
