"""winreverse.tui.screens.skill_list — Skill 列表页面。

扫描 skills/ 目录，展示已注册的 Skill 列表，包含：
- Skill 名称
- 描述说明
- 适用目标（通用/PE 文件/木马样本等）

支持通过 'r' 键刷新列表。

参考：实施方案 §9.3
"""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.widgets import DataTable, Static

from winreverse.config import AppConfig
from winreverse.skill.loader import SkillRegistry, YamlSkillLoader


class SkillListPane(Container):
    """Skill 列表页面。

    扫描配置指定的 skills/ 目录，加载并展示所有 YAML 格式的 Skill。

    Attributes:
        config: 应用配置（用于定位 skills_dir）
        project_root: 项目根目录
    """

    DEFAULT_CSS = """
    SkillListPane {
        padding: 1 2;
    }
    SkillListPane #title {
        margin: 0 0 1 0;
    }
    SkillListPane #skill-table {
        height: 1fr;
    }
    SkillListPane #hint {
        color: $text-muted;
        margin: 1 0 0 0;
    }
    """

    BINDINGS = [
        Binding("r", "refresh_skills", "刷新", show=True),
    ]

    def __init__(self, config: AppConfig, project_root: Path) -> None:
        """初始化 Skill 列表页面。

        Args:
            config: 应用配置（从中读取 agent.skills_dir）
            project_root: 项目根目录
        """
        super().__init__()
        self.config = config
        self.project_root = project_root

    def compose(self) -> ComposeResult:
        """构建页面布局。"""
        yield Static("[bold]已注册 Skill 列表[/bold]", id="title")
        yield DataTable(id="skill-table")
        yield Static("按 'r' 刷新列表", id="hint")

    def on_mount(self) -> None:
        """页面挂载时加载 Skill 列表。"""
        self._load_skills()

    def action_refresh_skills(self) -> None:
        """刷新 Skill 列表。"""
        self._load_skills()
        self.app.notify("Skill 列表已刷新", severity="information", timeout=2)

    def _load_skills(self) -> None:
        """加载 skills/ 目录下的所有 YAML Skill 文件。"""
        table = self.query_one("#skill-table", DataTable)
        table.clear(columns=True)
        table.add_column("名称", width=24)
        table.add_column("描述", width=50)
        table.add_column("适用目标", width=16)

        registry = SkillRegistry()
        skills_dir = self.project_root / self.config.agent.work_dir / self.config.agent.skills_dir

        if not skills_dir.is_dir():
            table.add_row("-", f"目录不存在: {skills_dir}", "-")
            return

        loader = YamlSkillLoader()
        loaded_count = 0
        for yaml_file in sorted(skills_dir.glob("*.yaml")):
            try:
                skill = loader.load(yaml_file)
                registry.register(skill)
                table.add_row(skill.name, skill.description, skill.target)
                loaded_count += 1
            except Exception as e:
                table.add_row(yaml_file.name, f"[加载失败] {e}", "-")
        for yaml_file in sorted(skills_dir.glob("*.yml")):
            try:
                skill = loader.load(yaml_file)
                registry.register(skill)
                table.add_row(skill.name, skill.description, skill.target)
                loaded_count += 1
            except Exception as e:
                table.add_row(yaml_file.name, f"[加载失败] {e}", "-")

        if loaded_count == 0:
            table.add_row("-", "未找到任何 Skill 文件", "-")
