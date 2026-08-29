"""测试模块：winreverse.tui.screens.skill_list.SkillListPane

覆盖：
- SkillListPane 初始化
- skills 目录不存在时 DataTable 显示"目录不存在"
- skills 目录含 YAML 文件时 DataTable 显示 Skill 列表
- action_refresh_skills 不抛异常
"""

from __future__ import annotations

from pathlib import Path

from textual.widgets import DataTable

from winreverse.config import AppConfig
from winreverse.tui.app import SettingsApp
from winreverse.tui.screens.skill_list import SkillListPane


def test_pane_init() -> None:
    """SkillListPane 初始化应保存 config 与 project_root 引用。"""
    config = AppConfig()
    root = Path("/tmp/test-project")
    pane = SkillListPane(config, root)
    assert pane.config is config
    assert pane.project_root == root


async def test_load_skills_empty_dir(tmp_path: Path) -> None:
    """skills_dir 不存在时，DataTable 应显示"目录不存在"。"""
    config = AppConfig()
    app = SettingsApp(config=config, project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(SkillListPane)
        table = pane.query_one("#skill-table", DataTable)
        # DataTable 应有 1 行，包含"目录不存在"
        assert table.row_count == 1
        # 验证行内容包含"目录不存在"
        found = False
        for row_key in table.rows:
            row_data = table.get_row(row_key)
            if any("目录不存在" in str(cell) for cell in row_data):
                found = True
                break
        assert found


async def test_load_skills_with_yaml(tmp_path: Path) -> None:
    """skills 目录含 YAML 文件时，DataTable 应显示 Skill 列表。"""
    # 创建 skills 目录和 YAML 文件
    skills_dir = tmp_path / "skills"
    skills_dir.mkdir()
    (skills_dir / "test_skill.yaml").write_text(
        'name: "测试技能"\n' 'description: "用于单元测试的示例技能"\n' 'target: "通用"\n',
        encoding="utf-8",
    )
    config = AppConfig()
    app = SettingsApp(config=config, project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(SkillListPane)
        table = pane.query_one("#skill-table", DataTable)
        # 应有 1 行 Skill 数据
        assert table.row_count == 1
        # 验证行内容包含 Skill 名称
        found = False
        for row_key in table.rows:
            row_data = table.get_row(row_key)
            if any("测试技能" in str(cell) for cell in row_data):
                found = True
                break
        assert found


async def test_action_refresh(tmp_path: Path) -> None:
    """action_refresh_skills 应不抛异常。"""
    config = AppConfig()
    app = SettingsApp(config=config, project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(SkillListPane)
        # 调用刷新，应不抛异常
        pane.action_refresh_skills()
