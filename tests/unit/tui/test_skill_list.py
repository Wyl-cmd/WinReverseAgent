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
        'name: "测试技能"\ndescription: "用于单元测试的示例技能"\ntarget: "通用"\n',
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


async def test_load_skills_empty_existing_dir(tmp_path: Path) -> None:
    """skills 目录存在但无任何 Skill 文件时，应显示"未找到任何 Skill 文件"。"""
    (tmp_path / "skills").mkdir()
    config = AppConfig()
    app = SettingsApp(config=config, project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(SkillListPane)
        table = pane.query_one("#skill-table", DataTable)
        assert table.row_count == 1
        found = False
        for row_key in table.rows:
            row_data = table.get_row(row_key)
            if any("未找到任何 Skill 文件" in str(cell) for cell in row_data):
                found = True
                break
        assert found


async def test_load_skills_yml_extension(tmp_path: Path) -> None:
    """.yml 扩展名的 Skill 文件同样应被扫描加载。"""
    skills_dir = tmp_path / "skills"
    skills_dir.mkdir()
    (skills_dir / "yml_skill.yml").write_text(
        'name: "YML技能"\ndescription: "yml 扩展名示例技能"\ntarget: "通用"\n',
        encoding="utf-8",
    )
    config = AppConfig()
    app = SettingsApp(config=config, project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(SkillListPane)
        table = pane.query_one("#skill-table", DataTable)
        assert table.row_count == 1
        found = False
        for row_key in table.rows:
            row_data = table.get_row(row_key)
            if any("YML技能" in str(cell) for cell in row_data):
                found = True
                break
        assert found


async def test_load_skills_invalid_files_show_error(tmp_path: Path) -> None:
    """无法解析的 .yaml / .yml 文件应显示"[加载失败]"行，不影响其他 Skill 正常加载。"""
    skills_dir = tmp_path / "skills"
    skills_dir.mkdir()
    (skills_dir / "good_skill.yaml").write_text(
        'name: "正常技能"\ndescription: "正常加载的示例技能"\ntarget: "通用"\n',
        encoding="utf-8",
    )
    (skills_dir / "bad_syntax.yaml").write_text("name: [unclosed\n", encoding="utf-8")
    (skills_dir / "missing_name.yml").write_text(
        "description: '缺少 name 字段'\n", encoding="utf-8"
    )
    config = AppConfig()
    app = SettingsApp(config=config, project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(SkillListPane)
        table = pane.query_one("#skill-table", DataTable)
        assert table.row_count == 3
        has_success = failed_names = 0
        for row_key in table.rows:
            row_data = table.get_row(row_key)
            cells = [str(cell) for cell in row_data]
            if any("正常技能" in cell for cell in cells):
                has_success += 1
            if cells[0] in ("bad_syntax.yaml", "missing_name.yml") and any(
                "[加载失败]" in cell for cell in cells
            ):
                failed_names += 1
        assert has_success == 1 and failed_names == 2


async def test_action_refresh(tmp_path: Path) -> None:
    """action_refresh_skills 应不抛异常。"""
    config = AppConfig()
    app = SettingsApp(config=config, project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(SkillListPane)
        # 调用刷新，应不抛异常
        pane.action_refresh_skills()
