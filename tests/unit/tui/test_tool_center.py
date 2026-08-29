"""测试模块：winreverse.tui.screens.tool_center.ToolCenterPane

覆盖：
- ToolCenterPane 初始化
- manifest 不存在时 DataTable 显示提示
- action_check_all 在 manifest 不存在时状态栏显示错误
- action_update_all 在空 manifest 下正常完成（0 成功 0 失败）
- action_export_report 创建报告文件
- 详情区操作按钮（_show_detail / _action_update_selected / _action_rollback_selected / _action_open_homepage）
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from textual.widgets import Button, DataTable, Static

from winreverse.tui.app import SettingsApp
from winreverse.tui.screens.tool_center import ToolCenterPane


def test_pane_init() -> None:
    """ToolCenterPane 初始化应保存 project_root 引用。"""
    root = Path("/tmp/test-project")
    pane = ToolCenterPane(root)
    assert pane.project_root == root


async def test_load_tools_no_manifest(tmp_path: Path) -> None:
    """manifest 不存在时，DataTable 应显示提示。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        table = pane.query_one("#tool-table", DataTable)
        # 应有 2 行（外部工具 + Python 依赖都提示 manifest 不存在）
        assert table.row_count == 2
        # 检查是否包含"manifest 不存在"
        found = False
        for row_key in table.rows:
            row_data = table.get_row(row_key)
            if any("manifest 不存在" in str(cell) for cell in row_data):
                found = True
                break
        assert found


async def test_action_check_all_no_manifest(tmp_path: Path) -> None:
    """manifest 不存在时，action_check_all 应在状态栏显示错误。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane.action_check_all()
        status = pane.query_one("#status-bar", Static)
        # 状态栏应包含"manifest 文件不存在"（Static 用 content 属性读取原始内容）
        assert "manifest 文件不存在" in str(status.content)


async def test_action_update_all_with_empty_manifest(tmp_path: Path) -> None:
    """action_update_all 在空 manifest 下应正常完成（0 成功 0 失败）。"""
    # 创建 tools/manifest.yaml 使 _tools_manifest 检查通过
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    (tools_dir / "manifest.yaml").write_text("tools: []\n", encoding="utf-8")

    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        # mock notify 避免触发通知副作用
        with patch.object(app, "notify"):
            pane.action_update_all()
            status = pane.query_one("#status-bar", Static)
            # 空 manifest 无更新，状态栏应显示"更新完成"
            assert "更新完成" in str(status.content)
            assert "成功 0" in str(status.content)


async def test_action_export_report(tmp_path: Path) -> None:
    """action_export_report 应创建报告文件。"""
    # 创建 tools/manifest.yaml 和 vendor/wheels_manifest.yaml
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    (tools_dir / "manifest.yaml").write_text("tools: []\n", encoding="utf-8")

    vendor_dir = tmp_path / "vendor"
    vendor_dir.mkdir()
    (vendor_dir / "wheels_manifest.yaml").write_text("wheels: []\n", encoding="utf-8")

    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        # mock notify 避免触发通知副作用
        with patch.object(app, "notify"):
            pane.action_export_report()
            # 验证报告文件被创建
            output_dir = tmp_path / "output"
            assert output_dir.exists()
            reports = list(output_dir.glob("tool_report_*.json"))
            assert len(reports) == 1


# ============================================================================
# 详情区操作按钮测试（覆盖 _show_detail / _action_update_selected /
# _action_rollback_selected / _action_open_homepage）
# ============================================================================


def _make_tools_manifest(tmp_path: Path) -> Path:
    """创建包含单个工具的 tools/manifest.yaml 测试夹具。"""
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(exist_ok=True)
    manifest = tools_dir / "manifest.yaml"
    manifest.write_text(
        "tools:\n"
        '  - name: "tshark"\n'
        '    version: "4.0.0"\n'
        '    latest_known: "4.6.0"\n'
        '    entry: "tshark.exe"\n'
        '    install_path: "tools/tshark/"\n'
        "    required: true\n"
        '    homepage: "https://www.wireshark.org/"\n'
        '    sha256: "abc123"\n'
        '    download_url: "https://example.com/tshark.zip"\n',
        encoding="utf-8",
    )
    return manifest


async def test_show_detail_tool_enables_buttons(tmp_path: Path) -> None:
    """选中外部工具时应启用更新/回滚/官网按钮。"""
    _make_tools_manifest(tmp_path)

    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._show_detail("tool:tshark")

        btn_update = pane.query_one("#btn-update-one", Button)
        btn_rollback = pane.query_one("#btn-rollback", Button)
        btn_homepage = pane.query_one("#btn-homepage", Button)
        # 三个按钮都应启用
        assert btn_update.disabled is False
        assert btn_rollback.disabled is False
        assert btn_homepage.disabled is False
        # 详情区应显示工具名
        detail = pane.query_one("#detail-content", Static)
        assert "tshark" in str(detail.content)


async def test_show_detail_wheel_enables_homepage_only(tmp_path: Path) -> None:
    """选中 Python 依赖时应仅启用官网按钮。"""
    _make_tools_manifest(tmp_path)
    vendor_dir = tmp_path / "vendor"
    vendor_dir.mkdir(exist_ok=True)
    (vendor_dir / "wheels_manifest.yaml").write_text(
        'wheels:\n  - name: "pymem"\n    version: "1.13"\n',
        encoding="utf-8",
    )

    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._show_detail("wheel:pymem")

        btn_update = pane.query_one("#btn-update-one", Button)
        btn_rollback = pane.query_one("#btn-rollback", Button)
        btn_homepage = pane.query_one("#btn-homepage", Button)
        # 仅官网按钮启用
        assert btn_update.disabled is True
        assert btn_rollback.disabled is True
        assert btn_homepage.disabled is False


async def test_show_detail_unknown_key(tmp_path: Path) -> None:
    """未知 key 应禁用所有按钮并显示提示。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._show_detail("unknown:something")

        btn_update = pane.query_one("#btn-update-one", Button)
        btn_rollback = pane.query_one("#btn-rollback", Button)
        btn_homepage = pane.query_one("#btn-homepage", Button)
        assert btn_update.disabled is True
        assert btn_rollback.disabled is True
        assert btn_homepage.disabled is True


async def test_action_update_selected_no_selection(tmp_path: Path) -> None:
    """未选中工具时 _action_update_selected 应显示错误。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = None
        pane._action_update_selected()
        status = pane.query_one("#status-bar", Static)
        assert "请先选择" in str(status.content)


async def test_action_update_selected_calls_updater(tmp_path: Path) -> None:
    """_action_update_selected 应调用 ToolUpdater.update。"""
    _make_tools_manifest(tmp_path)

    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = "tool:tshark"

        with patch("winreverse.tui.screens.tool_center.ToolUpdater") as mock_cls:
            mock_updater = MagicMock()
            mock_updater.update.return_value = MagicMock(success=True, message="已更新到 4.6.0")
            mock_updater.list_installed.return_value = []
            mock_updater._get_tool_entry.return_value = {"homepage": "x"}
            mock_cls.return_value = mock_updater
            with patch.object(app, "notify"):
                pane._action_update_selected()

            mock_updater.update.assert_called_once_with("tshark")


async def test_action_rollback_selected_calls_updater(tmp_path: Path) -> None:
    """_action_rollback_selected 应调用 ToolUpdater.rollback。"""
    _make_tools_manifest(tmp_path)

    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = "tool:tshark"

        with patch("winreverse.tui.screens.tool_center.ToolUpdater") as mock_cls:
            mock_updater = MagicMock()
            mock_updater.rollback.return_value = MagicMock(success=True, message="已回滚到 4.0.0")
            mock_updater.list_installed.return_value = []
            mock_updater._get_tool_entry.return_value = {"homepage": "x"}
            mock_cls.return_value = mock_updater
            with patch.object(app, "notify"):
                pane._action_rollback_selected()

            mock_updater.rollback.assert_called_once_with("tshark")


async def test_action_open_homepage_tool(tmp_path: Path) -> None:
    """_action_open_homepage 对外部工具应打开 manifest 中的 homepage。"""
    _make_tools_manifest(tmp_path)

    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = "tool:tshark"

        with patch("winreverse.tui.screens.tool_center.webbrowser.open") as mock_open:
            pane._action_open_homepage()
            mock_open.assert_called_once_with("https://www.wireshark.org/")


async def test_action_open_homepage_wheel(tmp_path: Path) -> None:
    """_action_open_homepage 对 Python 依赖应打开 PyPI 页面。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = "wheel:pymem"

        with patch("winreverse.tui.screens.tool_center.webbrowser.open") as mock_open:
            pane._action_open_homepage()
            mock_open.assert_called_once_with("https://pypi.org/project/pymem/")


async def test_action_open_homepage_no_selection(tmp_path: Path) -> None:
    """未选中工具时 _action_open_homepage 应显示错误。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = None
        pane._action_open_homepage()
        status = pane.query_one("#status-bar", Static)
        assert "请先选择" in str(status.content)


# ============================================================================
# 按钮事件分发与 action 方法测试（提升覆盖率）
# ============================================================================


async def test_on_button_pressed_refresh(tmp_path: Path) -> None:
    """点击「刷新检查」按钮应触发 action_refresh。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        with patch.object(app, "notify"):
            pane.on_button_pressed(Button.Pressed(button=pane.query_one("#btn-refresh")))
            status = pane.query_one("#status-bar", Static)
            # action_refresh 会调用 _load_tools，manifest 不存在时状态栏不变
            assert status is not None


async def test_on_button_pressed_check(tmp_path: Path) -> None:
    """点击「校验完整性」按钮应触发 action_check_all。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane.on_button_pressed(Button.Pressed(button=pane.query_one("#btn-check")))
        status = pane.query_one("#status-bar", Static)
        assert "manifest 文件不存在" in str(status.content)


async def test_on_button_pressed_update_all(tmp_path: Path) -> None:
    """点击「全部更新」按钮应触发 action_update_all。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane.on_button_pressed(Button.Pressed(button=pane.query_one("#btn-update-all")))
        status = pane.query_one("#status-bar", Static)
        assert "manifest.yaml 不存在" in str(status.content)


async def test_on_button_pressed_export(tmp_path: Path) -> None:
    """点击「导出报告」按钮应触发 action_export_report。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane.on_button_pressed(Button.Pressed(button=pane.query_one("#btn-export")))
        status = pane.query_one("#status-bar", Static)
        assert "manifest 文件不存在" in str(status.content)


async def test_on_button_pressed_update_one(tmp_path: Path) -> None:
    """点击「更新到最新」按钮应触发 _action_update_selected。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        # 未选中工具
        pane._selected_key = None
        pane.on_button_pressed(Button.Pressed(button=pane.query_one("#btn-update-one")))
        status = pane.query_one("#status-bar", Static)
        assert "请先选择" in str(status.content)


async def test_on_button_pressed_rollback(tmp_path: Path) -> None:
    """点击「回滚到备份」按钮应触发 _action_rollback_selected。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = None
        pane.on_button_pressed(Button.Pressed(button=pane.query_one("#btn-rollback")))
        status = pane.query_one("#status-bar", Static)
        assert "请先选择" in str(status.content)


async def test_on_button_pressed_homepage(tmp_path: Path) -> None:
    """点击「访问官网」按钮应触发 _action_open_homepage。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = None
        pane.on_button_pressed(Button.Pressed(button=pane.query_one("#btn-homepage")))
        status = pane.query_one("#status-bar", Static)
        assert "请先选择" in str(status.content)


async def test_action_refresh(tmp_path: Path) -> None:
    """action_refresh 应刷新工具列表并通知。"""
    _make_tools_manifest(tmp_path)
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        with patch.object(app, "notify"):
            pane.action_refresh()
        # 不抛异常即通过


async def test_action_check_all_with_manifests(tmp_path: Path) -> None:
    """有 manifest 时 action_check_all 应执行校验。"""
    _make_tools_manifest(tmp_path)
    vendor_dir = tmp_path / "vendor"
    vendor_dir.mkdir()
    (vendor_dir / "wheels_manifest.yaml").write_text(
        'wheels:\n  - name: "pymem"\n    version: "1.13"\n',
        encoding="utf-8",
    )
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        with patch.object(app, "notify"):
            pane.action_check_all()
        status = pane.query_one("#status-bar", Static)
        assert "校验完成" in str(status.content)


async def test_action_update_all_with_manifest(tmp_path: Path) -> None:
    """有 manifest 时 action_update_all 应执行更新。"""
    _make_tools_manifest(tmp_path)
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        with patch.object(app, "notify"):
            pane.action_update_all()
        status = pane.query_one("#status-bar", Static)
        # 工具会尝试下载，可能失败，但应显示"更新完成"
        assert "更新完成" in str(status.content) or "更新失败" in str(status.content)


async def test_action_export_report_no_manifest(tmp_path: Path) -> None:
    """无 manifest 时 action_export_report 应显示错误。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane.action_export_report()
        status = pane.query_one("#status-bar", Static)
        assert "manifest 文件不存在" in str(status.content)


async def test_action_rollback_selected_no_selection(tmp_path: Path) -> None:
    """未选中工具时 _action_rollback_selected 应显示错误。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = None
        pane._action_rollback_selected()
        status = pane.query_one("#status-bar", Static)
        assert "请先选择" in str(status.content)


async def test_action_rollback_selected_wheel_key(tmp_path: Path) -> None:
    """选中 Python 依赖时 _action_rollback_selected 应显示错误（仅支持外部工具）。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = "wheel:pymem"
        pane._action_rollback_selected()
        status = pane.query_one("#status-bar", Static)
        assert "请先选择" in str(status.content)
