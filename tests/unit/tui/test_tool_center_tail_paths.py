"""测试模块：winreverse.tui.screens.tool_center — 异常弧与行选中回调。

覆盖点：on_data_table_row_selected 转发详情、action_check_all / action_update_all /
action_export_report 的异常弧、_load_tools 的 tool-error / wheel-error 兜底行、
_render_tool_detail / _render_wheel_detail 的缺失与异常弧、_action_update_selected 与
_action_rollback_selected 的 manifest 缺失 / 失败结果 / 异常三弧、
_action_open_homepage 的未知类型 / 未配置官网 / 异常弧。
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from textual.widgets import Button, DataTable, Static

from winreverse.tui.app import SettingsApp
from winreverse.tui.screens.tool_center import ToolCenterPane

_UPDATER = "winreverse.tui.screens.tool_center.ToolUpdater"
_CHECKER = "winreverse.tui.screens.tool_center.VersionChecker"


def _make_manifests(tmp_path: Path, *, tools: bool = True, wheels: bool = True) -> None:
    """按需创建 tools/manifest.yaml 与 vendor/wheels_manifest.yaml 空夹具。"""
    if tools:
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir(exist_ok=True)
        (tools_dir / "manifest.yaml").write_text("tools: []\n", encoding="utf-8")
    if wheels:
        vendor_dir = tmp_path / "vendor"
        vendor_dir.mkdir(exist_ok=True)
        (vendor_dir / "wheels_manifest.yaml").write_text("wheels: []\n", encoding="utf-8")


def _tool_row() -> SimpleNamespace:
    """list_installed 的单条已安装工具记录。"""
    return SimpleNamespace(
        name="tshark",
        installed=True,
        version="4.0.0",
        required=True,
        install_path="tools/tshark",
        entry="tshark.exe",
    )


def _wheel_row(status: str = "ok") -> SimpleNamespace:
    """check_wheels 的单条依赖记录。"""
    return SimpleNamespace(
        name="pypdf",
        version="2.0.0",
        status=status,
        required=True,
        message="ok" if status == "ok" else "not installed",
    )


@contextmanager
def _mock_core(*, tools_manifest: bool = True, wheels_manifest: bool = True):
    """同时桩掉 ToolUpdater 与 VersionChecker，返回 (updater_mock, checker_mock)。"""
    with patch(_UPDATER) as mu, patch(_CHECKER) as mv:
        if tools_manifest:
            mu.return_value.list_installed.return_value = [_tool_row()]
            mu.return_value._get_tool_entry.return_value = {
                "homepage": "https://www.wireshark.org/",
                "latest_known": "4.6.0",
                "sha256": "abc123",
            }
        if wheels_manifest:
            mv.return_value.check_wheels.return_value = SimpleNamespace(results=[_wheel_row()])
        yield mu, mv


def _status(pane: ToolCenterPane) -> str:
    """读取状态栏文本。"""
    return str(pane.query_one("#status-bar", Static).content)


async def test_row_selected_shows_tool_detail(tmp_path: Path) -> None:
    """行选中事件应把行 key 转发到 _show_detail 并渲染详情。"""
    _make_manifests(tmp_path)
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        with _mock_core(), patch.object(app, "notify"):
            pane._load_tools()
            table = pane.query_one("#tool-table", DataTable)
            row_key = next(k for k in table.rows if k.value == "tool:tshark")

            pane.on_data_table_row_selected(DataTable.RowSelected(table, 0, row_key))

        assert pane._selected_key == "tool:tshark"
        detail = str(pane.query_one("#detail-content", Static).content)
        assert "tshark" in detail
        assert pane.query_one("#btn-update-one", Button).disabled is False


async def test_check_all_exception_shows_failure(tmp_path: Path) -> None:
    """校验过程中抛异常时状态栏应显示校验失败。"""
    _make_manifests(tmp_path)
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        with patch(_CHECKER) as mv:
            mv.return_value.check_all.side_effect = RuntimeError("boom")
            pane.action_check_all()
        assert "校验失败: boom" in _status(pane)


async def test_update_all_exception_shows_failure_and_notifies(tmp_path: Path) -> None:
    """全量更新抛异常时状态栏显示更新失败并弹出错误通知。"""
    _make_manifests(tmp_path, wheels=False)
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        with patch(_UPDATER) as mu, patch.object(app, "notify") as notify:
            mu.return_value.update_all.side_effect = RuntimeError("boom")
            pane.action_update_all()
        assert "更新失败: boom" in _status(pane)
        assert notify.called


async def test_export_report_exception_shows_failure(tmp_path: Path) -> None:
    """导出报告抛异常时状态栏应显示导出失败。"""
    _make_manifests(tmp_path)
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        with patch(_CHECKER) as mv:
            mv.return_value.check_all.side_effect = RuntimeError("boom")
            pane.action_export_report()
        assert "导出失败: boom" in _status(pane)


async def test_load_tools_tool_error_row(tmp_path: Path) -> None:
    """外部工具清单存在但解析抛异常时应出现 tool-error 兜底行。"""
    _make_manifests(tmp_path, wheels=False)
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        with patch(_UPDATER) as mu:
            mu.return_value.list_installed.side_effect = RuntimeError("boom")
            pane._load_tools()
        table = pane.query_one("#tool-table", DataTable)
        cells = [str(c) for k in table.rows for c in table.get_row(k)]
        assert any("加载失败" in c for c in cells)


async def test_load_tools_wheel_error_row(tmp_path: Path) -> None:
    """wheels 清单存在但校验抛异常时应出现 wheel-error 兜底行。"""
    _make_manifests(tmp_path, tools=False)
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        with patch(_CHECKER) as mv:
            mv.return_value.check_wheels.side_effect = RuntimeError("boom")
            pane._load_tools()
        table = pane.query_one("#tool-table", DataTable)
        error_rows = [table.get_row(k) for k in table.rows if k.value == "wheel-error"]
        assert len(error_rows) == 1
        assert any("加载失败" in str(c) for c in error_rows[0])


async def test_tool_detail_render_failure(tmp_path: Path) -> None:
    """工具详情渲染抛异常时详情区显示加载失败而非崩溃。"""
    _make_manifests(tmp_path, wheels=False)
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        with patch(_UPDATER) as mu:
            mu.return_value._get_tool_entry.side_effect = RuntimeError("boom")
            pane._show_detail("tool:tshark")
        assert "加载详情失败" in str(pane.query_one("#detail-content", Static).content)


async def test_wheel_detail_manifest_missing(tmp_path: Path) -> None:
    """wheels 清单缺失时依赖详情应提示不存在，仅官网按钮可用。"""
    _make_manifests(tmp_path, tools=False, wheels=False)
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._show_detail("wheel:pypdf")
        assert "wheels_manifest.yaml 不存在" in str(
            pane.query_one("#detail-content", Static).content
        )
        assert pane.query_one("#btn-homepage", Button).disabled is False
        assert pane.query_one("#btn-update-one", Button).disabled is True


async def test_wheel_detail_renders_abnormal_status(tmp_path: Path) -> None:
    """依赖状态非 ok 时详情按异常态渲染并显示 PyPI 链接。"""
    _make_manifests(tmp_path, tools=False)
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        with patch(_CHECKER) as mv:
            mv.return_value.check_wheels.return_value = SimpleNamespace(
                results=[_wheel_row("missing")]
            )
            pane._show_detail("wheel:pypdf")
        detail = str(pane.query_one("#detail-content", Static).content)
        assert "pypdf" in detail
        assert "missing" in detail
        assert "https://pypi.org/project/pypdf/" in detail
        assert pane.query_one("#btn-homepage", Button).disabled is False


async def test_wheel_detail_render_failure(tmp_path: Path) -> None:
    """依赖详情渲染抛异常时显示加载失败。"""
    _make_manifests(tmp_path, tools=False)
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        with patch(_CHECKER) as mv:
            mv.return_value.check_wheels.side_effect = RuntimeError("boom")
            pane._show_detail("wheel:pypdf")
        assert "加载详情失败" in str(pane.query_one("#detail-content", Static).content)


async def test_update_selected_manifest_missing(tmp_path: Path) -> None:
    """选中外部工具但 manifest 缺失时更新应拒绝并提示。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = "tool:tshark"
        pane._action_update_selected()
        assert "tools/manifest.yaml 不存在" in _status(pane)


async def test_update_selected_failure_result(tmp_path: Path) -> None:
    """更新结果 success=False 时状态栏与通知均为失败口径。"""
    _make_manifests(tmp_path, wheels=False)
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = "tool:tshark"
        with patch(_UPDATER) as mu, patch.object(app, "notify") as notify:
            mu.return_value.update.return_value = SimpleNamespace(success=False, message="net down")
            pane._action_update_selected()
        assert "更新失败: net down" in _status(pane)
        assert notify.called


async def test_update_selected_exception(tmp_path: Path) -> None:
    """更新过程抛异常时状态栏显示更新异常且不崩溃。"""
    _make_manifests(tmp_path, wheels=False)
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = "tool:tshark"
        with patch(_UPDATER) as mu:
            mu.return_value.update.side_effect = RuntimeError("boom")
            pane._action_update_selected()
        assert "更新异常: boom" in _status(pane)


async def test_rollback_selected_manifest_missing(tmp_path: Path) -> None:
    """选中外部工具但 manifest 缺失时回滚应拒绝并提示。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = "tool:tshark"
        pane._action_rollback_selected()
        assert "tools/manifest.yaml 不存在" in _status(pane)


async def test_rollback_selected_failure_result(tmp_path: Path) -> None:
    """回滚结果 success=False 时状态栏与通知均为失败口径。"""
    _make_manifests(tmp_path, wheels=False)
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = "tool:tshark"
        with patch(_UPDATER) as mu, patch.object(app, "notify") as notify:
            mu.return_value.rollback.return_value = SimpleNamespace(
                success=False, message="no backup"
            )
            pane._action_rollback_selected()
        assert "回滚失败: no backup" in _status(pane)
        assert notify.called


async def test_rollback_selected_exception(tmp_path: Path) -> None:
    """回滚过程抛异常时状态栏显示回滚异常且不崩溃。"""
    _make_manifests(tmp_path, wheels=False)
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = "tool:tshark"
        with patch(_UPDATER) as mu:
            mu.return_value.rollback.side_effect = RuntimeError("boom")
            pane._action_rollback_selected()
        assert "回滚异常: boom" in _status(pane)


async def test_open_homepage_unknown_key_type(tmp_path: Path) -> None:
    """选中 key 类型未知时打开官网应提示不支持的工具类型。"""
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = "weird:thing"
        pane._action_open_homepage()
        assert "不支持的工具类型" in _status(pane)


async def test_open_homepage_empty_url(tmp_path: Path) -> None:
    """工具未配置 homepage 时打开官网应提示未配置。"""
    _make_manifests(tmp_path, wheels=False)
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = "tool:tshark"
        with patch(_UPDATER) as mu:
            mu.return_value._get_tool_entry.return_value = {}
            pane._action_open_homepage()
        assert "该工具未配置官网" in _status(pane)


async def test_open_homepage_exception(tmp_path: Path) -> None:
    """读取官网配置抛异常时提示打开失败而非崩溃。"""
    _make_manifests(tmp_path, wheels=False)
    app = SettingsApp(project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        pane = app.query_one(ToolCenterPane)
        pane._selected_key = "tool:tshark"
        with patch(_UPDATER) as mu:
            mu.return_value._get_tool_entry.side_effect = RuntimeError("boom")
            pane._action_open_homepage()
        assert "打开官网失败" in _status(pane)
