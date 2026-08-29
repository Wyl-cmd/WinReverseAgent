"""winreverse.tui.screens.tool_center — 工具管理中心页面。

承载外部工具与 Python 依赖的版本校验、状态查看与更新操作。

功能：
- 工具列表展示（外部工具 + Python 依赖，分组显示）
- 详情区（显示选中工具的版本/SHA256/状态/路径）
- 全局操作（刷新检查/全部更新/校验完整性/导出报告）
- 单工具操作（更新/回滚/重新下载/访问官网）

参考：实施方案 §9.4
"""

from __future__ import annotations

import json
import webbrowser
from datetime import datetime
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.widgets import Button, DataTable, Static

from winreverse.tools.updater import ToolUpdater
from winreverse.tools.version_checker import VersionChecker


class ToolCenterPane(Container):
    """工具管理中心页面。

    展示外部工具与 Python 依赖的安装状态、版本信息，提供校验与更新操作。

    Attributes:
        project_root: 项目根目录（用于定位 manifest 文件）
    """

    DEFAULT_CSS = """
    ToolCenterPane {
        padding: 1 2;
    }
    ToolCenterPane #title {
        margin: 0 0 1 0;
    }
    ToolCenterPane #status-bar {
        color: $text-muted;
        margin: 0 0 1 0;
    }
    ToolCenterPane #action-bar {
        height: 3;
        margin: 0 0 1 0;
    }
    ToolCenterPane #action-bar Button {
        margin: 0 1 0 0;
    }
    ToolCenterPane #tool-table {
        height: 1fr;
        margin: 0 0 1 0;
    }
    ToolCenterPane #detail-area {
        height: 10;
        border: round $primary;
        padding: 0 1;
    }
    ToolCenterPane #detail-title {
        text-style: bold;
        margin: 0 0 1 0;
    }
    ToolCenterPane #detail-content {
        color: $text;
    }
    ToolCenterPane #detail-actions {
        height: 3;
        margin: 1 0 0 0;
    }
    ToolCenterPane #detail-actions Button {
        margin: 0 1 0 0;
    }
    """

    BINDINGS = [
        Binding("r", "refresh", "刷新", show=True),
        Binding("c", "check_all", "校验完整性", show=True),
        Binding("u", "update_all", "全部更新", show=True),
        Binding("e", "export_report", "导出报告", show=True),
    ]

    def __init__(self, project_root: Path) -> None:
        """初始化工具管理中心。

        Args:
            project_root: 项目根目录
        """
        super().__init__()
        self.project_root = project_root
        self._tools_manifest = project_root / "tools" / "manifest.yaml"
        self._wheels_manifest = project_root / "vendor" / "wheels_manifest.yaml"
        self._wheels_dir = project_root / "vendor" / "wheels"
        # 当前选中的工具 key（'tool:<name>' 或 'wheel:<name>'），None 表示未选中
        self._selected_key: str | None = None

    def compose(self) -> ComposeResult:
        """构建页面布局。"""
        yield Static("[bold]工具管理中心[/bold]", id="title")
        yield Static("准备就绪。按 'r' 刷新，'c' 校验完整性。", id="status-bar")

        with Horizontal(id="action-bar"):
            yield Button("刷新检查", id="btn-refresh")
            yield Button("校验完整性", id="btn-check")
            yield Button("全部更新", id="btn-update-all")
            yield Button("导出报告", id="btn-export")

        yield DataTable(id="tool-table")
        yield Static("[bold]详情[/bold]", id="detail-title")
        yield Static("选择上方列表中的工具查看详情", id="detail-content", markup=True)
        with Horizontal(id="detail-actions"):
            yield Button("更新到最新", id="btn-update-one", disabled=True)
            yield Button("回滚到备份", id="btn-rollback", disabled=True)
            yield Button("访问官网", id="btn-homepage", disabled=True)

    def on_mount(self) -> None:
        """页面挂载时初始化表格并加载工具列表。"""
        table = self.query_one("#tool-table", DataTable)
        table.add_column("类型", width=6)
        table.add_column("名称", width=18)
        table.add_column("版本", width=14)
        table.add_column("状态", width=10)
        table.add_column("必选", width=6)
        self._load_tools()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """选中工具行时显示详情。"""
        key = event.row_key.value
        if key is not None:
            self._show_detail(key)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """处理按钮点击事件。"""
        btn_id = event.button.id
        if btn_id == "btn-refresh":
            self.action_refresh()
        elif btn_id == "btn-check":
            self.action_check_all()
        elif btn_id == "btn-update-all":
            self.action_update_all()
        elif btn_id == "btn-export":
            self.action_export_report()
        elif btn_id == "btn-update-one":
            self._action_update_selected()
        elif btn_id == "btn-rollback":
            self._action_rollback_selected()
        elif btn_id == "btn-homepage":
            self._action_open_homepage()

    # =========================================================================
    # Action 处理
    # =========================================================================

    def action_refresh(self) -> None:
        """刷新工具列表。"""
        self._load_tools()
        self.app.notify("工具列表已刷新", severity="information", timeout=2)

    def action_check_all(self) -> None:
        """执行全量完整性校验。"""
        if not self._manifests_exist():
            self._set_status("manifest 文件不存在，无法校验", error=True)
            return

        try:
            checker = VersionChecker(
                wheels_manifest=self._wheels_manifest,
                wheels_dir=self._wheels_dir,
                tools_manifest=self._tools_manifest,
                project_root=self.project_root,
            )
            report = checker.check_all()
            self._load_tools()
            status = f"校验完成：总体状态={report.overall}，通过={'是' if report.passed else '否'}"
            self._set_status(status, error=not report.passed)
            self.app.notify(
                status, severity="warning" if not report.passed else "information", timeout=5
            )
        except Exception as e:
            self._set_status(f"校验失败: {e}", error=True)

    def action_update_all(self) -> None:
        """一键更新所有有新版本的工具。"""
        if not self._tools_manifest.exists():
            self._set_status("tools/manifest.yaml 不存在", error=True)
            return

        try:
            updater = ToolUpdater(
                manifest_path=self._tools_manifest,
                project_root=self.project_root,
            )
            report = updater.update_all()
            success = report.success_count
            failure = report.failure_count
            self._set_status(f"更新完成：成功 {success}，失败 {failure}")
            self._load_tools()
            self.app.notify(
                f"更新完成：成功 {success}，失败 {failure}",
                title="全部更新",
                severity="information" if failure == 0 else "warning",
                timeout=5,
            )
        except Exception as e:
            self._set_status(f"更新失败: {e}", error=True)
            self.app.notify(f"更新失败: {e}", title="错误", severity="error", timeout=5)

    def action_export_report(self) -> None:
        """导出校验报告到 output/tool_report_<timestamp>.json。"""
        if not self._manifests_exist():
            self._set_status("manifest 文件不存在，无法导出", error=True)
            return

        try:
            checker = VersionChecker(
                wheels_manifest=self._wheels_manifest,
                wheels_dir=self._wheels_dir,
                tools_manifest=self._tools_manifest,
                project_root=self.project_root,
            )
            report = checker.check_all()

            output_dir = self.project_root / "output"
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = output_dir / f"tool_report_{timestamp}.json"

            report_data = {
                "timestamp": datetime.now().isoformat(),
                "overall": report.overall,
                "passed": report.passed,
                "wheels": [
                    {
                        "name": r.name,
                        "version": r.version,
                        "status": r.status,
                        "message": r.message,
                        "required": r.required,
                    }
                    for r in report.wheel_report.results
                ],
                "tools": [
                    {
                        "name": r.name,
                        "version": r.version,
                        "status": r.status,
                        "message": r.message,
                        "required": r.required,
                    }
                    for r in report.tool_report.results
                ],
            }

            with report_path.open("w", encoding="utf-8") as f:
                json.dump(report_data, f, ensure_ascii=False, indent=2)

            self._set_status(f"报告已导出到 {report_path}")
            self.app.notify(f"报告已导出到 {report_path}", severity="information", timeout=5)
        except Exception as e:
            self._set_status(f"导出失败: {e}", error=True)

    # =========================================================================
    # 内部辅助方法
    # =========================================================================

    def _manifests_exist(self) -> bool:
        """检查 manifest 文件是否存在。"""
        return self._tools_manifest.exists() and self._wheels_manifest.exists()

    def _load_tools(self) -> None:
        """加载工具列表到表格。"""
        table = self.query_one("#tool-table", DataTable)
        table.clear()

        # 加载外部工具
        if self._tools_manifest.exists():
            try:
                updater = ToolUpdater(
                    manifest_path=self._tools_manifest,
                    project_root=self.project_root,
                )
                for tool in updater.list_installed():
                    status = "已安装" if tool.installed else "未安装"
                    required = "是" if tool.required else "否"
                    table.add_row(
                        "外部",
                        tool.name,
                        tool.version or "-",
                        status,
                        required,
                        key=f"tool:{tool.name}",
                    )
            except Exception as e:
                table.add_row("外部", "-", "-", f"加载失败: {e}", "-", key="tool-error")
        else:
            table.add_row("外部", "-", "-", "manifest 不存在", "-", key="tool-no-manifest")

        # 加载 Python 依赖
        if self._wheels_manifest.exists():
            try:
                checker = VersionChecker(
                    wheels_manifest=self._wheels_manifest,
                    wheels_dir=self._wheels_dir,
                    tools_manifest=self._tools_manifest,
                    project_root=self.project_root,
                )
                wheel_report = checker.check_wheels()
                for r in wheel_report.results:
                    status = "正常" if r.status == "ok" else r.status
                    required = "是" if r.required else "否"
                    table.add_row(
                        "Python",
                        r.name,
                        r.version,
                        status,
                        required,
                        key=f"wheel:{r.name}",
                    )
            except Exception as e:
                table.add_row("Python", "-", "-", f"加载失败: {e}", "-", key="wheel-error")
        else:
            table.add_row("Python", "-", "-", "manifest 不存在", "-", key="wheel-no-manifest")

    def _show_detail(self, key: str) -> None:
        """显示选中工具的详情，并启用对应的操作按钮。

        Args:
            key: 行 key，格式为 'tool:<name>' 或 'wheel:<name>'
        """
        self._selected_key = key
        detail = self.query_one("#detail-content", Static)
        btn_update = self.query_one("#btn-update-one", Button)
        btn_rollback = self.query_one("#btn-rollback", Button)
        btn_homepage = self.query_one("#btn-homepage", Button)

        # 默认禁用所有操作按钮
        btn_update.disabled = True
        btn_rollback.disabled = True
        btn_homepage.disabled = True

        if key.startswith("tool:"):
            tool_name = key.split(":", 1)[1]
            self._render_tool_detail(tool_name, detail)
            # 外部工具：启用更新/回滚/官网按钮
            if self._tools_manifest.exists():
                btn_update.disabled = False
                btn_rollback.disabled = False
                btn_homepage.disabled = False
        elif key.startswith("wheel:"):
            wheel_name = key.split(":", 1)[1]
            self._render_wheel_detail(wheel_name, detail)
            # Python 依赖：仅启用官网按钮（更新通过 pip）
            btn_homepage.disabled = False
        else:
            detail.update(f"[yellow]该项无可用操作: {key}[/yellow]")

    def _render_tool_detail(self, tool_name: str, detail_widget: Static) -> None:
        """渲染外部工具详情（参照 §9.4.3）。

        Args:
            tool_name: 工具名
            detail_widget: 详情 Static 组件
        """
        try:
            updater = ToolUpdater(
                manifest_path=self._tools_manifest,
                project_root=self.project_root,
            )
            entry = updater._get_tool_entry(tool_name)
            installed_list = updater.list_installed()
            info = next((t for t in installed_list if t.name == tool_name), None)

            if info is None:
                detail_widget.update(f"[red]未找到工具: {tool_name}[/red]")
                return

            status_text = "[green]已安装[/green]" if info.installed else "[red]未安装[/red]"
            required_text = "是" if info.required else "否"
            homepage = entry.get("homepage", "(未配置)")
            latest = entry.get("latest_known", info.version)
            sha256 = entry.get("sha256", "(未配置)")
            sha_display = sha256[:16] + "..." if len(sha256) > 16 else sha256

            detail_widget.update(
                f"[bold cyan]{tool_name}[/bold cyan]\n"
                f"  当前版本: [yellow]{info.version}[/yellow]    最新版本: [green]{latest}[/green]\n"
                f"  安装路径: {info.install_path}/{info.entry}\n"
                f"  SHA256:   {sha_display}\n"
                f"  必选: {required_text}    状态: {status_text}\n"
                f"  官网: {homepage}"
            )
        except Exception as e:
            detail_widget.update(f"[red]加载详情失败: {e}[/red]")

    def _render_wheel_detail(self, wheel_name: str, detail_widget: Static) -> None:
        """渲染 Python 依赖详情。

        Args:
            wheel_name: 包名
            detail_widget: 详情 Static 组件
        """
        try:
            if not self._wheels_manifest.exists():
                detail_widget.update("[red]wheels_manifest.yaml 不存在[/red]")
                return
            checker = VersionChecker(
                wheels_manifest=self._wheels_manifest,
                wheels_dir=self._wheels_dir,
                tools_manifest=self._tools_manifest,
                project_root=self.project_root,
            )
            wheel_report = checker.check_wheels()
            result = next((r for r in wheel_report.results if r.name == wheel_name), None)

            if result is None:
                detail_widget.update(f"[red]未找到 Python 依赖: {wheel_name}[/red]")
                return

            status_text = (
                "[green]正常[/green]" if result.status == "ok" else f"[red]{result.status}[/red]"
            )
            required_text = "是" if result.required else "否"
            homepage = f"https://pypi.org/project/{wheel_name}/"

            detail_widget.update(
                f"[bold cyan]{wheel_name}[/bold cyan] (Python 依赖)\n"
                f"  当前版本: [yellow]{result.version}[/yellow]\n"
                f"  状态: {status_text}    必选: {required_text}\n"
                f"  消息: {result.message or '(无)'}\n"
                f"  PyPI: {homepage}"
            )
        except Exception as e:
            detail_widget.update(f"[red]加载详情失败: {e}[/red]")

    def _action_update_selected(self) -> None:
        """更新当前选中的外部工具到最新版本。"""
        if self._selected_key is None or not self._selected_key.startswith("tool:"):
            self._set_status("请先选择一个外部工具", error=True)
            return
        tool_name = self._selected_key.split(":", 1)[1]
        if not self._tools_manifest.exists():
            self._set_status("tools/manifest.yaml 不存在", error=True)
            return
        try:
            updater = ToolUpdater(
                manifest_path=self._tools_manifest,
                project_root=self.project_root,
            )
            self._set_status(f"正在更新 {tool_name}...")
            result = updater.update(tool_name)
            if result.success:
                self._set_status(f"更新成功: {tool_name} - {result.message}")
                self.app.notify(
                    f"{tool_name} 更新成功", title="更新完成", severity="information", timeout=3
                )
            else:
                self._set_status(f"更新失败: {result.message}", error=True)
                self.app.notify(
                    f"更新失败: {result.message}", title="错误", severity="error", timeout=5
                )
            self._load_tools()
            self._show_detail(self._selected_key)  # 刷新详情
        except Exception as e:
            self._set_status(f"更新异常: {e}", error=True)

    def _action_rollback_selected(self) -> None:
        """回滚当前选中的外部工具到备份版本。"""
        if self._selected_key is None or not self._selected_key.startswith("tool:"):
            self._set_status("请先选择一个外部工具", error=True)
            return
        tool_name = self._selected_key.split(":", 1)[1]
        if not self._tools_manifest.exists():
            self._set_status("tools/manifest.yaml 不存在", error=True)
            return
        try:
            updater = ToolUpdater(
                manifest_path=self._tools_manifest,
                project_root=self.project_root,
            )
            self._set_status(f"正在回滚 {tool_name}...")
            result = updater.rollback(tool_name)
            if result.success:
                self._set_status(f"回滚成功: {tool_name} - {result.message}")
                self.app.notify(
                    f"{tool_name} 回滚成功", title="回滚完成", severity="information", timeout=3
                )
            else:
                self._set_status(f"回滚失败: {result.message}", error=True)
                self.app.notify(
                    f"回滚失败: {result.message}", title="错误", severity="error", timeout=5
                )
            self._load_tools()
            self._show_detail(self._selected_key)  # 刷新详情
        except Exception as e:
            self._set_status(f"回滚异常: {e}", error=True)

    def _action_open_homepage(self) -> None:
        """打开当前选中工具的官网（外部工具用 manifest 的 homepage，Python 依赖用 PyPI）。"""
        if self._selected_key is None:
            self._set_status("请先选择一个工具", error=True)
            return
        try:
            if self._selected_key.startswith("tool:"):
                tool_name = self._selected_key.split(":", 1)[1]
                updater = ToolUpdater(
                    manifest_path=self._tools_manifest,
                    project_root=self.project_root,
                )
                entry = updater._get_tool_entry(tool_name)
                url = entry.get("homepage", "")
            elif self._selected_key.startswith("wheel:"):
                wheel_name = self._selected_key.split(":", 1)[1]
                url = f"https://pypi.org/project/{wheel_name}/"
            else:
                self._set_status("不支持的工具类型", error=True)
                return

            if not url:
                self._set_status("该工具未配置官网", error=True)
                return
            webbrowser.open(url)
            self._set_status(f"已在浏览器打开: {url}")
        except Exception as e:
            self._set_status(f"打开官网失败: {e}", error=True)

    def _set_status(self, message: str, error: bool = False) -> None:
        """更新状态栏。"""
        status = self.query_one("#status-bar", Static)
        if error:
            status.update(f"[red]{message}[/red]")
        else:
            status.update(f"[green]{message}[/green]")
