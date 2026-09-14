"""winreverse.cli — Typer CLI 根应用（pyproject 入口 winreverse = winreverse.cli:app）。

命令总览（详见 运行说明.md 第 4/6 章）：
- --version / -V: 打印版本号
- info: 项目信息（版本 / Python / 平台 / 许可证 / 配置路径）
- run: 启动 Agent（默认 TUI 主操作台，--repl 旧版 REPL）
- skill: 执行指定 Skill（-p 进程 / -f 文件 / -P key=value / --show-flow）
- list-skills: 列出已注册 Skill
- settings: 启动 Textual 可视化设置页
- gui: DearPyGui 图形配置界面（缺失时给出安装指引）
- tools: 工具管理子命令组（check / list / update / verify / rollback）
- mem / case / android / behavior / net: 取证与分析子命令组

说明：
- 重依赖（winreverse.app / 引擎工具栈 / TUI / 更新器）一律在命令内延迟导入，
  保持 CLI 冷启动轻量，与 cli.mem / cli.case 等子模块风格一致
- 失败路径统一 console.print 提示 + raise typer.Exit(code=1)
"""

from __future__ import annotations

import contextlib
import json
import sys
from pathlib import Path
from typing import Any

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from winreverse import __version__
from winreverse.config import load_or_default
from winreverse.skill.executor import SkillExecutionError
from winreverse.skill.loader import SkillNotFoundError


def _reconfigure_streams_utf8() -> None:
    """Windows 下把 stdout/stderr 重配置为 UTF-8（不可编码字符降级为 ?）。

    管道/SSH/重定向场景 stdout 编码回落 ANSI 代码页（cp437/cp1252 等 charmap），
    打印中文帮助文本会直接 UnicodeEncodeError 崩溃（--help 在回调前渲染，
    必须在模块导入期完成重配置）。交互式控制台本就走 UTF-8（PEP 528），不受影响。
    """
    if sys.platform != "win32":
        return
    for stream in (sys.stdout, sys.stderr):  # type: ignore[unreachable]
        if stream is not None and hasattr(stream, "reconfigure"):
            with contextlib.suppress(OSError, ValueError):
                stream.reconfigure(encoding="utf-8", errors="replace")


_reconfigure_streams_utf8()

app = typer.Typer(
    name="winreverse",
    help="WinReverseAgent — Windows 原生逆向工程 AI Agent",
    no_args_is_help=False,
    rich_markup_mode="rich",
)

console = Console()


# =============================================================================
# 模块级工具函数（测试会 patch 这两个名字）
# =============================================================================


def _get_project_root() -> Path:
    """定位项目根目录（用于 tools/manifest.yaml 与 vendor/ 解析）。

    从当前工作目录逐级向上查找 pyproject.toml 或 .git，找不到时回退当前目录。
    """
    current = Path.cwd()
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").exists() or (candidate / ".git").exists():
            return candidate
    return current


def _stdout_is_interactive() -> bool:
    """stdout 是否为交互式终端。

    双击 exe（stdout 非 tty）时无参数启动会直接进入 TUI 主操作台。
    """
    return sys.stdout is not None and sys.stdout.isatty()


def create_agent_from_config(app_config: Any) -> Any:
    """从 AppConfig 创建 Agent（薄委托，保持模块级名字可被 patch）。

    真正的工厂函数在 winreverse.app（会拉起引擎工具栈），此处延迟导入。

    Args:
        app_config: 应用配置（winreverse.config.AppConfig）

    Returns:
        winreverse.app.Agent 实例
    """
    from winreverse.app import create_agent_from_config as _factory

    return _factory(app_config)


# =============================================================================
# 回调与顶层选项
# =============================================================================


def _version_callback(value: bool) -> None:
    """--version / -V：打印版本号后退出。"""
    if value:
        console.print(f"WinReverseAgent v{__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="显示版本号后退出",
    ),
) -> None:
    """WinReverseAgent — Windows 原生逆向工程 AI Agent。"""
    if ctx.invoked_subcommand is None:
        if _stdout_is_interactive():
            # 无参数（双击 exe / 裸启动）直接进入 TUI 主操作台
            from winreverse.tui import launch_main_app

            launch_main_app()
            return
        console.print("[bold]WinReverseAgent[/bold] 当前 stdout 非交互式终端，跳过 TUI 启动。")
        console.print("查看全部命令: [cyan]winreverse --help[/cyan]")


# =============================================================================
# info / settings / skill / run / list-skills / gui
# =============================================================================


@app.command("info")
def info_command() -> None:
    """显示项目信息（版本 / Python / 目标平台 / 许可证 / 配置路径）。"""
    import platform

    from winreverse.config import get_default_config_path

    body = (
        f"[bold]WinReverseAgent[/bold] v{__version__}\n"
        f"版本: {__version__}\n"
        f"Python: {platform.python_version()}（{platform.python_implementation()}）\n"
        f"目标平台: Windows 10/11 x64（Windows 原生）\n"
        f"许可证: MIT\n"
        f"配置文件: {get_default_config_path()}\n"
        f"内部工具: 47 个 ToolInterface（外部工具管理见 winreverse tools）"
    )
    console.print(Panel(body, title="WinReverseAgent 项目信息", border_style="cyan"))


@app.command("settings")
def settings_command(
    config_path: Path | None = typer.Option(None, "-c", "--config", help="配置文件路径"),
) -> None:
    """启动可视化设置页（Textual TUI：LLM / Skill / 工具管理）。"""
    from winreverse.tui import SettingsApp

    config = load_or_default(config_path)
    settings_app = SettingsApp(config=config, project_root=_get_project_root())
    settings_app.run()


@app.command("skill")
def skill_command(
    name: str = typer.Argument(..., help="Skill 名称（如 'PE 文件分析'）"),
    process: str = typer.Option("", "-p", "--process", help="目标进程名"),
    file: str = typer.Option("", "-f", "--file", help="目标文件路径"),
    config_path: Path | None = typer.Option(None, "-c", "--config", help="配置文件路径"),
    show_flow: bool = typer.Option(False, "--show-flow", help="显示预置执行流结果"),
    params: list[str] = typer.Option([], "-P", "--param", help="额外参数 key=value，可多次指定"),
) -> None:
    """执行指定 Skill：组装参数 → 创建 Agent → run_skill_sync。"""
    # 1. 解析额外参数（key=value），格式错误直接退出
    skill_params: dict[str, Any] = {}
    for item in params:
        if "=" not in item:
            console.print(f"[red]参数格式错误: {item}（应为 key=value 形式）[/red]")
            raise typer.Exit(code=1)
        key, _, value = item.partition("=")
        skill_params[key.strip()] = value

    # 2. 组装预置参数（-f / -p 是常用快捷方式）
    if file:
        skill_params["file_path"] = file
    if process:
        skill_params["process_name"] = process

    # 3. 回显入参（便于无补全环境下确认）
    console.print(f"[bold]Skill:[/bold] {name}")
    if process:
        console.print(f"目标进程: {process}")
    if file:
        console.print(f"目标文件: {file}")
    if skill_params:
        rendered = ", ".join(f"{key}={value}" for key, value in skill_params.items())
        console.print(f"参数: {rendered}")

    # 4. 创建 Agent 并同步执行
    config = load_or_default(config_path)
    agent = create_agent_from_config(config)
    try:
        result = agent.run_skill_sync(name, skill_params)
    except SkillNotFoundError:
        console.print(f"[red]Skill '{name}' 未注册[/red]")
        skills = agent._skill_registry.list_skills()
        if skills:
            console.print("可用 Skill:")
            for skill in skills:
                console.print(f"  - {skill['name']}: {skill['description']}")
        else:
            console.print("未找到任何已注册 Skill（请检查 skills_dir 下的 YAML 定义）")
        raise typer.Exit(code=1) from None
    except SkillExecutionError as exc:
        console.print(f"[red]Skill 执行失败: SkillExecutionError: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    # 5. 展示预置执行流结果（可选）
    if show_flow:
        if result.flow_results:
            console.print("[bold]预置执行流结果[/bold]")
            for step in result.flow_results:
                marker = "OK" if not step.is_error else "ERROR"
                console.print(
                    f"  {marker}: {step.action} -> {step.output}",
                    markup=False,
                )
        else:
            console.print("（该 Skill 无预置执行流）")

    console.print(f"最终答复: {result.final_answer}")


@app.command("run")
def run_command(
    repl: bool = typer.Option(False, "--repl", help="使用旧版纯文本 REPL（默认启动 TUI 主操作台）"),
    config_path: Path | None = typer.Option(None, "-c", "--config", help="配置文件路径"),
    target: str = typer.Option(
        "", "-t", "--target", help="目标文件路径或进程名（显示在 TUI 标题栏）"
    ),
) -> None:
    """启动 Agent：默认进入 TUI 主操作台。"""
    config = load_or_default(config_path)
    agent = create_agent_from_config(config)
    if repl:
        raise typer.Exit(agent.run_repl())
    from winreverse.tui import launch_main_app

    launch_main_app(agent=agent, target=target)


@app.command("list-skills")
def list_skills_command() -> None:
    """列出已注册 Skill（名称 + 描述）。"""
    agent = create_agent_from_config(load_or_default())
    # Agent 为惰性初始化（__post_init__ 不建 registry），必须先触发
    agent._ensure_initialized()
    skills = agent._skill_registry.list_skills()
    if not skills:
        console.print("未找到任何 Skill（请检查 skills_dir 配置与 YAML 文件）")
        return
    table = Table(box=box.ROUNDED, title="已注册 Skill")
    table.add_column("名称", style="cyan")
    table.add_column("描述", style="white")
    for skill in skills:
        table.add_row(skill["name"], skill["description"])
    console.print(table)


@app.command("gui")
def gui_command(
    config_path: Path | None = typer.Option(None, "-c", "--config", help="配置文件路径"),
) -> None:
    """启动 DearPyGui 图形配置界面（主推；缺失时给出安装指引）。"""
    from winreverse.gui.app import GUIUnavailableError, run_gui

    try:
        run_gui(config_path)
    except GUIUnavailableError as exc:
        console.print(f"[yellow]{exc}[/yellow]")
        console.print("安装指引: uv pip install dearpygui（或用 vendor/wheels 离线包）")
        console.print("替代方案: [cyan]winreverse settings[/cyan]（Textual TUI 设置页）")
        raise typer.Exit(code=1) from exc


# =============================================================================
# tools 子命令组（运行说明.md §6.5）
# =============================================================================

tools_app = typer.Typer(
    name="tools",
    help="工具管理：外部工具与 Python 依赖的检查 / 更新 / 校验 / 回滚",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
app.add_typer(tools_app)

_TOOLS_MANIFEST = Path("tools") / "manifest.yaml"
_WHEELS_MANIFEST = Path("vendor") / "wheels_manifest.yaml"


def _check_result_to_dict(result: Any) -> dict[str, str]:
    """将 ToolCheckResult / WheelCheckResult 转为可 JSON 序列化的字典。"""
    return {
        "name": str(getattr(result, "name", "")),
        "version": str(getattr(result, "version", "")),
        "status": str(getattr(result, "status", "")),
        "message": str(getattr(result, "message", "")),
    }


@tools_app.command("check")
def tools_check() -> None:
    """检查外部工具可用更新（对比 version 与 latest_known，纯本地）。"""
    root = _get_project_root()
    manifest_path = root / _TOOLS_MANIFEST
    if not manifest_path.exists():
        console.print(f"[yellow]tools manifest 不存在，跳过更新检查: {manifest_path}[/yellow]")
        return
    from winreverse.tools.updater import ToolUpdater

    updater = ToolUpdater(manifest_path=manifest_path, project_root=root)
    updates = updater.check_updates()
    if not updates:
        console.print("[green]所有外部工具均为最新，无可用更新。[/green]")
        return
    table = Table(box=box.ROUNDED, title="外部工具更新检查")
    table.add_column("工具", style="cyan")
    table.add_column("当前版本", style="white")
    table.add_column("最新已知", style="green")
    table.add_column("必选", style="yellow")
    for update in updates:
        table.add_row(
            update.name,
            update.current,
            update.latest,
            "是" if update.required else "否",
        )
    console.print(table)


@tools_app.command("list")
def tools_list() -> None:
    """列出外部工具与安装状态（纯本地）。"""
    root = _get_project_root()
    manifest_path = root / _TOOLS_MANIFEST
    if not manifest_path.exists():
        console.print(f"[yellow]tools manifest 不存在: {manifest_path}[/yellow]")
        return
    from winreverse.tools.updater import ToolUpdater

    updater = ToolUpdater(manifest_path=manifest_path, project_root=root)
    installed = updater.list_installed()
    table = Table(box=box.ROUNDED, title="外部工具清单")
    table.add_column("工具", style="cyan")
    table.add_column("版本", style="white")
    table.add_column("状态", style="green")
    table.add_column("必选", style="yellow")
    table.add_column("入口", style="dim")
    for tool in installed:
        table.add_row(
            tool.name,
            tool.version,
            "已安装" if tool.installed else "未安装",
            "是" if tool.required else "否",
            tool.entry,
        )
    console.print(table)


@tools_app.command("update")
def tools_update(
    name: str | None = typer.Argument(None, help="工具名或 Python 依赖名（省略时更新全部）"),
    wheel: bool = typer.Option(False, "-w", "--wheel", help="将 name 视为 Python 依赖（wheel）"),
) -> None:
    """更新外部工具或 Python 依赖（联网下载 + SHA256 校验 + 备份回滚点）。"""
    root = _get_project_root()
    if wheel:
        wheels_manifest = root / _WHEELS_MANIFEST
        if not wheels_manifest.exists():
            console.print(f"[red]wheels manifest 不存在: {wheels_manifest}[/red]")
            raise typer.Exit(code=1)
        from winreverse.tools.version_checker import WheelUpdater

        wheel_updater = WheelUpdater(
            wheels_manifest=wheels_manifest,
            wheels_dir=root / "vendor" / "wheels",
        )
        if not name:
            results = wheel_updater.update_all()
            failed = [wheel_name for wheel_name, ok in results.items() if not ok]
            console.print(f"wheel 更新完成: 成功 {len(results) - len(failed)}，失败 {len(failed)}")
            raise typer.Exit(code=1 if failed else 0)
        if wheel_updater.update(name):
            console.print(f"[green]更新成功: {name}[/green]")
            raise typer.Exit(code=0)
        console.print(f"[red]更新失败: {name}[/red]")
        raise typer.Exit(code=1)

    manifest_path = root / _TOOLS_MANIFEST
    if not manifest_path.exists():
        console.print(f"[red]tools manifest 不存在: {manifest_path}[/red]")
        raise typer.Exit(code=1)
    from winreverse.tools.updater import ToolUpdater

    updater = ToolUpdater(manifest_path=manifest_path, project_root=root)
    if name:
        result = updater.update(name)
        if result.success:
            console.print(f"[green]{result.message}[/green]")
            raise typer.Exit(code=0)
        console.print(f"[red]{result.message}[/red]")
        raise typer.Exit(code=1)

    report = updater.update_all()
    for result in report.results:
        style = "green" if result.success else "red"
        console.print(f"[{style}]{result.message}[/{style}]", markup=False)
    console.print(f"批量更新完成: 成功 {report.success_count}，失败 {report.failure_count}")
    raise typer.Exit(code=0 if report.failure_count == 0 else 1)


@tools_app.command("verify")
def tools_verify(
    export: Path | None = typer.Option(None, "-e", "--export", help="将校验报告导出为 JSON 文件"),
) -> None:
    """完整性校验（存在性 / SHA256 / 版本一致性），显示总体状态。"""
    root = _get_project_root()
    tools_manifest = root / _TOOLS_MANIFEST
    if not tools_manifest.exists():
        console.print(f"[red]tools manifest 不存在: {tools_manifest}[/red]")
        raise typer.Exit(code=1)
    from winreverse.tools.version_checker import VersionChecker

    checker = VersionChecker(
        wheels_manifest=root / _WHEELS_MANIFEST,
        wheels_dir=root / "vendor" / "wheels",
        tools_manifest=tools_manifest,
        project_root=root,
    )
    report = checker.check_all()
    summary = "（通过）" if report.passed else "（未通过）"
    console.print(f"总体状态: [bold]{report.overall}[/bold]{summary}")

    for title, results in (
        ("外部工具校验", report.tool_report.results),
        ("Python 依赖校验", report.wheel_report.results),
    ):
        table = Table(box=box.ROUNDED, title=title)
        table.add_column("名称", style="cyan")
        table.add_column("版本", style="white")
        table.add_column("状态", style="yellow")
        table.add_column("说明", style="dim")
        for result in results:
            table.add_row(
                str(getattr(result, "name", "-")),
                str(getattr(result, "version", "-")),
                str(getattr(result, "status", "-")),
                str(getattr(result, "message", "-")),
            )
        console.print(table)

    if export is not None:
        report_data = {
            "overall": report.overall,
            "passed": report.passed,
            "tools": [_check_result_to_dict(r) for r in report.tool_report.results],
            "wheels": [_check_result_to_dict(r) for r in report.wheel_report.results],
        }
        export.parent.mkdir(parents=True, exist_ok=True)
        export.write_text(json.dumps(report_data, ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"[green]报告已导出: {export}[/green]")

    if not report.passed:
        raise typer.Exit(code=1)


@tools_app.command("rollback")
def tools_rollback(
    name: str = typer.Argument(..., help="要回滚的工具名"),
) -> None:
    """将指定工具回滚到 .bak 目录中的旧版本。"""
    root = _get_project_root()
    manifest_path = root / _TOOLS_MANIFEST
    if not manifest_path.exists():
        console.print(f"[red]tools manifest 不存在: {manifest_path}[/red]")
        raise typer.Exit(code=1)
    from winreverse.tools.updater import ToolUpdater

    updater = ToolUpdater(manifest_path=manifest_path, project_root=root)
    result = updater.rollback(name)
    if result.success:
        console.print(f"[green]{result.message}[/green]")
        raise typer.Exit(code=0)
    console.print(f"[red]{result.message}[/red]")
    raise typer.Exit(code=1)


# =============================================================================
# 取证与分析子命令组
# =============================================================================

from winreverse.cli.android import android_app  # noqa: E402
from winreverse.cli.behavior import behavior_app  # noqa: E402
from winreverse.cli.case import case_app  # noqa: E402
from winreverse.cli.mem import mem_app  # noqa: E402
from winreverse.cli.net import net_app  # noqa: E402

app.add_typer(mem_app)
app.add_typer(case_app)
app.add_typer(android_app)
app.add_typer(behavior_app)
app.add_typer(net_app)
