"""winreverse.cli.behavior — 动态行为分析子命令（winreverse behavior）。

提供命令行动态行为分析工作流：
- winreverse behavior monitor <样本>: 进程隔离运行样本并采集四维行为报告
- winreverse behavior sandbox-check: Windows Sandbox 可用性检测
- winreverse behavior sandbox-wsb <样本>: 生成沙箱引爆配置（.wsb）
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

behavior_app = typer.Typer(
    name="behavior",
    help="动态行为分析：进程隔离监控（即插即用）/ Windows Sandbox 增强",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


@behavior_app.command("monitor")
def monitor(
    sample_path: Path = typer.Argument(..., help="样本文件路径（会被复制进隔离会话目录运行）"),
    duration: int = typer.Option(30, "-d", "--duration", help="监控时长（秒）"),
    sessions_root: Path = typer.Option(
        None, "--root", help="会话目录根（默认 output/behavior_sessions）"
    ),
    json_output: Path = typer.Option(None, "--json", help="完整报告写入 JSON 文件"),
) -> None:
    """运行动态行为监控（进程隔离，零配置；请仅对合法样本使用）。"""
    from winreverse.forensics.behavior import BehaviorError, ProcessIsolationRunner

    runner = (
        ProcessIsolationRunner(sessions_root=sessions_root)
        if sessions_root
        else ProcessIsolationRunner()
    )
    session_id: str | None = None
    try:
        session_id = runner.prepare(str(sample_path), {})
        runner.run(session_id, duration=duration)
        report = runner.collect(session_id)
    except BehaviorError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    finally:
        # 报告已采集，清理样本副本与残留进程（对齐 engine 层行为工具口径：
        # 样本常驻时不得无人处置；销毁失败不影响命令退出）
        if session_id is not None:
            with contextlib.suppress(Exception):
                runner.destroy(session_id)

    overview = Table(box=box.ROUNDED, title="行为监控报告")
    overview.add_column("字段", style="cyan")
    overview.add_column("值", style="green")
    overview.add_row("会话 ID", report["session_id"])
    overview.add_row("样本", report["sample"])
    overview.add_row("监控时长", f"{report['duration_seconds']} 秒")
    overview.add_row("退出码", str(report["exit_code"]))
    overview.add_row("事件数", str(report["event_count"]))
    overview.add_row("外联", ", ".join(report["outbound_connections"][:5]) or "-")
    overview.add_row("释放文件", str(len(report["dropped_files"])))
    risk = report["risk_score"]
    color = "red" if risk >= 60 else ("yellow" if risk >= 30 else "green")
    overview.add_row("风险评分", f"[{color}]{risk}/100[/{color}]")
    overview.add_row("风险因子", ", ".join(report["risk_factors"]) or "-")
    overview.add_row("IOC 数", str(len(report["iocs"])))
    console.print(overview)

    if report["iocs"]:
        console.print("[bold red]IOC:[/bold red]")
        for hit in report["iocs"][:20]:
            console.print(f"  [{hit['kind']}] {hit['value']}")

    if json_output is not None:
        json_output.parent.mkdir(parents=True, exist_ok=True)
        json_output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"[green]完整报告已写入: {json_output}[/green]")


@behavior_app.command("sandbox-check")
def sandbox_check() -> None:
    """检测 Windows Sandbox 是否可用（可选的更强隔离引爆环境）。"""
    from winreverse.forensics.sandbox_wsb import is_sandbox_available

    if is_sandbox_available():
        console.print(
            "[green]Windows Sandbox 已启用[/green]，"
            "可用 'winreverse behavior sandbox-wsb <样本>' 生成引爆配置"
        )
    else:
        console.print(
            "[yellow]Windows Sandbox 未启用[/yellow]（不影响即插即用："
            "直接用 'winreverse behavior monitor <样本>' 的进程隔离后端）"
        )


@behavior_app.command("sandbox-wsb")
def sandbox_wsb(
    sample_path: Path = typer.Argument(..., help="样本路径"),
    output: Path = typer.Option(
        Path("output/behavior_sessions/sample_sandbox.wsb"), "-o", "--out", help="wsb 输出路径"
    ),
    networking: bool = typer.Option(False, "--network/--no-network", help="是否允许沙箱联网"),
) -> None:
    """生成 Windows Sandbox 引爆配置（.wsb，默认关网络、只读映射）。"""
    from winreverse.forensics.sandbox_wsb import SandboxConfigError, write_wsb_config

    try:
        result_path = write_wsb_config(sample_path, output, networking=networking)
    except SandboxConfigError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    console.print(
        Panel(
            f"[bold]配置:[/bold] {result_path}\n"
            f"[bold]联网:[/bold] {'允许' if networking else '禁止'}\n"
            "双击 wsb 文件即可在 Windows Sandbox 中运行样本。",
            title="沙箱配置已生成",
            border_style="green",
        )
    )
