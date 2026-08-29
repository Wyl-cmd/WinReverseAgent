"""winreverse.cli.case — 取证案件子命令（winreverse case）。

提供命令行取证案件工作流：
- winreverse case create: 建案
- winreverse case list: 列出案件
- winreverse case show <case_id>: 查看案件详情与证据链
- winreverse case add <case_id> <path>: 登记文件证据
- winreverse case collect <case_id> <pid|进程名>: 内存转储并登记证据（联动 mem.dump）
- winreverse case verify <case_id>: 证据链完整性验证
- winreverse case report <case_id>: 导出案件 JSON 报告
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

if TYPE_CHECKING:
    from winreverse.forensics.case import CaseManager

case_app = typer.Typer(
    name="case",
    help="取证案件管理：建案 / 证据链 / 完整性验证 / 报告",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


def _get_manager() -> CaseManager:
    """构造 CaseManager（案件根目录默认 output/cases）。"""
    from winreverse.forensics.case import CaseManager

    return CaseManager(Path("output/cases"))


@case_app.command("create")
def create(
    name: str = typer.Argument(..., help="案件名称"),
    description: str = typer.Option("", "--desc", help="案件描述"),
) -> None:
    """创建新取证案件。"""
    from winreverse.forensics.case import CaseError

    manager = _get_manager()
    try:
        case = manager.create_case(name, description=description)
    except CaseError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    console.print(
        Panel(
            f"[bold]案件 ID:[/bold] {case.case_id}\n"
            f"[bold]目录:[/bold] {manager.case_dir(case.case_id)}",
            title=f"案件已创建: {name}",
            border_style="green",
        )
    )


@case_app.command("list")
def list_cases() -> None:
    """列出全部案件。"""
    manager = _get_manager()
    cases = manager.list_cases()
    if not cases:
        console.print("[yellow]暂无案件（winreverse case create <名称>）[/yellow]")
        return
    table = Table(box=box.ROUNDED, title=f"取证案件（{len(cases)}）")
    table.add_column("案件 ID", style="cyan")
    table.add_column("名称", style="white")
    table.add_column("证据数", style="yellow")
    table.add_column("建案时间", style="green")
    for case in cases:
        table.add_row(case.case_id, case.name, str(len(case.evidences)), case.created_at[:19])
    console.print(table)


@case_app.command("show")
def show(case_id: str = typer.Argument(..., help="案件 ID")) -> None:
    """查看案件详情与证据链。"""
    from winreverse.forensics.case import CaseError

    manager = _get_manager()
    try:
        case = manager.load_case(case_id)
    except CaseError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e

    console.print(
        Panel(
            f"[bold]名称:[/bold] {case.name}\n"
            f"[bold]描述:[/bold] {case.description or '-'}\n"
            f"[bold]建案:[/bold] {case.created_at}",
            title=case.case_id,
            border_style="cyan",
        )
    )
    if not case.evidences:
        console.print("[yellow]（暂无证据）[/yellow]")
        return
    table = Table(box=box.ROUNDED, title="证据链")
    table.add_column("证据 ID", style="magenta")
    table.add_column("类型", style="cyan")
    table.add_column("路径", style="white")
    table.add_column("SHA256", style="green")
    table.add_column("采集方式", style="yellow")
    for evidence in case.evidences:
        table.add_row(
            evidence.evidence_id,
            evidence.type.value,
            evidence.path or evidence.original_path,
            evidence.sha256[:16] + "...",
            evidence.collector or "-",
        )
    console.print(table)


@case_app.command("add")
def add(
    case_id: str = typer.Argument(..., help="案件 ID"),
    path: Path = typer.Argument(..., help="证据来源路径（文件或目录）"),
    evidence_type: str = typer.Option("raw_file", "--type", "-t", help="证据类型"),
    collector: str = typer.Option("", "--collector", help="采集方式说明"),
    notes: str = typer.Option("", "--notes", help="备注"),
) -> None:
    """登记文件/目录证据（复制入案件目录并建立 SHA256 基线）。"""
    from winreverse.forensics.case import CaseError, EvidenceType

    try:
        ev_type = EvidenceType(evidence_type)
    except ValueError:
        valid = ", ".join(t.value for t in EvidenceType)
        console.print(f"[red]未知证据类型: {evidence_type}（可选: {valid}）[/red]")
        raise typer.Exit(1) from None

    manager = _get_manager()
    try:
        evidence = manager.add_evidence(case_id, ev_type, path, collector=collector, notes=notes)
    except CaseError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    console.print(
        f"[green]证据已登记[/green] {evidence.evidence_id} " f"(SHA256: {evidence.sha256[:16]}...)"
    )


@case_app.command("collect")
def collect(
    case_id: str = typer.Argument(..., help="案件 ID"),
    target: str = typer.Argument(..., help="目标进程名或 PID"),
    max_total_mb: int = typer.Option(512, "--max-mb", help="总转储上限（MB）"),
) -> None:
    """内存采集入证：全进程内存转储并登记为案件证据（需管理员权限）。"""
    from winreverse.cli.mem import _attach
    from winreverse.core import memdump_api
    from winreverse.core.memory_api import MemoryAccessError
    from winreverse.forensics.case import CaseError, EvidenceType

    manager = _get_manager()
    pm, pid = _attach(target)
    temp_dir = Path("output/memory_dumps") / f"case_{pid}_collect"
    console.print(f"[cyan]转储进程 {target} (pid={pid}) → {temp_dir}[/cyan]")
    try:
        result = memdump_api.dump_process(
            int(pm.process_handle), temp_dir, max_total_bytes=max_total_mb * 1024 * 1024
        )
        evidence = manager.add_evidence(
            case_id,
            EvidenceType.MEM_DUMP,
            temp_dir,
            collector=f"memory.dump pid={pid}",
            notes=f"区域 {result.dumped_count}，共 {result.total_bytes:,} 字节，"
            f"可疑区域 {result.suspicious_count}",
        )
    except (CaseError, MemoryAccessError) as e:
        console.print(f"[red]采集失败: {e}[/red]")
        raise typer.Exit(1) from e

    console.print(
        Panel(
            f"[bold]证据 ID:[/bold] {evidence.evidence_id}\n"
            f"[bold]转储目录:[/bold] {result.output_dir}\n"
            f"[bold]区域:[/bold] {result.dumped_count}/{result.region_count}"
            f"（可疑 {result.suspicious_count}）\n"
            f"[bold]SHA256:[/bold] {evidence.sha256[:24]}...",
            title="内存证据已入案",
            border_style="green",
        )
    )
    console.print(f"[yellow]后续: winreverse mem analyze {result.output_dir}[/yellow]")


@case_app.command("verify")
def verify(case_id: str = typer.Argument(..., help="案件 ID")) -> None:
    """证据链完整性验证（重算全部证据哈希对照清单）。"""
    from winreverse.forensics.case import CaseError

    manager = _get_manager()
    try:
        result = manager.verify_case(case_id)
    except CaseError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e

    if result.passed:
        console.print(
            f"[green]证据链完整[/green]: {result.passed_count}/{result.checked_count} 条证据校验通过"
        )
    else:
        console.print(
            f"[red]证据链被破坏[/red]: {len(result.failures)}/{result.checked_count} 条失败"
        )
        for failure in result.failures:
            console.print(f"  [red]✗[/red] {failure['evidence_id']}: {failure['reason']}")
        raise typer.Exit(1)


@case_app.command("report")
def report(
    case_id: str = typer.Argument(..., help="案件 ID"),
    output: Path = typer.Option(
        None, "--out", "-o", help="报告输出路径（默认案件目录 report.json）"
    ),
) -> None:
    """导出案件 JSON 报告（清单 + 证据链 + 验证结果）。"""
    from winreverse.forensics.case import CaseError

    manager = _get_manager()
    try:
        report_path = manager.export_report(case_id, output)
    except CaseError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    report = json.loads(report_path.read_text(encoding="utf-8"))
    console.print(
        Panel(
            f"[bold]报告:[/bold] {report_path}\n"
            f"[bold]证据:[/bold] {report['evidence_count']} 条\n"
            f"[bold]验证:[/bold] {'通过' if report['verification']['passed'] else '失败'}",
            title="案件报告已导出",
            border_style="green",
        )
    )
