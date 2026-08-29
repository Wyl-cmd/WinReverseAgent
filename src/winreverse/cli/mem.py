"""winreverse.cli.mem — 内存取证子命令（winreverse mem）。

提供不依赖 LLM 的命令行内存取证入口：
- winreverse mem regions <pid|进程名>: 枚举进程内存区域，标注可疑注入区域
- winreverse mem dump <pid|进程名>: 全进程内存转储（raw bin + manifest.json）
- winreverse mem analyze <dump_dir>: 转储目录一键取证分析（字符串/IOC/熵/PE/YARA）

说明：
- 附加其他进程需要管理员权限；对自身进程无需提权
- regions / dump 需要目标进程存活；analyze 只操作落盘数据，可离线复现
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

mem_app = typer.Typer(
    name="mem",
    help="内存取证：区域枚举 / 全进程转储 / 转储分析",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


def _attach(target: str) -> tuple[Any, int]:
    """按进程名或 PID 附加进程。

    Args:
        target: 进程名（如 'notepad.exe'）或纯数字 PID

    Returns:
        (Pymem 实例, pid)

    Raises:
        typer.Exit: 附加失败（退出码 1）
    """
    from winreverse.core import memory_api

    try:
        pm = memory_api.attach(target)
    except memory_api.MemoryAccessError as e:
        console.print(f"[red]{e}[/red]")
        if "附加进程失败" in str(e):
            console.print("[yellow]提示: 附加其他进程需要管理员权限，请以管理员身份运行[/yellow]")
        raise typer.Exit(1) from e
    return pm, int(pm.process_id)


def _print_regions(target: str, pm: Any, include_all: bool) -> None:
    """打印内存区域表格。"""
    from winreverse.core import memdump_api

    regions = memdump_api.enumerate_regions(int(pm.process_handle), only_committed=True)
    suspicious = [r for r in regions if r.is_suspicious]
    executable = [r for r in regions if r.is_executable]
    shown = regions if include_all else executable

    console.print(
        f"[bold]进程 {target}[/bold]: 已提交区域 {len(regions)} 个，"
        f"可执行 {len(executable)} 个，[red]可疑注入候选 {len(suspicious)} 个[/red]"
    )
    if suspicious:
        console.print("[red]⚠ 可执行私有内存 / RWX 区域（代码注入候选）:[/red]")
        s_table = Table(box=box.ROUNDED, title="可疑区域")
        s_table.add_column("基地址", style="red")
        s_table.add_column("大小", style="yellow")
        s_table.add_column("保护", style="magenta")
        s_table.add_column("类型", style="cyan")
        for r in suspicious[:50]:
            s_table.add_row(f"0x{r.base_address:X}", f"{r.size:,}", r.protect_name, r.type_name)
        console.print(s_table)

    r_table = Table(box=box.ROUNDED, title="全部可执行区域" if not include_all else "全部区域")
    r_table.add_column("基地址", style="cyan")
    r_table.add_column("大小", style="yellow")
    r_table.add_column("保护", style="magenta")
    r_table.add_column("类型", style="white")
    r_table.add_column("映射文件", style="green")
    for r in shown[:200]:
        r_table.add_row(
            f"0x{r.base_address:X}",
            f"{r.size:,}",
            r.protect_name,
            r.type_name,
            r.mapped_file or "-",
        )
    if len(shown) > 200:
        console.print(f"[yellow]（仅显示前 200 个，共 {len(shown)} 个）[/yellow]")
    console.print(r_table)


@mem_app.command("regions")
def regions(
    target: str = typer.Argument(..., help="目标进程名或 PID"),
    include_all: bool = typer.Option(False, "--all", help="显示全部已提交区域（默认仅可执行）"),
) -> None:
    """枚举进程内存区域，识别可疑注入区域（无映像 backing 的可执行内存）。"""
    pm, _pid = _attach(target)
    _print_regions(target, pm, include_all)


@mem_app.command("dump")
def dump(
    target: str = typer.Argument(..., help="目标进程名或 PID"),
    output_dir: Path | None = typer.Option(
        None, "--out", "-o", help="输出目录（默认 output/memory_dumps/<pid>_<时间戳>）"
    ),
    max_total_mb: int = typer.Option(1024, "--max-mb", help="总转储上限（MB）"),
    min_size: int = typer.Option(0x1000, "--min-size", help="最小区域大小（字节）"),
) -> None:
    """全进程内存转储：按区域导出 raw bin + manifest.json 元数据清单。"""
    from winreverse.core import memdump_api
    from winreverse.core.memory_api import MemoryAccessError

    pm, pid = _attach(target)
    if output_dir is None:
        from datetime import datetime

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path(f"output/memory_dumps/{pid}_{timestamp}")

    console.print(f"[cyan]开始转储进程 {target} (pid={pid}) → {output_dir}[/cyan]")
    try:
        result = memdump_api.dump_process(
            int(pm.process_handle),
            output_dir,
            min_size=min_size,
            max_total_bytes=max_total_mb * 1024 * 1024,
        )
    except MemoryAccessError as e:
        console.print(f"[red]转储失败: {e}[/red]")
        raise typer.Exit(1) from e

    console.print(
        Panel(
            f"[bold]输出目录:[/bold] {result.output_dir}\n"
            f"[bold]清单文件:[/bold] {result.manifest_path}\n"
            f"[bold]区域总数:[/bold] {result.region_count}（转储 {result.dumped_count}，"
            f"跳过 {result.skipped_count}，截断 {result.truncated_count}）\n"
            f"[bold]总字节数:[/bold] {result.total_bytes:,}\n"
            f"[bold red]可疑区域:[/bold red] {result.suspicious_count}",
            title="转储完成",
            border_style="green",
        )
    )
    console.print("[yellow]后续: winreverse mem analyze " + result.output_dir + "[/yellow]")


@mem_app.command("analyze")
def analyze(
    dump_dir: Path = typer.Argument(..., help="memory.dump 输出的转储目录（需含 manifest.json）"),
    rules_path: Path | None = typer.Option(
        None, "--rules", "-r", help="YARA 规则文件（.yar/.yara）"
    ),
    top: int = typer.Option(20, "--top", help="每个文件保留的代表性字符串数"),
    no_carve: bool = typer.Option(False, "--no-carve", help="跳过 PE 雕刻"),
    json_output: Path | None = typer.Option(None, "--json", help="将完整报告写入 JSON 文件"),
) -> None:
    """转储目录一键取证分析：字符串 / IOC / 熵 / PE 雕刻 / YARA。"""
    from winreverse.core import memanalysis_api

    try:
        report = memanalysis_api.analyze_dump_dir(
            dump_dir,
            rules_path=rules_path,
            top_strings=top,
            carve=not no_carve,
        )
    except memanalysis_api.MemoryAnalysisError as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(1) from e

    overview = Table(box=box.ROUNDED, title="内存取证分析报告")
    overview.add_column("字段", style="cyan")
    overview.add_column("值", style="green")
    overview.add_row("转储目录", report.dump_dir)
    overview.add_row("目标 PID", str(report.pid) if report.pid else "-")
    overview.add_row("转储时间", report.created_at or "-")
    overview.add_row("分析字节数", f"{report.total_bytes:,}")
    overview.add_row("文件数", str(len(report.files)))
    overview.add_row("IOC 命中", str(report.total_ioc_count))
    overview.add_row("雕刻 PE", str(report.total_carved_pe_count))
    overview.add_row("YARA 命中文件数", str(len(report.yara_matches)))
    overview.add_row("可疑区域数", str(len(report.suspicious_regions)))
    console.print(overview)

    if report.suspicious_regions:
        s_table = Table(box=box.ROUNDED, title="可疑区域（注入候选）")
        s_table.add_column("文件", style="red")
        s_table.add_column("基地址", style="yellow")
        s_table.add_column("保护", style="magenta")
        s_table.add_column("类型", style="cyan")
        for region in report.suspicious_regions[:50]:
            s_table.add_row(
                str(region.get("file", "-")),
                str(region.get("base_address", "-")),
                str(region.get("protect", "-")),
                str(region.get("type", "-")),
            )
        console.print(s_table)

    for name, matches in report.yara_matches.items():
        console.print(f"[red]YARA 命中: {name}[/red]")
        for m in matches:
            meta = json.dumps(m.meta, ensure_ascii=False) if m.meta else "-"
            console.print(f"  - [bold]{m.rule}[/bold] tags={m.tags} meta={meta}")

    detail = Table(box=box.ROUNDED, title="文件明细")
    detail.add_column("文件", style="cyan")
    detail.add_column("大小", style="white")
    detail.add_column("熵", style="yellow")
    detail.add_column("字符串", style="white")
    detail.add_column("IOC", style="red")
    detail.add_column("PE", style="magenta")
    detail.add_column("告警", style="orange3")
    for f in report.files:
        detail.add_row(
            f.file,
            f"{f.size:,}",
            f"{f.entropy:.2f}",
            str(f.string_count),
            str(len(f.iocs)),
            str(len(f.carved_pes)),
            ";".join(f.warnings) or "-",
        )
    console.print(detail)

    # IOC 汇总（跨文件去重）
    ioc_by_kind: dict[str, set[str]] = {}
    for f in report.files:
        for hit in f.iocs:
            ioc_by_kind.setdefault(hit.kind, set()).add(hit.value)
    if ioc_by_kind:
        console.print("[bold red]IOC 汇总（跨文件去重）[/bold red]")
        for kind in sorted(ioc_by_kind):
            values = sorted(ioc_by_kind[kind])[:20]
            console.print(f"  [bold]{kind}[/bold] ({len(ioc_by_kind[kind])}): {', '.join(values)}")

    for warning in report.warnings:
        console.print(f"[yellow]告警: {warning}[/yellow]")

    if json_output is not None:
        json_output.parent.mkdir(parents=True, exist_ok=True)
        with json_output.open("w", encoding="utf-8") as fp:
            json.dump(report.to_dict(), fp, ensure_ascii=False, indent=2)
        console.print(f"[green]完整报告已写入: {json_output}[/green]")
