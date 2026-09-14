"""winreverse.cli.net — 网络分析与抓包子命令（winreverse net）。

提供命令行抓包与分析工作流：
- winreverse net interfaces: 列出可抓包接口
- winreverse net capture: 实时抓包落盘 pcap（需管理员权限）
- winreverse net read: 解析 pcap（显示过滤/字段提取）
- winreverse net edit: pcap 文件级编辑（editcap）
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich import box
from rich.console import Console
from rich.table import Table

net_app = typer.Typer(
    name="net",
    help="网络分析：接口枚举 / 实时抓包 / pcap 解析与编辑（内置 tshark）",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

if TYPE_CHECKING:
    from winreverse.forensics.network import TsharkBridge

console = Console()


def _bridge(tshark_path: str | None) -> TsharkBridge:
    """构造 TsharkBridge（统一错误出口）。"""
    from winreverse.forensics.network import NetworkToolError, TsharkBridge

    try:
        return TsharkBridge(tshark_path) if tshark_path else TsharkBridge()
    except NetworkToolError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e


@net_app.command("interfaces")
def interfaces(
    tshark_path: str = typer.Option(None, "--tshark", help="tshark 路径"),
) -> None:
    """列出可抓包的网络接口。"""
    bridge = _bridge(tshark_path)
    from winreverse.forensics.network import NetworkToolError

    try:
        interface_list = bridge.list_interfaces()
    except NetworkToolError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    table = Table(box=box.ROUNDED, title=f"可抓包接口（{len(interface_list)}）")
    table.add_column("编号", style="cyan")
    table.add_column("名称", style="white")
    table.add_column("描述", style="green")
    for i in interface_list:
        table.add_row(str(i.index), i.name, i.description or "-")
    console.print(table)
    console.print("[yellow]抓包: winreverse net capture <编号> -o out.pcap -d 30[/yellow]")


@net_app.command("capture")
def capture(
    interface: str = typer.Argument(..., help="接口编号（net interfaces 查看）"),
    output: Path = typer.Option(..., "-o", "--out", help="pcap 输出路径"),
    duration: int = typer.Option(30, "-d", "--duration", help="抓包时长（秒）"),
    capture_filter: str = typer.Option(
        "", "-f", "--filter", help="BPF 捕获过滤（如 host 1.2.3.4）"
    ),
    tshark_path: str = typer.Option(None, "--tshark", help="tshark 路径"),
) -> None:
    """实时抓包落盘 pcap（需管理员权限）。"""
    bridge = _bridge(tshark_path)
    from winreverse.forensics.network import NetworkToolError

    console.print(f"[cyan]抓包 {duration} 秒（接口 {interface}）→ {output}[/cyan]")
    try:
        result_path = bridge.live_capture(
            output,
            interface=interface,
            duration_seconds=duration,
            capture_filter=capture_filter,
        )
    except NetworkToolError as e:
        console.print(f"[red]{e}[/red]")
        console.print("[yellow]提示: 抓包需要管理员权限运行[/yellow]")
        raise typer.Exit(1) from e
    console.print(f"[green]pcap 已保存:[/green] {result_path}")
    console.print(f"[yellow]解析: winreverse net read {result_path}[/yellow]")


@net_app.command("read")
def read(
    pcap_path: Path = typer.Argument(..., help="pcap 文件"),
    display_filter: str = typer.Option("", "-Y", help="显示过滤（如 http.request || dns）"),
    fields: str = typer.Option("", "-e", "--fields", help="逗号分隔字段（如 ip.src,http.host）"),
    tshark_path: str = typer.Option(None, "--tshark", help="tshark 路径"),
) -> None:
    """解析 pcap（显示过滤 / 字段提取）。"""
    bridge = _bridge(tshark_path)
    from winreverse.forensics.network import NetworkToolError

    field_list = [f.strip() for f in fields.split(",") if f.strip()] if fields else None
    try:
        result = bridge.read_pcap(pcap_path, display_filter=display_filter, fields=field_list)
    except NetworkToolError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    console.print(f"[bold]{result.packet_count} 行[/bold]")
    for line in result.lines[:200]:
        console.print(line)
    if len(result.lines) > 200:
        console.print(f"[yellow]（仅显示前 200 行，共 {len(result.lines)} 行）[/yellow]")


@net_app.command("edit")
def edit(
    input_pcap: Path = typer.Argument(..., help="输入 pcap"),
    output_pcap: Path = typer.Argument(..., help="输出 pcap"),
    keep_first_n: int = typer.Option(None, "--first", help="只保留前 N 个包"),
    remove_duplicates: bool = typer.Option(False, "--dedup", help="去除重复包"),
    tshark_path: str = typer.Option(None, "--tshark", help="tshark 路径"),
) -> None:
    """pcap 文件级编辑（editcap：取前 N 包/去重，如提取 C2 流量样本段）。"""
    # 修复(2026-09-12)：原实现先 `_bridge(tshark_path)` 构造 TsharkBridge，
    # 而本命令只用 editcap（editcap.exe 与 tshark 同属 Wireshark，但不必需 tshark），
    # 导致"有 editcap 无 tshark"的环境（含测试环境）在进入 editcap 分支前就抛
    # NetworkToolError、异常落在 try 之外直接冒泡 → 退出码 1 且报 tshark 缺失。
    # 现改为直接委托 EditcapBridge，错误统一由 NetworkToolError 出口处理。
    from winreverse.forensics.network import EditcapBridge, NetworkToolError

    editcap_override: Path | None = None
    if tshark_path:  # --tshark 兼容保留：给的是 tshark.exe 时按同目录找 editcap.exe
        candidate = Path(tshark_path).with_name("editcap.exe")
        if candidate.is_file():
            editcap_override = candidate

    try:
        editor = EditcapBridge(editcap_override)
        result_path = editor.edit_pcap(
            input_pcap,
            output_pcap,
            keep_first_n=keep_first_n,
            remove_duplicates=remove_duplicates,
        )
    except NetworkToolError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    console.print(f"[green]已输出:[/green] {result_path}")
