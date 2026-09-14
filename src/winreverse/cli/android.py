"""winreverse.cli.android — Android 取证子命令（winreverse android）。

提供命令行 Android 取证工作流：
- winreverse android devices: 列出已连接设备
- winreverse android info <serial>: 设备属性快照
- winreverse android packages <serial>: 第三方应用清单
- winreverse android pull <serial> <remote> [local]: 拉取文件
- winreverse android lime <serial>: LiME 内存采集引导（GPL 隔离）
- winreverse android analyze-image <镜像> <插件>: Volatility 3 分析
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

if TYPE_CHECKING:
    from winreverse.forensics.android.adb import AdbClient

android_app = typer.Typer(
    name="android",
    help="Android 取证：设备采集 / 文件提取 / LiME 引导 / 内存镜像分析",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


def _get_adb(adb_path: str | None) -> AdbClient:
    """构造 AdbClient（统一错误出口）。"""
    from winreverse.forensics.android.adb import AdbClient, AdbError

    try:
        return AdbClient(adb_path) if adb_path else AdbClient()
    except AdbError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e


@android_app.command("devices")
def devices(
    adb_path: str = typer.Option(None, "--adb", help="adb 路径（默认 tools/adb 或 PATH）"),
) -> None:
    """列出已连接的 Android 设备。"""
    adb = _get_adb(adb_path)
    from winreverse.forensics.android.adb import AdbError

    try:
        device_list = adb.list_devices()
    except AdbError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    if not device_list:
        console.print("[yellow]未发现设备（检查 USB 调试与授权）[/yellow]")
        return
    table = Table(box=box.ROUNDED, title=f"已连接设备（{len(device_list)}）")
    table.add_column("序列号", style="cyan")
    table.add_column("状态", style="green")
    table.add_column("型号", style="white")
    for d in device_list:
        console_style = "green" if d.state == "device" else "red"
        table.add_row(d.serial, f"[{console_style}]{d.state}[/{console_style}]", d.model)
    console.print(table)


@android_app.command("info")
def info(
    serial: str = typer.Argument(..., help="设备序列号"),
    adb_path: str = typer.Option(None, "--adb", help="adb 路径"),
) -> None:
    """采集设备属性快照（getprop，只读）。"""
    adb = _get_adb(adb_path)
    from winreverse.forensics.android.adb import AdbError

    try:
        info_obj = adb.get_device_info(serial)
    except AdbError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    console.print(
        Panel(
            f"[bold]型号:[/bold] {info_obj.brand} {info_obj.model}\n"
            f"[bold]Android:[/bold] {info_obj.android_version} (API {info_obj.api_level})\n"
            f"[bold]构建:[/bold] {info_obj.build_id}\n"
            f"[bold]安全补丁:[/bold] {info_obj.security_patch}\n"
            f"[bold]指纹:[/bold] {info_obj.extra.get('ro.build.fingerprint', '-')}",
            title=f"设备 {serial}",
            border_style="cyan",
        )
    )


@android_app.command("packages")
def packages(
    serial: str = typer.Argument(..., help="设备序列号"),
    adb_path: str = typer.Option(None, "--adb", help="adb 路径"),
) -> None:
    """列出第三方应用包名（取证关注面）。"""
    adb = _get_adb(adb_path)
    from winreverse.forensics.android.adb import AdbError

    try:
        package_list = adb.list_packages(serial, third_party_only=True)
    except AdbError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    console.print(f"[bold]第三方应用 {len(package_list)} 个[/bold]")
    for pkg in package_list:
        console.print(f"  {pkg}")


@android_app.command("pull")
def pull(
    serial: str = typer.Argument(..., help="设备序列号"),
    remote_path: str = typer.Argument(..., help="设备侧路径"),
    local_path: Path = typer.Argument(..., help="本地保存路径"),
    adb_path: str = typer.Option(None, "--adb", help="adb 路径"),
) -> None:
    """拉取设备文件到本地（只读取证归档）。"""
    adb = _get_adb(adb_path)
    from winreverse.forensics.android.adb import AdbError

    try:
        result_path = adb.pull_file(serial, remote_path, local_path)
    except AdbError as e:
        console.print(f"[red]拉取失败: {e}[/red]")
        raise typer.Exit(1) from e
    console.print(f"[green]已拉取[/green] {remote_path} → {result_path}")


@android_app.command("lime")
def lime(
    serial: str = typer.Argument(..., help="设备序列号"),
    local_module: str = typer.Option("lime.ko", "--module", help="本地编译好的 lime.ko 路径"),
) -> None:
    """生成 LiME 内存采集引导（GPL-2.0 隔离：只出命令清单，不分发不执行）。"""
    from winreverse.forensics.android.adb import AdbError
    from winreverse.forensics.android.lime import build_lime_guide

    adb = _get_adb(adb_path=None)
    try:
        kernel = adb.get_kernel_release(serial)
    except AdbError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    guide = build_lime_guide(serial, kernel_release=kernel, local_module_path=local_module)

    console.print(
        Panel(
            "LiME 内存采集需在设备侧手动执行以下命令（需 root）。\n"
            "lime.ko 须从 LiME 源码针对目标内核自编译（GPL-2.0，本项目不分发）。",
            title=f"LiME 采集引导（内核 {guide.kernel_release or '未知'}）",
            border_style="yellow",
        )
    )
    console.print("[bold]执行步骤:[/bold]")
    for i, step in enumerate(guide.steps, 1):
        console.print(f"  {i}. {step}")
    console.print("\n[bold]注意事项:[/bold]")
    for warning in guide.warnings:
        console.print(f"  [yellow]![/yellow] {warning}")
    console.print(
        "\n[yellow]镜像就绪后:[/yellow] winreverse android analyze-image ram.lime linux.pslist"
    )


@android_app.command("analyze-image")
def analyze_image(
    image_path: Path = typer.Argument(..., help="内存镜像（.lime/.raw/.dmp）"),
    plugin: str = typer.Argument(..., help="volatility3 插件（如 linux.pslist / windows.malfind）"),
    vol_path: str = typer.Option(None, "--vol", help="vol 命令路径（默认探测 PATH）"),
) -> None:
    """用 Volatility 3 分析内存镜像（白名单插件）。"""
    from winreverse.forensics.android.volatility import VolatilityBridge, VolatilityError

    bridge = VolatilityBridge(vol_path) if vol_path else VolatilityBridge()
    try:
        analysis = bridge.analyze(image_path, plugin)
    except VolatilityError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    console.print(f"[dim]$ {analysis.command}[/dim]")
    console.print(analysis.output)


@android_app.command("shell")
def shell_cmd(
    serial: str = typer.Argument(..., help="设备序列号"),
    command: str = typer.Argument(..., help="shell 命令（可写，root 操作自行加 su -c）"),
    adb_path: str = typer.Option(None, "--adb", help="adb 路径"),
) -> None:
    """在设备上执行任意 shell 命令（木马分析：部署/触发/排查）。"""
    adb = _get_adb(adb_path)
    from winreverse.forensics.android.adb import AdbError

    try:
        output = adb.shell_command(serial, command)
    except AdbError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    console.print(output or "[dim]（无输出）[/dim]")


@android_app.command("push")
def push(
    serial: str = typer.Argument(..., help="设备序列号"),
    local_path: Path = typer.Argument(..., help="本地文件"),
    remote_path: str = typer.Argument(..., help="设备侧目标路径"),
    adb_path: str = typer.Option(None, "--adb", help="adb 路径"),
) -> None:
    """推送本地文件到设备（部署采样代理/载荷）。"""
    adb = _get_adb(adb_path)
    from winreverse.forensics.android.adb import AdbError

    try:
        adb.push_file(serial, local_path, remote_path)
    except AdbError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    console.print(f"[green]已推送[/green] {local_path} → {remote_path}")


@android_app.command("install")
def install(
    serial: str = typer.Argument(..., help="设备序列号"),
    apk_path: Path = typer.Argument(..., help="APK 路径"),
    adb_path: str = typer.Option(None, "--adb", help="adb 路径"),
) -> None:
    """安装 APK 到设备（部署监控代理/测试样本）。"""
    adb = _get_adb(adb_path)
    from winreverse.forensics.android.adb import AdbError

    try:
        output = adb.install_apk(serial, apk_path)
    except AdbError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    console.print(f"[green]安装完成[/green] {output.strip()}")


@android_app.command("logcat")
def logcat_cmd(
    serial: str = typer.Argument(..., help="设备序列号"),
    lines: int = typer.Option(200, "--lines", "-n", help="最近条数"),
    tag: str = typer.Option("", "--tag", help="标签过滤"),
    adb_path: str = typer.Option(None, "--adb", help="adb 路径"),
) -> None:
    """抓取设备 logcat 日志（行为分析线索）。"""
    adb = _get_adb(adb_path)
    from winreverse.forensics.android.adb import AdbError

    try:
        text = adb.logcat(serial, lines=lines, filter_tag=tag)
    except AdbError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    console.print(text or "[dim]（无日志）[/dim]")


@android_app.command("screenshot")
def screenshot(
    serial: str = typer.Argument(..., help="设备序列号"),
    local_path: Path = typer.Argument(..., help="PNG 保存路径"),
    adb_path: str = typer.Option(None, "--adb", help="adb 路径"),
) -> None:
    """截取设备当前屏幕（行为记录）。"""
    adb = _get_adb(adb_path)
    from winreverse.forensics.android.adb import AdbError

    try:
        result = adb.screenshot(serial, local_path)
    except AdbError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    console.print(f"[green]已保存[/green] {result}")


@android_app.command("pair")
def pair(
    host_port: str = typer.Argument(..., help="配对页显示的 ip:配对端口"),
    pairing_code: str = typer.Argument(..., help="6 位配对码"),
    adb_path: str = typer.Option(None, "--adb", help="adb 路径"),
) -> None:
    """无线调试首次配对（Android 11+，无需 USB）。"""
    adb = _get_adb(adb_path)
    from winreverse.forensics.android.adb import AdbError

    try:
        output = adb.pair(host_port, pairing_code)
    except AdbError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    console.print(f"[green]{output.strip()}[/green]")


@android_app.command("connect")
def connect(
    host_port: str = typer.Argument(..., help="ip:端口（无线调试页显示）"),
    adb_path: str = typer.Option(None, "--adb", help="adb 路径"),
) -> None:
    """网络远程连接设备（Android 11+ 无线调试，配对后使用）。"""
    adb = _get_adb(adb_path)
    from winreverse.forensics.android.adb import AdbError

    try:
        output = adb.connect(host_port)
    except AdbError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    console.print(
        f"{output.strip()}\n[yellow]连接后直接用 devices/info/packages 等（serial 为 ip:端口）[/yellow]"
    )


@android_app.command("tcpip")
def tcpip(
    serial: str = typer.Argument(..., help="USB 连接的设备序列号"),
    port: int = typer.Option(5555, "--port", help="TCP 监听端口"),
    adb_path: str = typer.Option(None, "--adb", help="adb 路径"),
) -> None:
    """将 USB 设备切换为 TCP/IP 模式（拔线后走网络远程调试）。"""
    adb = _get_adb(adb_path)
    from winreverse.forensics.android.adb import AdbError

    try:
        adb.tcpip_mode(serial, port)
    except AdbError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    console.print(
        f"[green]已切换 TCP 模式[/green]，用 'winreverse android connect <设备IP>:{port}' 网络连接"
    )
