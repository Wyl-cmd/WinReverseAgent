"""winreverse.doctor — 环境自检与修复模块。

M1 阶段最小骨架（已实现）：
- 检查管理员权限
- 检查 Python 版本
- 检查核心契约模块可导入
- 输出自检报告

M2 阶段扩展（已实现）：
- 检查 vendor/wheels/ 完整性（按 wheels_manifest.yaml 校验 SHA256）

M3 阶段扩展（已实现）：
- 检查外部工具完整性（按 tools/manifest.yaml 校验 entry 存在性 + SHA256）
- 检查可用更新（对比 version 与 latest_known，仅提示不阻塞）
"""

from __future__ import annotations

import ctypes
import sys
from dataclasses import dataclass, field

from rich import box
from rich.console import Console
from rich.table import Table


@dataclass
class CheckResult:
    """单项检查结果。"""

    name: str
    status: str  # 'ok' / 'warn' / 'error'
    message: str = ""
    detail: str = ""


@dataclass
class DoctorReport:
    """doctor 自检报告。"""

    checks: list[CheckResult] = field(default_factory=list)

    @property
    def overall(self) -> str:
        """总体状态：有 error 即 error；否则有 warn 即 warn；否则 ok。"""
        if any(c.status == "error" for c in self.checks):
            return "error"
        if any(c.status == "warn" for c in self.checks):
            return "warn"
        return "ok"

    @property
    def passed(self) -> bool:
        """是否通过（无 error）。"""
        return not any(c.status == "error" for c in self.checks)


def _check_admin() -> CheckResult:
    """检查管理员权限。"""
    try:
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        # 非 Windows 平台，标记为 warn
        return CheckResult(
            name="管理员权限",
            status="warn",
            message="非 Windows 平台，跳过管理员权限检查",
        )
    if is_admin:
        return CheckResult(name="管理员权限", status="ok", message="已获取管理员权限")
    return CheckResult(
        name="管理员权限",
        status="warn",
        message="未以管理员身份运行",
        detail="内存读写需要管理员权限，请右键「以管理员身份运行」",
    )


def _check_python_version() -> CheckResult:
    """检查 Python 版本（>=3.12）。"""
    major, minor = sys.version_info[:2]
    version_str = f"{major}.{minor}.{sys.version_info[2]}"
    if (major, minor) >= (3, 12):
        return CheckResult(name="Python 版本", status="ok", message=f"Python {version_str}")
    return CheckResult(
        name="Python 版本",
        status="error",
        message=f"Python {version_str} 不满足要求",
        detail="需要 Python 3.12+，请升级",
    )


def _check_core_contracts() -> CheckResult:
    """检查核心契约模块可导入。"""
    try:
        from winreverse.engine import bus, mcp_adapter, sandbox_runner  # noqa: F401
        from winreverse.skill import loader  # noqa: F401

        return CheckResult(
            name="核心契约模块",
            status="ok",
            message="ToolInterface / SkillLoader / SandboxRunner / MCP 全部可导入",
        )
    except ImportError as e:
        return CheckResult(
            name="核心契约模块",
            status="error",
            message="核心契约导入失败",
            detail=str(e),
        )


def _check_platform() -> CheckResult:
    """检查运行平台。"""
    if sys.platform == "win32":
        return CheckResult(name="运行平台", status="ok", message="Windows")
    # 非 Windows 平台分支（mypy 在 Windows 上会判定为 unreachable，但保留跨平台兼容）
    return CheckResult(  # type: ignore[unreachable]
        name="运行平台",
        status="warn",
        message=f"当前平台 {sys.platform}，本项目仅支持 Windows",
    )


def _check_wheels() -> CheckResult:
    """检查 vendor/wheels/ 下 wheel 文件完整性（按 wheels_manifest.yaml 校验 SHA256）。"""
    from pathlib import Path

    from winreverse.tools.version_checker import WheelChecker

    # 定位项目根目录：doctor.py 在 src/winreverse/doctor.py
    project_root = Path(__file__).resolve().parent.parent.parent
    manifest_path = project_root / "vendor" / "wheels_manifest.yaml"
    wheels_dir = project_root / "vendor" / "wheels"

    if not manifest_path.exists():
        return CheckResult(
            name="Python wheel 完整性",
            status="error",
            message="wheels_manifest.yaml 不存在",
            detail=f"期望路径: {manifest_path}",
        )

    try:
        checker = WheelChecker(
            wheels_manifest=manifest_path,
            wheels_dir=wheels_dir,
            check_importable=False,
        )
        report = checker.check_all()
    except (OSError, ValueError) as e:
        return CheckResult(
            name="Python wheel 完整性",
            status="error",
            message="manifest 解析失败",
            detail=str(e),
        )

    total = len(report.results)
    ok_count = sum(1 for r in report.results if r.status == "ok")
    missing = report.missing_wheels
    mismatched = report.mismatched_wheels

    if report.passed:
        return CheckResult(
            name="Python wheel 完整性",
            status="ok",
            message=f"{ok_count}/{total} 个 wheel 校验通过",
            detail=f"目录: {wheels_dir}",
        )

    # 有必选项失败
    details = []
    if missing:
        details.append("缺失: " + ", ".join(f"{r.name}=={r.version}" for r in missing))
    if mismatched:
        details.append("SHA256 不匹配: " + ", ".join(f"{r.name}=={r.version}" for r in mismatched))
    return CheckResult(
        name="Python wheel 完整性",
        status="error",
        message=f"{ok_count}/{total} 个 wheel 校验通过（{total - ok_count} 个失败）",
        detail="; ".join(details),
    )


def _check_tools() -> CheckResult:
    """检查 tools/ 下外部工具完整性（按 manifest.yaml 校验 entry 存在性 + SHA256）。

    校验规则：
    - 必选工具 missing / sha256_mismatch → error
    - 可选工具 missing / sha256_mismatch → warn
    - sha256 为空（sha256_empty）→ warn（不阻塞）
    """
    from pathlib import Path

    from winreverse.tools.version_checker import ToolChecker

    # 定位项目根目录：doctor.py 在 src/winreverse/doctor.py
    project_root = Path(__file__).resolve().parent.parent.parent
    manifest_path = project_root / "tools" / "manifest.yaml"

    if not manifest_path.exists():
        return CheckResult(
            name="外部工具完整性",
            status="error",
            message="tools/manifest.yaml 不存在",
            detail=f"期望路径: {manifest_path}",
        )

    try:
        checker = ToolChecker(
            manifest_path=manifest_path,
            project_root=project_root,
        )
        report = checker.check_all()
    except (OSError, ValueError) as e:
        return CheckResult(
            name="外部工具完整性",
            status="error",
            message="manifest 解析失败",
            detail=str(e),
        )

    total = len(report.results)
    ok_count = sum(1 for r in report.results if r.status == "ok")
    missing = report.missing_tools
    mismatched = report.mismatched_tools
    empty_sha = report.empty_sha256_tools

    # 按必选/可选分类缺失与不匹配
    missing_required = [r for r in missing if r.required]
    missing_optional = [r for r in missing if not r.required]
    mismatch_required = [r for r in mismatched if r.required]
    mismatch_optional = [r for r in mismatched if not r.required]

    # 总体状态：必选 missing/mismatch → error；可选 missing/mismatch 或 sha256_empty → warn
    has_error = bool(missing_required or mismatch_required)
    has_warn = bool(missing_optional or mismatch_optional or empty_sha)

    if not has_error and not has_warn:
        return CheckResult(
            name="外部工具完整性",
            status="ok",
            message=f"{ok_count}/{total} 个工具校验通过",
            detail=f"清单: {manifest_path.relative_to(project_root)}",
        )

    details = []
    if missing_required:
        details.append("必选缺失: " + ", ".join(f"{r.name}=={r.version}" for r in missing_required))
    if mismatch_required:
        details.append(
            "必选 SHA256 不匹配: " + ", ".join(f"{r.name}=={r.version}" for r in mismatch_required)
        )
    if missing_optional:
        details.append("可选缺失: " + ", ".join(f"{r.name}=={r.version}" for r in missing_optional))
    if mismatch_optional:
        details.append(
            "可选 SHA256 不匹配: " + ", ".join(f"{r.name}=={r.version}" for r in mismatch_optional)
        )
    if empty_sha:
        details.append(
            "SHA256 未填写（仅 warn）: " + ", ".join(f"{r.name}=={r.version}" for r in empty_sha)
        )

    status = "error" if has_error else "warn"
    return CheckResult(
        name="外部工具完整性",
        status=status,
        message=f"{ok_count}/{total} 个工具校验通过（{total - ok_count} 个异常）",
        detail="; ".join(details),
    )


def _check_tool_updates() -> CheckResult:
    """检查外部工具可用更新（对比 version 与 latest_known，仅提示不阻塞）。"""
    from pathlib import Path

    from winreverse.tools.updater import ToolUpdater

    # 定位项目根目录：doctor.py 在 src/winreverse/doctor.py
    project_root = Path(__file__).resolve().parent.parent.parent
    manifest_path = project_root / "tools" / "manifest.yaml"

    if not manifest_path.exists():
        # manifest 不存在时 _check_tools 已报 error，此处跳过
        return CheckResult(
            name="工具更新检查",
            status="ok",
            message="manifest.yaml 不存在，跳过更新检查",
        )

    try:
        updater = ToolUpdater(
            manifest_path=manifest_path,
            project_root=project_root,
        )
        updates = updater.check_updates()
    except (OSError, ValueError) as e:
        return CheckResult(
            name="工具更新检查",
            status="warn",
            message="更新检查失败",
            detail=str(e),
        )

    if not updates:
        return CheckResult(
            name="工具更新检查",
            status="ok",
            message="所有工具均为最新版本",
        )

    detail = "; ".join(f"{u.name}: {u.current} -> {u.latest}" for u in updates)
    return CheckResult(
        name="工具更新检查",
        status="warn",
        message=f"{len(updates)} 个工具有可用更新",
        detail=detail + "（运行 --update-tools 或在设置页面更新）",
    )


def run_all_checks() -> DoctorReport:
    """运行全部自检，返回报告。"""
    report = DoctorReport()
    report.checks.append(_check_platform())
    report.checks.append(_check_python_version())
    report.checks.append(_check_admin())
    report.checks.append(_check_core_contracts())
    report.checks.append(_check_wheels())
    report.checks.append(_check_tools())
    report.checks.append(_check_tool_updates())
    return report


def print_report(report: DoctorReport) -> None:
    """打印自检报告到控制台。"""
    # Windows 控制台默认 GBK 编码，强制 UTF-8 避免 Unicode 字符报错
    import contextlib
    import sys

    if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
        with contextlib.suppress(AttributeError, OSError):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    console = Console()

    status_color = {"ok": "green", "warn": "yellow", "error": "red"}
    # 用 ASCII 字符避免 Windows GBK 控制台编码问题
    status_icon = {"ok": "OK", "warn": "!!", "error": "XX"}

    table = Table(title="WinReverseAgent 环境自检报告", box=box.ROUNDED)
    table.add_column("状态", justify="center", width=4)
    table.add_column("检查项", style="cyan")
    table.add_column("信息")
    table.add_column("详情", style="dim")

    for check in report.checks:
        icon = status_icon[check.status]
        color = status_color[check.status]
        table.add_row(
            f"[{color}]{icon}[/{color}]",
            check.name,
            check.message,
            check.detail,
        )

    console.print(table)

    # 总体状态
    overall = report.overall
    if overall == "ok":
        console.print("[green][OK] 全部检查通过[/green]")
    elif overall == "warn":
        console.print("[yellow][!!] 存在警告项，但不影响基础功能。[/yellow]\n详细原因见上表。")
    else:
        console.print("[red][XX] 存在错误项，请修复后重试。[/red]\n详细原因见上表。")


def main() -> int:
    """doctor 命令入口。

    Returns:
        0: 通过
        1: 有警告
        2: 有错误
    """
    report = run_all_checks()
    print_report(report)
    if report.overall == "error":
        return 2
    if report.overall == "warn":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
