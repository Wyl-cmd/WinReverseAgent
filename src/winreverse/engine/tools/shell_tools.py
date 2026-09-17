"""winreverse.engine.tools.shell_tools — Shell 调用工具（Agent 基础设施）。

让 LLM 具备执行任意命令的能力（逆向工作的核心基础设施）：
- shell.run: 执行 cmd / powershell 命令（超时、输出截断、返回码）
  · cmd 分支：命令含内嵌双引号时落临时 .bat 执行（P1-4 修复，避免 list2cmdline
    的 \" 转义被 cmd.exe 误解析 → 带引号路径被破坏成伪 FILE_NOT_FOUND）

安全守卫（对齐 config.agent.yolo 配置语义）：
- 默认拦截破坏性命令模式（format / rd /s / del /f / shutdown / reg add HKLM /
  diskpart / bcdedit / Remove-Item -Recurse 等）
- 放行条件（二选一）：环境变量 WINREVERSE_YOLO=1（全局豁免，对应 GUI/TUI
  的 yolo 配置），或调用参数 allow_dangerous=true（LLM 显式申请）
- 输出统一 UTF-8 replace 解码，截断到 64KB 防止撑爆上下文
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from winreverse.engine.tools._base import BaseTool

# 默认命令超时（秒）
_DEFAULT_TIMEOUT = 120
# 输出截断（字节）
_OUTPUT_TRUNCATE = 64 * 1024

# 危险命令模式（不区分大小写，子串匹配）
_DANGEROUS_PATTERNS: tuple[str, ...] = (
    "format ",
    "rd /s",
    "rmdir /s",
    "del /f",
    "del /q",
    "erase /f",
    "shutdown",
    "diskpart",
    "bcdedit",
    "cipher /w",
    "reg add hkey_local_machine",
    "reg delete hkey_local_machine",
    "vssadmin delete",
    "wbadmin delete",
    "remove-item -recurse",
    "remove-item -force",
    "stop-computer",
    "restart-computer",
    "taskkill /f /im lsass",
    "attrib -s -h",
)


def _needs_cmd_script(command: str) -> bool:
    """命令是否需要经临时 .bat 执行（含内嵌双引号 → 会被 list2cmdline 破坏）。"""
    return '"' in command


def _script_encoding() -> str:
    """批处理文件编码：Windows 用 mbcs（=cmd.exe 当前 ANSI 代码页），其他平台 utf-8。"""
    if os.name == "nt":
        try:
            "x".encode("mbcs")
            return "mbcs"
        except LookupError:  # pragma: no cover - 非中文/西欧 Windows 语言的极端情形
            pass
    return "utf-8"


def _write_cmd_script(command: str) -> Path:
    """把命令原文写入临时 .bat（由 cmd.exe 原生解析引号与转义）。

    Args:
        command: 原始命令（保持原样写入，不做任何转义改写）

    Returns:
        临时批处理文件路径（调用方负责删除）

    Raises:
        OSError: 临时文件写入失败（由 BaseTool 兜底转为 error 结果）
    """
    fd, raw_path = tempfile.mkstemp(prefix="wra_cmd_", suffix=".bat")
    os.close(fd)
    script_path = Path(raw_path)
    payload = f"@echo off\r\n{command}\r\nexit /b %errorlevel%\r\n"
    try:
        script_path.write_bytes(payload.encode(_script_encoding(), errors="replace"))
    except OSError:
        script_path.unlink(missing_ok=True)
        raise
    return script_path


class ShellRunTool(BaseTool):
    """shell.run — 执行 shell 命令。

    2026-09-16（P1-4 修复）：cmd 分支在命令含内嵌引号时改走临时 .bat，
    避免 Windows list2cmdline 的 ``\\"`` 转义被 cmd.exe 误解析导致
    带引号路径变成"伪 FILE_NOT_FOUND"（0x80070002）。
    """

    name = "shell.run"
    description = (
        "执行 shell 命令（cmd 或 powershell，默认 cmd），返回返回码与输出；"
        "破坏性命令默认拦截（需 allow_dangerous=true 或全局 yolo 模式放行）"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        command = str(self._require(input_data, "command"))
        shell = str(input_data.get("shell", "cmd")).lower()
        timeout = int(input_data.get("timeout", _DEFAULT_TIMEOUT))
        cwd = str(input_data["cwd"]) if input_data.get("cwd") else None
        allow_dangerous = bool(input_data.get("allow_dangerous", False))

        if shell not in ("cmd", "powershell"):
            raise ValueError(f"不支持的 shell: {shell}（可选 cmd / powershell）")

        guard = self._check_dangerous(command)
        if guard and not (allow_dangerous or self._yolo_enabled()):
            return {
                "status": "error",
                "error_message": (
                    f"命令命中危险模式 {guard!r}，已被拦截。"
                    "确认必要后传 allow_dangerous=true 重试，"
                    "或开启全局 yolo 模式（WINREVERSE_YOLO=1 / 配置 agent.yolo）"
                ),
                "blocked_pattern": guard,
            }

        if shell == "powershell":
            argv: list[str] = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ]
            script_path: Path | None = None
        elif _needs_cmd_script(command):
            # P1-4 修复（2026-09-16 实测）：cmd.exe 不认 MSVCRT 的 \" 转义——
            # subprocess 传列表时 Windows 用 list2cmdline 把内嵌 " 变成 \"，
            # cmd 又把 \ 当字面量 → 带引号路径被破坏成本不存在的路径
            # （certutil 报 0x80070002 FILE_NOT_FOUND，误导成"样本不存在"）。
            # 修法：命令原文落到临时 .bat，由 cmd.exe 自己解析引号（等价于人工敲进 cmd）。
            script_path = _write_cmd_script(command)
            argv = ["cmd.exe", "/c", str(script_path)]
        else:
            # 无内嵌引号的命令继续沿用原 argv 形态（行为与既有测试保持一致）
            argv = ["cmd.exe", "/c", command]
            script_path = None

        workdir = str(Path(cwd).resolve()) if cwd else None
        try:
            completed = subprocess.run(
                argv,
                cwd=workdir,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as e:
            raise RuntimeError(f"shell 不可用: {e}") from e
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "error_message": f"命令超时（>{timeout}s）已被终止",
                "timed_out": True,
            }
        finally:
            if script_path is not None:
                script_path.unlink(missing_ok=True)

        stdout = (completed.stdout or "")[:_OUTPUT_TRUNCATE]
        stderr = (completed.stderr or "")[:_OUTPUT_TRUNCATE]
        result: dict[str, Any] = {
            "command": command,
            "shell": shell,
            "returncode": completed.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "truncated": len((completed.stdout or "").encode("utf-8")) > _OUTPUT_TRUNCATE,
        }
        # 统一 status 字段（BaseTool 只在异常时置 error，此处按返回码标注）
        if completed.returncode != 0:
            result["status"] = "error"
        return result

    @staticmethod
    def _yolo_enabled() -> bool:
        """全局 yolo 豁免（环境变量，与 config.agent.yolo 语义对齐）。"""
        return os.environ.get("WINREVERSE_YOLO", "").lower() in ("1", "true", "yes")

    @staticmethod
    def _check_dangerous(command: str) -> str | None:
        """命中危险模式时返回该模式，否则 None。"""
        lowered = command.lower()
        for pattern in _DANGEROUS_PATTERNS:
            if pattern in lowered:
                return pattern
        return None


# 工具实例列表
SHELL_TOOLS: list[BaseTool] = [
    ShellRunTool(),
]
