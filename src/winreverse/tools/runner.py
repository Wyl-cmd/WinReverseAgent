"""winreverse.tools.runner — 外部工具命令行调用封装。

职责：
通过 subprocess + 相对路径调用 tools/<name>/<entry>，避免修改系统 PATH。
所有外部工具（tshark/yara/diec/r2/ghidraRun）的命令行调用统一走本模块。

设计要点：
1. 从 tools/manifest.yaml 读取工具的 install_path 与 entry
2. 拼接 entry 完整路径（project_root / install_path / entry）
3. 检查 entry 是否存在（不存在则抛 FileNotFoundError）
4. 使用 subprocess.run 执行，捕获 stdout/stderr
5. Windows 编码兼容：默认 errors="replace" 避免中文输出解码崩溃

参考：实施方案 §5.2
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from loguru import logger as _logger

# =============================================================================
# 数据模型
# =============================================================================


@dataclass
class ToolRunResult:
    """工具执行结果。

    Attributes:
        tool_name: 工具名（如 'tshark'）
        command: 实际执行的命令列表（argv）
        returncode: 进程退出码（0 表示成功）
        stdout: 标准输出（已解码为字符串）
        stderr: 标准错误（已解码为字符串）
        duration_ms: 执行耗时（毫秒）
        timed_out: 是否因超时被终止
    """

    tool_name: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False

    @property
    def success(self) -> bool:
        """是否执行成功（returncode == 0 且未超时）。"""
        return self.returncode == 0 and not self.timed_out


# =============================================================================
# 异常
# =============================================================================


class ToolNotFoundError(FileNotFoundError):
    """工具 entry 文件不存在。"""


# =============================================================================
# ToolRunner — 外部工具调用器
# =============================================================================


class ToolRunner:
    """外部工具命令行调用器。

    通过 subprocess + 相对路径调用 tools/<name>/<entry>，
    不修改系统 PATH，保证绿色便携。

    用法：
        runner = ToolRunner(
            manifest_path=Path("tools/manifest.yaml"),
            project_root=Path("."),
        )
        result = runner.run("tshark", ["-r", "capture.pcap", "-Y", "dns"])
        if result.success:
            print(result.stdout)
        else:
            print(f"tshark 失败: {result.stderr}")
    """

    def __init__(
        self,
        manifest_path: Path,
        project_root: Path,
        default_timeout: int = 300,
        default_encoding: str | None = None,
    ) -> None:
        """初始化工具调用器。

        Args:
            manifest_path: tools/manifest.yaml 路径
            project_root: 项目根目录（用于解析 install_path 相对路径）
            default_timeout: 默认超时秒数（默认 300 秒）
            default_encoding: 默认输出编码（None 表示使用系统默认编码，
                Windows 上通常是 GBK；如需强制 UTF-8 可传 "utf-8"）
        """
        self.manifest_path = manifest_path
        self.project_root = project_root
        self.default_timeout = default_timeout
        self.default_encoding = default_encoding
        self._manifest_data: dict[str, Any] | None = None

    # ------------------------- manifest 加载 -------------------------

    def _load_manifest(self) -> dict[str, Any]:
        """加载 manifest.yaml（带缓存）。

        Returns:
            manifest 字典

        Raises:
            FileNotFoundError: manifest 文件不存在
            yaml.YAMLError: manifest 格式错误
            ValueError: manifest 顶层结构非字典
        """
        if self._manifest_data is not None:
            return self._manifest_data
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"manifest.yaml 不存在: {self.manifest_path}")
        with self.manifest_path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise ValueError(f"manifest.yaml 顶层应为字典，实际为 {type(data).__name__}")
        self._manifest_data = data
        return data

    def _get_tool_entry(self, name: str) -> dict[str, Any]:
        """从 manifest 中获取指定工具的配置项。

        Args:
            name: 工具名

        Returns:
            工具配置字典

        Raises:
            KeyError: 工具名未在 manifest 中登记
            ValueError: 配置项类型异常
        """
        manifest = self._load_manifest()
        tools = manifest.get("tools", [])
        entry = next((t for t in tools if t.get("name") == name), None)
        if entry is None:
            raise KeyError(f"工具未在 manifest 中登记: {name}")
        if not isinstance(entry, dict):
            raise ValueError(
                f"manifest.yaml 中 {name} 配置项应为字典，实际为 {type(entry).__name__}"
            )
        return entry

    # ------------------------- 路径解析 -------------------------

    def get_entry_path(self, tool_name: str) -> Path:
        """获取工具 entry 的完整路径。

        Args:
            tool_name: 工具名（如 'tshark'）

        Returns:
            entry 完整路径（project_root / install_path / entry）

        Raises:
            KeyError: 工具未在 manifest 中登记
            ValueError: manifest 字段类型异常
            ToolNotFoundError: entry 文件不存在
        """
        entry_cfg = self._get_tool_entry(tool_name)
        install_path = entry_cfg["install_path"]
        exe = entry_cfg["entry"]
        if not isinstance(install_path, str) or not isinstance(exe, str):
            raise ValueError(f"manifest.yaml 中 {tool_name} 的 install_path/entry 应为字符串")
        entry_path = self.project_root / install_path / exe
        if not entry_path.exists():
            raise ToolNotFoundError(
                f"工具 entry 不存在: {entry_path}（请先通过 updater 安装 {tool_name}）"
            )
        return entry_path

    # ------------------------- 命令执行 -------------------------

    def run(
        self,
        tool_name: str,
        args: list[str] | None = None,
        *,
        timeout: int | None = None,
        check: bool = False,
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
        encoding: str | None = None,
    ) -> ToolRunResult:
        """执行外部工具命令。

        Args:
            tool_name: 工具名（manifest 中的 name 字段）
            args: 命令行参数列表（不含工具名本身），默认空列表
            timeout: 超时秒数（None 表示使用 default_timeout）
            check: True 时返回码非 0 抛 CalledProcessError
            env: 追加的环境变量（合并到当前 env，不替换）
            cwd: 子进程工作目录（None 表示当前目录）
            encoding: 输出编码（None 表示使用 default_encoding）

        Returns:
            ToolRunResult 执行结果

        Raises:
            KeyError: 工具未在 manifest 中登记
            ToolNotFoundError: entry 文件不存在
            subprocess.TimeoutExpired: check=True 且超时时抛出
            subprocess.CalledProcessError: check=True 且返回码非 0 时抛出

        Note:
            - Windows 编码兼容：默认 errors="replace"，避免中文/特殊字符解码崩溃
            - 不修改系统 PATH，仅通过相对路径调用
        """
        if args is None:
            args = []
        effective_timeout = timeout if timeout is not None else self.default_timeout
        effective_encoding = encoding if encoding is not None else self.default_encoding

        entry_path = self.get_entry_path(tool_name)
        command = [str(entry_path), *args]

        # 环境变量：默认继承当前进程，允许追加
        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        _logger.info(f"[RUN] {tool_name}: {command} (timeout={effective_timeout}s)")

        start_ts = time.monotonic()
        timed_out = False
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                check=check,
                env=run_env,
                cwd=str(cwd) if cwd else None,
                encoding=effective_encoding,
                errors="replace",
            )
            returncode = completed.returncode
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
        except subprocess.TimeoutExpired as e:
            timed_out = True
            returncode = -1
            stdout = (e.stdout or "") if isinstance(e.stdout, str) else ""
            stderr = (e.stderr or "") if isinstance(e.stderr, str) else ""
            _logger.warning(
                f"[TIMEOUT] {tool_name} 执行超时（{effective_timeout}s），命令: {command}"
            )
        except subprocess.CalledProcessError as e:
            # check=True 时返回码非 0 抛出，直接向上抛原始异常
            _logger.warning(f"[FAIL] {tool_name} returncode={e.returncode}: {e.stderr}")
            raise

        duration_ms = int((time.monotonic() - start_ts) * 1000)

        result = ToolRunResult(
            tool_name=tool_name,
            command=command,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            timed_out=timed_out,
        )
        _logger.info(f"[DONE] {tool_name} returncode={returncode} duration={duration_ms}ms")
        return result

    # ------------------------- 便捷方法 -------------------------

    def run_text(
        self,
        tool_name: str,
        args: list[str] | None = None,
        *,
        timeout: int | None = None,
    ) -> str:
        """执行工具并返回 stdout 字符串（便捷方法）。

        Args:
            tool_name: 工具名
            args: 命令行参数列表
            timeout: 超时秒数

        Returns:
            stdout 字符串（已 strip）

        Raises:
            RuntimeError: 工具执行失败（返回码非 0 或超时）
            KeyError: 工具未在 manifest 中登记
            ToolNotFoundError: entry 文件不存在
        """
        result = self.run(tool_name, args, timeout=timeout, check=False)
        if not result.success:
            raise RuntimeError(
                f"{tool_name} 执行失败 (returncode={result.returncode}): {result.stderr}"
            )
        return result.stdout.strip()
