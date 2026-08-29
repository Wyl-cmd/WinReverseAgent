"""winreverse.forensics.android.volatility — Volatility 3 桥接层。

许可证边界：Volatility 3 采用 Volatility Software License（VSL，非标准 OSI
许可），不随本项目分发、不写入 vendor wheels。本模块提供：
1. 可用性探测（pip 包或独立 vol/vol.py 命令）
2. 运行时安装指引（用户显式确认后自行执行）
3. CLI 桥接分析：对内存镜像执行白名单插件，产出结构化文本结果

既支持 LiME 的 raw 镜像（Android/Linux），也支持本项目 memdump_api
产出的 Windows minidump（memory.dump_minidump 产物）。

参考：https://github.com/volatilityfoundation/volatility3
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

# 默认单插件分析超时（秒；全内存镜像的 malfind 等插件可能较慢）
_ANALYZE_TIMEOUT = 1800

# 插件白名单（防止把任意 -p 参数传给外部命令）
_ALLOWED_PLUGIN_PREFIXES = (
    "windows.",
    "linux.",
    "banners.",
    "isinfo.",
)


class VolatilityError(RuntimeError):
    """Volatility 3 调用失败的统一异常。"""


@dataclass
class VolatilityAnalysis:
    """一次插件分析的结果。

    Attributes:
        image: 镜像路径
        plugin: 插件名
        output: 插件 stdout 文本
        command: 实际执行的完整命令（供报告复现）
    """

    image: str
    plugin: str
    output: str
    command: str

    def to_dict(self) -> dict[str, str]:
        """转为 JSON 兼容字典。"""
        return {
            "image": self.image,
            "plugin": self.plugin,
            "output": self.output,
            "command": self.command,
        }


class VolatilityBridge:
    """Volatility 3 CLI 桥接（运行时安装通道 + 白名单插件执行）。"""

    def __init__(self, vol_path: str | Path | None = None) -> None:
        """初始化桥接。

        Args:
            vol_path: vol/vol.py 可执行路径（None 时自动探测 PATH 中的 vol/vol.exe）
        """
        self._vol_path: Path | None = Path(vol_path) if vol_path is not None else self._probe_vol()

    @staticmethod
    def _probe_vol() -> Path | None:
        """探测 PATH 中的 volatility3 命令。"""
        for name in ("vol", "vol.exe", "vol.py"):
            which = shutil.which(name)
            if which:
                return Path(which)
        return None

    def is_available(self) -> bool:
        """Volatility 3 命令是否可用。"""
        return self._vol_path is not None

    def install_instructions(self) -> str:
        """返回运行时安装指引（VSL 许可要求用户显式获取，故不自动安装）。"""
        return (
            "Volatility 3 采用自定义 VSL 许可，不随本项目分发。请手动安装：\n"
            "  pip install volatility3\n"
            "或从官方仓库获取：https://github.com/volatilityfoundation/volatility3\n"
            "安装后确认 vol 命令在 PATH 中，再次运行分析。"
        )

    def _require_available(self) -> Path:
        """确保 vol 命令可用。"""
        if self._vol_path is None:
            self._vol_path = self._probe_vol()
        if self._vol_path is None:
            raise VolatilityError(self.install_instructions())
        return self._vol_path

    def analyze(
        self,
        image_path: str | Path,
        plugin: str,
        *,
        extra_args: list[str] | None = None,
    ) -> VolatilityAnalysis:
        """对内存镜像执行白名单插件分析。

        Args:
            image_path: 内存镜像（.raw / .lime / .dmp）
            plugin: volatility3 插件名（如 windows.malfind / linux.pslist）
            extra_args: 附加参数（如 --profile，通常 v3 自动识别无需指定）

        Returns:
            VolatilityAnalysis 分析结果

        Raises:
            VolatilityError: 插件不在白名单 / 命令不可用 / 执行失败
        """
        if not plugin.startswith(_ALLOWED_PLUGIN_PREFIXES):
            allowed = ", ".join(_ALLOWED_PLUGIN_PREFIXES)
            raise VolatilityError(f"插件不在白名单内: {plugin}（允许前缀: {allowed}）")
        vol = self._require_available()
        image = Path(image_path)
        if not image.is_file():
            raise VolatilityError(f"镜像文件不存在: {image}")

        cmd = [str(vol), "-f", str(image), plugin, *(extra_args or [])]
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_ANALYZE_TIMEOUT,
                check=False,
            )
        except FileNotFoundError as e:
            raise VolatilityError(f"vol 命令不可用: {vol}") from e
        except subprocess.TimeoutExpired as e:
            raise VolatilityError(f"分析超时: {plugin}") from e
        if completed.returncode != 0:
            stderr = completed.stderr.strip()[:2000]
            raise VolatilityError(f"volatility3 分析失败: {plugin}: {stderr}")
        return VolatilityAnalysis(
            image=str(image),
            plugin=plugin,
            output=completed.stdout,
            command=" ".join(cmd),
        )
