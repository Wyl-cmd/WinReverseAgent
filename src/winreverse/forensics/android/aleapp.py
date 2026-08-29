"""winreverse.forensics.android.aleapp — ALEAPP 桥接层。

许可证边界：ALEAPP（Android Logs Events And Protobuf Parser，MIT）为
持续演进的脚本集合，未发布 PyPI 包。采用"运行时下载通道"：
1. is_available: 探测 vendor/aleapp/ 是否已就位
2. setup_instructions: 下载/更新指引（git clone 到 vendor/aleapp/）
3. analyze: 调用其 CLI（aleapp.py）对提取目录解析制品并产出 HTML 报告

MIT 许可允许内置，但脚本集更新频繁且依赖较多（protobuf 等），
下载通道能保持上游最新解析规则，与本项目外部工具更新机制一致。
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# vendor/aleapp 期望位置
_ALEAPP_DIR = Path("vendor") / "aleapp"
_ALEAPP_ENTRY = "aleapp.py"

# 单次解析超时（秒；大提取目录可能较慢）
_ANALYZE_TIMEOUT = 1800


class AleappError(RuntimeError):
    """ALEAPP 调用失败的统一异常。"""


@dataclass
class AleappAnalysis:
    """一次 ALEAPP 解析的结果。

    Attributes:
        target: 提取目录/压缩包路径
        report_dir: HTML 报告输出目录
        command: 实际执行的完整命令
    """

    target: str
    report_dir: str
    command: str


class AleappBridge:
    """ALEAPP CLI 桥接（运行时下载通道）。"""

    def __init__(self, aleapp_dir: str | Path | None = None) -> None:
        """初始化桥接。

        Args:
            aleapp_dir: ALEAPP 源码目录（None 用项目 vendor/aleapp）
        """
        self._aleapp_dir = Path(aleapp_dir) if aleapp_dir is not None else Path.cwd() / _ALEAPP_DIR

    @property
    def aleapp_dir(self) -> Path:
        """ALEAPP 源码目录。"""
        return self._aleapp_dir

    @property
    def entry_script(self) -> Path:
        """aleapp.py 入口脚本路径。"""
        return self._aleapp_dir / _ALEAPP_ENTRY

    def is_available(self) -> bool:
        """ALEAPP 源码是否就位。"""
        return self.entry_script.is_file()

    def setup_instructions(self) -> str:
        """返回下载/更新指引（运行时获取，与外部工具更新机制一致）。"""
        return (
            "ALEAPP 未就位。请将源码放入 vendor/aleapp/：\n"
            "  git clone https://github.com/abrignoni/ALEAPP vendor/aleapp\n"
            "  pip install -r vendor/aleapp/requirements.txt\n"
            "ALEAPP 为 MIT 许可，解析规则随上游持续更新，建议定期 git pull。"
        )

    def _require_available(self) -> Path:
        """确保 ALEAPP 就位。"""
        if not self.is_available():
            raise AleappError(self.setup_instructions())
        return self.entry_script

    def analyze(
        self,
        target_path: str | Path,
        output_dir: str | Path,
    ) -> AleappAnalysis:
        """对 Android 提取目录（或 tar 包）执行制品解析。

        Args:
            target_path: 提取数据目录或 .tar/.tar.gz 归档
            output_dir: HTML 报告输出目录

        Returns:
            AleappAnalysis 结果

        Raises:
            AleappError: 未就位 / 目标不存在 / 解析失败
        """
        entry = self._require_available()
        target = Path(target_path)
        if not target.exists():
            raise AleappError(f"提取数据不存在: {target}")
        out = Path(output_dir)
        out.parent.mkdir(parents=True, exist_ok=True)

        cmd = [sys.executable, str(entry), "-t", str(target), "-o", str(out)]
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
        except subprocess.TimeoutExpired as e:
            raise AleappError("ALEAPP 解析超时") from e
        if completed.returncode != 0:
            stderr = completed.stderr.strip()[:2000]
            raise AleappError(f"ALEAPP 解析失败: {stderr}")
        return AleappAnalysis(target=str(target), report_dir=str(out), command=" ".join(cmd))
