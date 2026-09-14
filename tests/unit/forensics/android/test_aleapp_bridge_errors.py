"""被测模块: winreverse.forensics.android.aleapp（AleappBridge.analyze 错误分支）。

覆盖点: subprocess 超时 → AleappError；returncode != 0 → 携带 stderr 的 AleappError；
报告输出目录父级自动创建。纯 stdlib 导入链，Linux/Windows 均可实跑。
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from winreverse.forensics.android.aleapp import AleappBridge, AleappError


def _make_bridge(tmp_path: Path) -> AleappBridge:
    """构造一个 ALEAPP 源码已就位的桥接实例。"""
    aleapp_dir = tmp_path / "vendor" / "aleapp"
    aleapp_dir.mkdir(parents=True, exist_ok=True)
    (aleapp_dir / "aleapp.py").write_text("# entry", encoding="utf-8")
    return AleappBridge(aleapp_dir)


def _make_target(tmp_path: Path) -> Path:
    target = tmp_path / "extract"
    target.mkdir(exist_ok=True)
    return target


class TestAleappBridgeErrorBranches:
    """analyze() 失败路径（现有 test_android.py 只覆盖成功/缺目标/未就位）。"""

    def test_analyze_timeout(self, tmp_path: Path) -> None:
        """解析超时转 AleappError，而非向上泄漏 TimeoutExpired。"""
        bridge = _make_bridge(tmp_path)
        target = _make_target(tmp_path)
        with (
            patch(
                "winreverse.forensics.android.aleapp.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="aleapp.py", timeout=1800),
            ),
            pytest.raises(AleappError, match="超时"),
        ):
            bridge.analyze(target, tmp_path / "out")

    def test_analyze_failure_includes_stderr(self, tmp_path: Path) -> None:
        """非零退出码时 AleappError 信息携带子进程 stderr 便于排障。"""
        bridge = _make_bridge(tmp_path)
        target = _make_target(tmp_path)
        failing = MagicMock(returncode=2, stdout="", stderr="Traceback: protobuf boom\n")
        with (
            patch("winreverse.forensics.android.aleapp.subprocess.run", return_value=failing),
            pytest.raises(AleappError) as excinfo,
        ):
            bridge.analyze(target, tmp_path / "out")
        assert "解析失败" in str(excinfo.value)
        assert "protobuf boom" in str(excinfo.value)

    def test_analyze_creates_report_parent_dir(self, tmp_path: Path) -> None:
        """输出目录父级不存在时自动创建（report_dir 本身由 ALEAPP 生成）。"""
        bridge = _make_bridge(tmp_path)
        target = _make_target(tmp_path)
        out = tmp_path / "deep" / "nested" / "report"
        ok = MagicMock(returncode=0, stdout="", stderr="")
        with patch("winreverse.forensics.android.aleapp.subprocess.run", return_value=ok):
            result = bridge.analyze(target, out)
        assert out.parent.is_dir()
        assert result.target == str(target)
        assert str(target) in result.command and str(out) in result.command
