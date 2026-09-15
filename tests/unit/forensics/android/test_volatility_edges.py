"""被测模块: winreverse.forensics.android.volatility（边界路径）。

覆盖点: _probe_vol 命中 PATH 返回命令 / analyze 对 vol 可执行缺失
（FileNotFoundError）与插件超时（TimeoutExpired）的异常包装。
全部 mock 外部命令，无真机依赖，Linux 可实跑。
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from winreverse.forensics.android import volatility as volatility_module
from winreverse.forensics.android.volatility import VolatilityBridge, VolatilityError


class TestProbeVol:
    """_probe_vol 探测 PATH 中的 vol 命令。"""

    def test_probe_returns_first_hit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_which(name: str) -> str | None:
            return "/usr/local/bin/vol" if name == "vol" else None

        monkeypatch.setattr(shutil, "which", fake_which)
        assert VolatilityBridge._probe_vol() == Path("/usr/local/bin/vol")

    def test_probe_miss_everything_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shutil, "which", lambda _name: None)
        assert VolatilityBridge._probe_vol() is None

    def test_init_without_vol_reports_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shutil, "which", lambda _name: None)
        bridge = VolatilityBridge()
        assert bridge.is_available() is False
        assert "pip install volatility3" in bridge.install_instructions()


class TestAnalyzeFailurePaths:
    """analyze 的命令缺失 / 超时异常包装。"""

    def _bridge_with_image(self, tmp_path: Path) -> tuple[VolatilityBridge, Path]:
        image = tmp_path / "mem.lime"
        image.write_bytes(b"LiME")
        missing_vol = tmp_path / "no_such_bin" / "vol"
        return VolatilityBridge(vol_path=missing_vol), image

    def test_missing_vol_binary_wraps_filenotfound(self, tmp_path: Path) -> None:
        bridge, image = self._bridge_with_image(tmp_path)
        with pytest.raises(VolatilityError, match="vol 命令不可用"):
            bridge.analyze(image, "windows.malfind")

    def test_timeout_wraps_timeoutexpired(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bridge, image = self._bridge_with_image(tmp_path)

        def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(cmd="vol", timeout=1800)

        monkeypatch.setattr(volatility_module.subprocess, "run", fake_run)
        with pytest.raises(VolatilityError, match=r"分析超时: windows\.pslist"):
            bridge.analyze(image, "windows.pslist")
