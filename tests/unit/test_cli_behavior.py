"""测试模块：winreverse.cli.behavior（winreverse behavior 子命令组）。

覆盖：monitor 的运行器委托（prepare/run/collect）、报告渲染与 --json 落盘、
风险分级显示、BehaviorError 错误出口；sandbox-check 判定文案；
sandbox-wsb 的配置生成委托与 SandboxConfigError 错误出口。
"""

from __future__ import annotations

import json
import re
import sys
import types
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from winreverse.cli import app
from winreverse.forensics.sandbox_wsb import SandboxConfigError

runner = CliRunner()

RUNNER = "winreverse.forensics.behavior.ProcessIsolationRunner"


@pytest.fixture(autouse=True)
def _isolated_memanalysis(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """在 core.memanalysis_api 调用点边界隔离依赖链（全 mock，平台无关）。

    winreverse.forensics.behavior 顶层 `from winreverse.core.memanalysis_api
    import extract_iocs_from_text`，而 core.memanalysis_api 顶层链路 import
    yara。本文件被测路径不触达 IOC 提取实现（ProcessIsolationRunner 全
    mock），故对 core 调用点注入 fake 模块（与 test_cli_mem_offline 同一
    手法），不伪造 yara 本体；teardown 弹出 forensics.behavior，保证其他
    测试拿到未被 fake 污染的真实导入（monkeypatch 自行还原 sys.modules）。
    """
    fake = types.ModuleType("winreverse.core.memanalysis_api")
    fake.extract_iocs_from_text = lambda text: []
    import winreverse.core as core_pkg

    monkeypatch.setitem(sys.modules, "winreverse.core.memanalysis_api", fake)
    monkeypatch.setattr(core_pkg, "memanalysis_api", fake, raising=False)
    yield
    sys.modules.pop("winreverse.forensics.behavior", None)


def _report(**overrides: object) -> dict[str, object]:
    """与 BehaviorReport.to_dict 键结构一致的采集报告。"""
    base: dict[str, object] = {
        "session_id": "sess-001",
        "sample": "malSample.exe",
        "duration_seconds": 5.0,
        "exit_code": 0,
        "event_count": 12,
        "outbound_connections": ["1.2.3.4:443"],
        "dropped_files": ["C:\\Temp\\drop.dll"],
        "iocs": [{"kind": "ip", "value": "1.2.3.4"}],
        "risk_score": 75,
        "risk_factors": ["外联连接", "释放文件"],
    }
    base.update(overrides)
    return base


@pytest.fixture()
def runner_cls() -> MagicMock:
    """patch 进程隔离运行器源模块。"""
    with patch(RUNNER) as cls:
        instance = cls.return_value
        instance.prepare.return_value = "sess-001"
        instance.collect.return_value = _report()
        yield cls


class TestMonitorCommand:
    """behavior monitor：进程隔离监控全流程。"""

    def test_runs_and_renders_report(self, runner_cls: MagicMock, tmp_path: Path) -> None:
        sample = tmp_path / "malSample.exe"
        sample.write_bytes(b"MZ")
        result = runner.invoke(
            app, ["behavior", "monitor", str(sample), "-d", "5", "--root", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "sess-001" in result.stdout
        assert "malSample.exe" in result.stdout
        assert "75/100" in result.stdout
        assert "1.2.3.4" in result.stdout
        assert "外联连接" in result.stdout
        instance = runner_cls.return_value
        instance.prepare.assert_called_once_with(str(sample), {})
        kwargs = instance.run.call_args.kwargs
        assert kwargs["duration"] == 5
        instance.collect.assert_called_once_with("sess-001")

    def test_json_output_writes_report(self, runner_cls: MagicMock, tmp_path: Path) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"MZ")
        json_path = tmp_path / "r.json"
        result = runner.invoke(app, ["behavior", "monitor", str(sample), "--json", str(json_path)])
        assert result.exit_code == 0
        assert "完整报告已写入" in result.stdout
        saved = json.loads(json_path.read_text(encoding="utf-8"))
        assert saved["session_id"] == "sess-001"
        assert saved["risk_score"] == 75

    def test_low_risk_sample(self, runner_cls: MagicMock, tmp_path: Path) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"MZ")
        runner_cls.return_value.collect.return_value = _report(
            risk_score=10, risk_factors=[], iocs=[], outbound_connections=[]
        )
        result = runner.invoke(app, ["behavior", "monitor", str(sample)])
        assert result.exit_code == 0
        assert "10/100" in result.stdout
        assert "1.2.3.4" not in result.stdout  # 无 IOC 值时不得出现 IOC 段

    def test_behavior_error_exits_1(self, runner_cls: MagicMock, tmp_path: Path) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"MZ")
        from winreverse.forensics.behavior import BehaviorError

        runner_cls.return_value.prepare.side_effect = BehaviorError("样本不存在")
        result = runner.invoke(app, ["behavior", "monitor", str(sample)])
        assert result.exit_code == 1
        assert "样本不存在" in result.stdout


class TestSandboxCheckCommand:
    """behavior sandbox-check：Windows Sandbox 可用性文案。"""

    def test_available(self) -> None:
        with patch("winreverse.forensics.sandbox_wsb.is_sandbox_available", return_value=True):
            result = runner.invoke(app, ["behavior", "sandbox-check"])
        assert result.exit_code == 0
        assert "已启用" in result.stdout

    def test_unavailable(self) -> None:
        with patch("winreverse.forensics.sandbox_wsb.is_sandbox_available", return_value=False):
            result = runner.invoke(app, ["behavior", "sandbox-check"])
        assert result.exit_code == 0
        assert "未启用" in result.stdout


class TestSandboxWsbCommand:
    """behavior sandbox-wsb：引爆配置生成委托与错误出口。"""

    def test_generates_config(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"MZ")
        out = tmp_path / "s.wsb"
        with patch("winreverse.forensics.sandbox_wsb.write_wsb_config", return_value=out) as write:
            result = runner.invoke(app, ["behavior", "sandbox-wsb", str(sample), "-o", str(out)])
        assert result.exit_code == 0
        # 修复(2026-09-12)：rich 面板会把长路径折行（并在折行处插入边框字符），
        # 直接子串匹配在 Windows 长临时路径下必失败。归一化空白与边框后再比较。
        flat = re.sub(r"[\s\u2502\u2503]+", "", result.stdout)
        assert re.sub(r"\s+", "", str(out)) in flat
        assert "禁止" in result.stdout  # 默认不联网
        write.assert_called_once_with(sample, out, networking=False)

    def test_config_error_exits_1(self, tmp_path: Path) -> None:
        sample = tmp_path / "missing.exe"
        with patch(
            "winreverse.forensics.sandbox_wsb.write_wsb_config",
            side_effect=SandboxConfigError("样本不存在"),
        ):
            result = runner.invoke(app, ["behavior", "sandbox-wsb", str(sample)])
        assert result.exit_code == 1
        assert "样本不存在" in result.stdout
