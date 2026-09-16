"""测试模块：winreverse.cli.behavior 的 IOC 行渲染（rich markup 转义回归锁）。

真机现象（2026-09-15，Windows Server 2025 + `winreverse behavior monitor`）::

    IOC:
       C:\\work                ← 只剩空格 + 值，类型标签消失

根因：`console.print(f"  [{hit['kind']}] {hit['value']}")` 中 IOC kind 是
`filepath` / `ip` / `url` 这类裸词，rich 会把 `[filepath]` 解析成**样式标签**
并吞掉（不报错）→ 类型标签在终端不可见。修复：`rich.markup.escape` 转义
kind 与 value 后再拼接样式标签。

（本文件只锁渲染层；`filepath` 正则截断见
tests/unit/core/test_ioc_filepath_full_path.py。）
"""

from __future__ import annotations

import sys
import types
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from winreverse.cli import app

runner = CliRunner()

RUNNER = "winreverse.forensics.behavior.ProcessIsolationRunner"


@pytest.fixture(autouse=True)
def _isolated_memanalysis(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """隔离 core.memanalysis_api（经 yara）依赖链，与原 test_cli_behavior 同手法。"""
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
        "session_id": "sess-ioc",
        "sample": "malSample.exe",
        "duration_seconds": 5.0,
        "exit_code": 0,
        "event_count": 3,
        "outbound_connections": [],
        "dropped_files": [],
        "iocs": [],
        "risk_score": 25,
        "risk_factors": ["注册表持久化"],
    }
    base.update(overrides)
    return base


@pytest.fixture()
def runner_cls() -> Iterator[MagicMock]:
    """patch 进程隔离运行器源模块（prepare/run/collect 全 mock）。"""
    with patch(RUNNER) as cls:
        instance = cls.return_value
        instance.prepare.return_value = "sess-ioc"
        instance.collect.return_value = _report()
        yield cls


def _invoke(tmp_path: Path, iocs: list[dict[str, object]]):
    with patch(RUNNER) as cls:
        instance = cls.return_value
        instance.prepare.return_value = "sess-ioc"
        instance.collect.return_value = _report(iocs=iocs)
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"MZ")
        return runner.invoke(app, ["behavior", "monitor", str(sample)])


class TestIocKindLabelRendering:
    """IOC 行的类型标签必须可见（不得被 rich markup 吞掉）。"""

    def test_filepath_kind_label_visible(self, tmp_path: Path) -> None:
        result = _invoke(tmp_path, [{"kind": "filepath", "value": r"C:\work\x\evil.cmd"}])
        assert result.exit_code == 0
        assert "[filepath]" in result.stdout
        assert r"C:\work\x\evil.cmd" in result.stdout

    def test_ip_kind_label_visible(self, tmp_path: Path) -> None:
        """既有用例只断言值出现（`1.2.3.4`），标签被吞也照样通过 —— 此处补锁标签。"""
        result = _invoke(tmp_path, [{"kind": "ip", "value": "1.2.3.4"}])
        assert result.exit_code == 0
        assert "[ip]" in result.stdout
        assert "1.2.3.4" in result.stdout

    def test_markup_like_value_is_escaped(self, tmp_path: Path) -> None:
        """值里出现 `[red]` 之类字样时必须原样显示，不得被当样式标签。"""
        result = _invoke(tmp_path, [{"kind": "registry", "value": r"[red]HKLM\Software\Evil"}])
        assert result.exit_code == 0
        assert "[registry]" in result.stdout
        assert r"[red]HKLM\Software\Evil" in result.stdout

    def test_no_ioc_section_when_empty(self, tmp_path: Path) -> None:
        """无 IOC 时不渲染 IOC 段（维持既有语义）。"""
        result = _invoke(tmp_path, [])
        assert result.exit_code == 0
        assert "[filepath]" not in result.stdout
        assert "[ip]" not in result.stdout
