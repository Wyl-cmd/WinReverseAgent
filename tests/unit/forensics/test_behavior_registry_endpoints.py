"""behavior.py 注册表维度与网络快照过滤弧的直测（2026-09-16 错峰轮）。

覆盖点（coverage_guest 2026-09-16 复核 missed）：
- ``_snapshot_connections`` 回环/未连接地址跳过分支；
- ``_read_registry_key`` EnumValue 成功累积路径与 OpenKey 失败兜底；
- ``ProcessIsolationRunner._diff_registry`` 变更事件追加分支。

注册表用例读真实注册表（HKCU 只读），不写入任何键值。
winreg 为 Windows 专有依赖，直连 import：依赖缺失 → Linux 如实报
collection error（基线接受态），待 Windows 实机（依赖就位）实跑回填。
"""

from __future__ import annotations

import winreg
from pathlib import Path
from types import SimpleNamespace

import pytest

from winreverse.forensics import behavior
from winreverse.forensics.behavior import (
    BehaviorReport,
    ProcessIsolationRunner,
    _read_registry_key,
    _Session,
    _snapshot_connections,
)

# 该键随用户首登即被系统填充，值集必非空，只读访问
_SHELL_FOLDERS = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
_NO_SUCH_KEY = r"Software\__wra_no_such_key_20260916__"


def test_snapshot_connections_excludes_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    """未连接与回环/全零地址必须被过滤，仅保留真实外联 endpoint 且去重。"""
    conns = [
        SimpleNamespace(raddr=None),  # 未建立连接
        SimpleNamespace(raddr=SimpleNamespace(ip="127.0.0.1", port=135)),
        SimpleNamespace(raddr=SimpleNamespace(ip="::1", port=445)),
        SimpleNamespace(raddr=SimpleNamespace(ip="0.0.0.0", port=137)),
        SimpleNamespace(raddr=SimpleNamespace(ip="10.0.0.5", port=8080)),
        SimpleNamespace(raddr=SimpleNamespace(ip="10.0.0.5", port=8080)),
    ]

    def fake_net_connections(*, kind: str) -> list[SimpleNamespace]:
        assert kind == "inet"
        return conns

    monkeypatch.setattr(behavior.psutil, "net_connections", fake_net_connections)

    assert _snapshot_connections() == {"10.0.0.5:8080"}


def test_read_registry_key_reads_all_values() -> None:
    """真实键：返回键下全部值（字符串化）；Shell Folders 必非空。"""
    values = _read_registry_key(winreg.HKEY_CURRENT_USER, _SHELL_FOLDERS)

    assert isinstance(values, dict)
    assert len(values) >= 1
    assert all(isinstance(name, str) and isinstance(v, str) for name, v in values.items())


def test_read_registry_key_missing_returns_empty() -> None:
    """键不存在：OpenKey 抛 OSError → 返回空字典而非异常。"""
    assert _read_registry_key(winreg.HKEY_CURRENT_USER, _NO_SUCH_KEY) == {}


def test_diff_registry_appends_events_and_rebaselines(tmp_path: Path) -> None:
    """空基线 + 真实键必有值 → 必产出 registry 事件；diff 后基线重置，二次 diff 零新事件。"""
    keys = [(winreg.HKEY_CURRENT_USER, _SHELL_FOLDERS)]
    runner = ProcessIsolationRunner(registry_keys=keys, sessions_root=tmp_path)
    session = _Session(
        session_id="t_reg_diff",
        sample_path=tmp_path / "sample.exe",
        isolated_path=tmp_path / "sample.exe",
        session_dir=tmp_path,
        watch_dirs=[],
        registry_keys=keys,
        baseline_registry={},  # 空基线：现网任何值都算变更
    )
    session.report = BehaviorReport(session_id="t_reg_diff", sample="sample.exe")

    runner._diff_registry(session)

    first = [e for e in session.report.events if e.kind == "registry"]
    assert len(first) >= 1
    event = first[0]
    assert event.detail["key"] == f"HKCU\\{_SHELL_FOLDERS}"
    assert event.detail["name"]
    assert event.detail["value"]
    assert event.risk == behavior._RISK_WEIGHTS["注册表持久化"]
    assert event.factor == "注册表持久化"

    # diff 完成后基线已重置为当前快照 → 立即二次 diff 不追加新事件
    runner._diff_registry(session)
    assert len([e for e in session.report.events if e.kind == "registry"]) == len(first)
