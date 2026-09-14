"""被测模块: winreverse.forensics.behavior（进程隔离行为监控）。

覆盖点: 快照容错（进程消失/网络拒绝/目录缺失/stat 竞态）、风险因子、
注册表与网络 diff、启动器命令构造、样本启动失败包装、评分口径。
本模块经 memanalysis_api 传递依赖 yara（Windows 运行时专有）→ Linux
如实报 collection error（基线接受态），用例直连 import，待 Windows
实机（依赖就位）实跑回填。
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import psutil
import pytest

import winreverse.forensics.behavior as behavior_module
from winreverse.forensics.behavior import (
    BehaviorError,
    BehaviorReport,
    ProcessIsolationRunner,
    _file_factor,
    _launcher_command,
    _registry_diff,
    _sample_tree_connections,
    _Session,
    _snapshot_connections,
    _snapshot_dir,
    _snapshot_processes,
)

# =============================================================================
# 快照容错路径
# =============================================================================


class TestSnapshotTolerance:
    """快照函数对消失进程 / 拒绝访问 / 竞态的容错。"""

    def test_process_snapshot_skips_vanished(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class VanishedProc:
            @property
            def info(self) -> dict[str, Any]:
                raise psutil.NoSuchProcess(pid=7)

        good = SimpleNamespace(
            info={
                "pid": 4,
                "ppid": 0,
                "name": "evil.exe",
                "cmdline": ["evil.exe", "-go"],
                "create_time": 123.0,
            }
        )
        monkeypatch.setattr(
            behavior_module.psutil, "process_iter", lambda _attrs: [good, VanishedProc()]
        )
        snapshot = _snapshot_processes()
        assert set(snapshot) == {4}
        assert snapshot[4]["name"] == "evil.exe"
        assert snapshot[4]["cmdline"] == "evil.exe -go"

    def test_connection_snapshot_denied_returns_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def denied(kind: str) -> list[Any]:
            raise psutil.AccessDenied(pid=0)

        monkeypatch.setattr(behavior_module.psutil, "net_connections", denied)
        assert _snapshot_connections() == set()

    def test_dir_snapshot_missing_dir_returns_empty(self, tmp_path: Path) -> None:
        assert _snapshot_dir(tmp_path / "no_such_dir") == {}

    def test_dir_snapshot_skips_stat_oserror(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """模拟列表后 stat 前文件消失的竞态：该文件被跳过，其余照常。"""
        original_stat = Path.stat
        original_is_file = Path.is_file

        def fake_stat(self: Path, **kwargs: Any) -> object:
            if self.name == "ghost.txt":
                raise OSError(2, "stale listing")
            return original_stat(self, **kwargs)

        def fake_is_file(self: Path) -> bool:
            return self.name == "ghost.txt" or original_is_file(self)

        monkeypatch.setattr(Path, "stat", fake_stat)
        monkeypatch.setattr(Path, "is_file", fake_is_file)

        watch = tmp_path / "watch"
        watch.mkdir()
        (watch / "keep.txt").write_text("x", encoding="utf-8")
        snapshot = _snapshot_dir(watch)
        assert set(snapshot) == {"keep.txt"}


# =============================================================================
# 纯函数：风险因子 / 注册表 diff / 启动器命令
# =============================================================================


class TestPureHelpers:
    def test_file_factor_executable_vs_plain(self) -> None:
        assert _file_factor("payload.EXE") == "释放可执行文件"
        assert _file_factor("sub/dir/run.ps1") == "释放可执行文件"
        assert _file_factor("notes.txt") == "写入监控目录"

    def test_registry_diff_detects_new_and_ignores_same(self) -> None:
        label = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        before = {label: {"auto_run": "1"}}
        after_same = {label: {"auto_run": "1"}}
        after_new = {label: {"auto_run": "1", "evil": "C:\\x.exe"}}
        assert _registry_diff(before, after_same) == []
        assert _registry_diff(before, after_new) == [(label, "evil", "C:\\x.exe")]

    def test_launcher_command_by_suffix(self, tmp_path: Path) -> None:
        bat = tmp_path / "s.bat"
        ps1 = tmp_path / "s.ps1"
        exe = tmp_path / "s.txt"
        for f in (bat, ps1, exe):
            f.write_text("x", encoding="utf-8")
        assert _launcher_command(bat) == ["cmd.exe", "/c", str(bat.resolve())]
        ps1_cmd = _launcher_command(ps1)
        assert ps1_cmd[0] == "powershell.exe"
        assert ps1_cmd[-1] == str(ps1.resolve())
        assert _launcher_command(exe) == [str(exe.resolve())]


# =============================================================================
# 样本树连接采集
# =============================================================================


class TestSampleTreeConnections:
    def test_filters_loopback_and_dead_pid(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeProcess:
            def __init__(self, pid: int) -> None:
                if pid == 999:
                    raise psutil.NoSuchProcess(pid)

            def net_connections(self, kind: str) -> list[Any]:
                return [
                    SimpleNamespace(raddr=SimpleNamespace(ip="8.8.8.8", port=53)),
                    SimpleNamespace(raddr=SimpleNamespace(ip="127.0.0.1", port=1900)),
                    SimpleNamespace(raddr=None),
                ]

        monkeypatch.setattr(behavior_module.psutil, "Process", FakeProcess)
        endpoints = _sample_tree_connections({4, 999})
        assert endpoints == {"8.8.8.8:53"}


# =============================================================================
# diff 编排与评分（直接构造 _Session）
# =============================================================================


def _make_session(tmp_path: Path, watch: Path | None = None) -> _Session:
    return _Session(
        session_id="s1",
        sample_path=tmp_path / "sample.exe",
        isolated_path=tmp_path / "session" / "sample.exe",
        session_dir=tmp_path / "session",
        watch_dirs=[watch] if watch else [],
        registry_keys=[],
    )


class TestDiffOrchestration:
    def test_diff_network_emits_event_and_dedups_outbound(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = _make_session(tmp_path)
        session.report = BehaviorReport(session_id="s1", sample="sample.exe")
        monkeypatch.setattr(
            behavior_module, "_snapshot_connections", lambda: {"9.9.9.9:53"}
        )
        monkeypatch.setattr(
            behavior_module,
            "_sample_tree_connections",
            lambda pids: {"5.6.7.8:443"},
        )
        runner = ProcessIsolationRunner(sessions_root=tmp_path / "sess")

        runner._diff_network(session)
        assert session.baseline_connections == {"9.9.9.9:53"}
        runner._diff_network(session)

        assert len(session.report.events) == 2
        first = session.report.events[0]
        assert first.kind == "network"
        assert first.risk == 20
        assert first.factor == "外联网络"
        assert first.detail == {"remote": "5.6.7.8:443"}
        assert session.report.outbound_connections == ["5.6.7.8:443"]

    def test_diff_files_records_dropped_and_factors(self, tmp_path: Path) -> None:
        watch = tmp_path / "watch"
        watch.mkdir()
        session = _make_session(tmp_path, watch=watch)
        session.report = BehaviorReport(session_id="s1", sample="sample.exe")
        (watch / "dropped.dll").write_text("MZ", encoding="utf-8")
        (watch / "notes.txt").write_text("hi", encoding="utf-8")
        runner = ProcessIsolationRunner(sessions_root=tmp_path / "sess")

        runner._diff_files(session)
        factors = {e.factor: e.risk for e in session.report.events}
        assert factors == {"释放可执行文件": 20, "写入监控目录": 5}
        assert session.report.dropped_files == ["dropped.dll", "notes.txt"]

        runner._diff_files(session)
        assert len(session.report.events) == 2

    def test_score_skips_zero_risk_and_dedups_factors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from winreverse.forensics.behavior import BehaviorEvent

        session = _make_session(tmp_path)
        session.report = BehaviorReport(session_id="s1", sample="sample.exe")
        session.report.events = [
            BehaviorEvent(timestamp="t", kind="info", detail={}, risk=0),
            BehaviorEvent(timestamp="t", kind="network", detail={}, risk=20, factor="外联网络"),
            BehaviorEvent(timestamp="t", kind="network", detail={}, risk=20, factor="外联网络"),
        ]
        session.sample_pids = {4}
        monkeypatch.setattr(behavior_module, "_snapshot_processes", lambda: {})
        runner = ProcessIsolationRunner(sessions_root=tmp_path / "sess")

        runner._score_and_extract(session)
        assert session.report.risk_score == 40
        assert session.report.risk_factors == ["外联网络"]
        assert session.report.process_tree == []


# =============================================================================
# 样本启动失败包装
# =============================================================================


class TestRunStartFailure:
    def test_popen_oserror_wrapped_as_behavior_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ")
        runner = ProcessIsolationRunner(sessions_root=tmp_path / "sess")
        session_id = runner.prepare(str(sample), {})

        def refused(*_args: object, **_kwargs: object) -> None:
            raise OSError("spawn denied")

        monkeypatch.setattr(behavior_module.subprocess, "Popen", refused)
        with pytest.raises(BehaviorError, match=r"样本启动失败.*spawn denied"):
            runner.run(session_id, duration=1)
