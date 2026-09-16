"""被测模块: winreverse.forensics.behavior（样本退出后进程树归档回退）。

覆盖点（2026-09-15 真机 Windows 实测暴露的缺陷回归锁）：

真机现象：样本（.cmd）先把子进程拉起、随后自身与子进程在监控结束前退出，
`behavior.monitor` 的报告里 `process_tree` 为 **空列表**，而 `events` 中
3 条 `kind="process"` 事件明明带着 pid/ppid/name/cmdline。

根因：`_score_and_extract` 只用收尾时刻的**实时快照**（`_snapshot_processes`）
按 `session.sample_pids` 反查；pid 已消失 → 整棵进程树丢失（取证证据缺口）。

修复口径：启动瞬间归档样本自身进程信息、检测到子进程时归档子进程信息，
收尾时"实时快照优先 + 归档回退"。

本模块经 memanalysis_api 传递依赖 yara（Windows 运行时专有）→ Linux 上如实
报 collection error（基线接受态，与同目录既有 test_behavior*.py 一致）。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import psutil
import pytest

import winreverse.forensics.behavior as behavior_module
from winreverse.forensics.behavior import (
    BehaviorReport,
    ProcessIsolationRunner,
    _process_info,
    _Session,
)


def _make_session(tmp_path: Path) -> _Session:
    """构造最小可用会话（不含真实进程）。"""
    return _Session(
        session_id="bhv_test",
        sample_path=tmp_path / "sample.cmd",
        isolated_path=tmp_path / "sess" / "sandbox" / "sample.cmd",
        session_dir=tmp_path / "sess",
        watch_dirs=[tmp_path / "sess" / "sandbox"],
        registry_keys=[],
    )


def _runner(tmp_path: Path) -> ProcessIsolationRunner:
    return ProcessIsolationRunner(sessions_root=tmp_path / "sessions")


class TestProcessInfoHelper:
    """`_process_info`：单进程四要素取出与容错。"""

    def test_returns_four_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeProc:
            def oneshot(self) -> Any:
                import contextlib

                return contextlib.nullcontext()

            def ppid(self) -> int:
                return 4

            def name(self) -> str:
                return "evil.exe"

            def cmdline(self) -> list[str]:
                return ["evil.exe", "-go"]

            def create_time(self) -> float:
                return 123.0

        monkeypatch.setattr(behavior_module.psutil, "Process", lambda _pid: FakeProc())
        info = _process_info(4242)
        assert info == {
            "ppid": 4,
            "name": "evil.exe",
            "cmdline": "evil.exe -go",
            "create_time": 123.0,
        }

    def test_returns_none_when_vanished(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def gone(pid: int) -> Any:
            raise psutil.NoSuchProcess(pid=pid)

        monkeypatch.setattr(behavior_module.psutil, "Process", gone)
        assert _process_info(999999) is None

    def test_returns_none_when_denied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def denied(pid: int) -> Any:
            raise psutil.AccessDenied(pid=pid)

        monkeypatch.setattr(behavior_module.psutil, "Process", denied)
        assert _process_info(4) is None


class TestProcessTreeArchive:
    """样本树进程归档回退（真机缺陷回归锁）。"""

    def test_archive_used_when_sample_exited(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """实时快照已空（样本退出）→ 仍须从归档重建进程树。"""
        session = _make_session(tmp_path)
        session.report = BehaviorReport(session_id="bhv_test", sample="sample.cmd")
        session.sample_pids = {4242}
        session.sample_process_info = {
            4242: {
                "ppid": 4,
                "name": "cmd.exe",
                "cmdline": "cmd.exe /c sample.cmd",
                "create_time": 1.0,
            }
        }
        monkeypatch.setattr(behavior_module, "_snapshot_processes", dict)

        _runner(tmp_path)._score_and_extract(session)

        assert [p["pid"] for p in session.report.process_tree] == [4242]
        assert session.report.process_tree[0]["name"] == "cmd.exe"
        assert session.report.process_tree[0]["cmdline"] == "cmd.exe /c sample.cmd"

    def test_live_snapshot_wins_over_archive(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """进程仍存活时以实时快照为准（归档只作回退）。"""
        session = _make_session(tmp_path)
        session.report = BehaviorReport(session_id="bhv_test", sample="sample.cmd")
        session.sample_pids = {4242}
        session.sample_process_info = {
            4242: {"ppid": 4, "name": "stale.exe", "cmdline": "stale", "create_time": 1.0}
        }
        live = {4242: {"ppid": 4, "name": "live.exe", "cmdline": "live", "create_time": 2.0}}
        monkeypatch.setattr(behavior_module, "_snapshot_processes", lambda: live)

        _runner(tmp_path)._score_and_extract(session)

        assert session.report.process_tree[0]["name"] == "live.exe"

    def test_empty_when_no_archive_and_no_live(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """无归档且无实时数据 → 维持空进程树（不凭空编造）。"""
        session = _make_session(tmp_path)
        session.report = BehaviorReport(session_id="bhv_test", sample="sample.cmd")
        session.sample_pids = {4242}
        monkeypatch.setattr(behavior_module, "_snapshot_processes", dict)

        _runner(tmp_path)._score_and_extract(session)

        assert session.report.process_tree == []

    def test_diff_processes_archives_child(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """检测到样本树子进程时同步写入归档（供收尾回退）。"""
        session = _make_session(tmp_path)
        session.report = BehaviorReport(session_id="bhv_test", sample="sample.cmd")
        session.sample_pids = {100}
        current = {
            200: {
                "ppid": 100,
                "name": "PING.EXE",
                "cmdline": "ping -n 8 127.0.0.1",
                "create_time": 3.0,
            }
        }
        monkeypatch.setattr(behavior_module, "_snapshot_processes", lambda: current)

        _runner(tmp_path)._diff_processes(session)

        assert session.sample_process_info[200]["name"] == "PING.EXE"
        assert session.sample_process_info[200]["cmdline"] == "ping -n 8 127.0.0.1"
        assert "pid" not in session.sample_process_info[200]
        assert any(e.kind == "process" for e in session.report.events)
        assert session.sample_pids == {100, 200}

    def test_archived_child_survives_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """子进程被归档后即便随样本一起退出，进程树仍完整。"""
        session = _make_session(tmp_path)
        session.report = BehaviorReport(session_id="bhv_test", sample="sample.cmd")
        session.sample_pids = {100}
        # run() 在启动瞬间归档样本自身进程信息（此处等价模拟）
        session.sample_process_info = {
            100: {
                "ppid": 4,
                "name": "cmd.exe",
                "cmdline": "cmd.exe /c sample.cmd",
                "create_time": 1.0,
            }
        }
        monkeypatch.setattr(
            behavior_module,
            "_snapshot_processes",
            lambda: {
                200: {
                    "ppid": 100,
                    "name": "PING.EXE",
                    "cmdline": "ping -n 8 127.0.0.1",
                    "create_time": 3.0,
                }
            },
        )
        runner = _runner(tmp_path)
        runner._diff_processes(session)

        # 收尾时刻父子进程均已退出 → 实时快照为空
        monkeypatch.setattr(behavior_module, "_snapshot_processes", dict)
        runner._score_and_extract(session)

        names = [p["name"] for p in session.report.process_tree]
        assert "PING.EXE" in names
        assert [p["pid"] for p in session.report.process_tree] == [100, 200]
