"""测试模块：destroy 残余风险收口的三条路径（2026-09-17 P0 destroy 修复）。

被测点（``src/winreverse/forensics/behavior.py``）：
1. **kill 后仍存活 → 再 kill 一轮并再次等待**；最后一轮仍存活则登记
   ``session.survivor_pids`` 并 ERROR 记日志（不静默放行）；
2. **rmtree 重试前先重杀存活进程**（``_reap_survivors``）——若失败根因是进程未死，
   单纯 sleep 重试只是空转；
3. **样本以中立 cwd 启动**（``session_dir`` 而非被删除的沙箱副本目录）——
   本条在 ``test_behavior_destroy_neutral_cwd.py`` 里用真实进程验证。

本文件用 psutil 替身（不进程、不落盘到真实样本）覆盖上面的分支与容错路径：
NoSuchProcess/AccessDenied 跳过、多轮升级、survivor 登记/清空、rmtree 重试/FileNotFound。
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any

import psutil
import pytest

from winreverse.forensics import behavior
from winreverse.forensics.behavior import BehaviorError, ProcessIsolationRunner, _Session


class _FakeProc:
    """最小 psutil.Process 替身（只实现 destroy 路径用到的方法）。"""

    def __init__(
        self,
        pid: int,
        *,
        die_on_terminate: bool = False,
        die_after_kills: int | None = None,
        raise_on_kill: bool = False,
        children: tuple[_FakeProc, ...] = (),
    ) -> None:
        self.pid = pid
        self.dead = False
        self.terminate_calls = 0
        self.kill_calls = 0
        self._die_on_terminate = die_on_terminate
        self._die_after_kills = die_after_kills
        self._raise_on_kill = raise_on_kill
        self._children = list(children)

    def children(self, recursive: bool = True) -> list[_FakeProc]:
        return list(self._children)

    def terminate(self) -> None:
        self.terminate_calls += 1
        if self._die_on_terminate:
            self.dead = True

    def kill(self) -> None:
        self.kill_calls += 1
        if self._raise_on_kill:
            raise psutil.NoSuchProcess(self.pid)
        if self._die_after_kills is not None and self.kill_calls >= self._die_after_kills:
            self.dead = True

    def is_running(self) -> bool:
        return not self.dead


class _FakePsutil:
    """psutil 命名空间替身：只解析预先登记的 pid，其余视为已退出。"""

    def __init__(self, procs: dict[int, _FakeProc]) -> None:
        self._procs = procs
        self.NoSuchProcess = psutil.NoSuchProcess
        self.AccessDenied = psutil.AccessDenied
        self.ZombieProcess = psutil.ZombieProcess
        self.STATUS_ZOMBIE = psutil.STATUS_ZOMBIE

    def Process(self, pid: int) -> _FakeProc:
        proc = self._procs.get(pid)
        if proc is None:
            raise psutil.NoSuchProcess(pid)
        return proc

    @staticmethod
    def wait_procs(
        procs: list[_FakeProc], timeout: float | None = None
    ) -> tuple[list[_FakeProc], list[_FakeProc]]:
        _ = timeout
        gone = [p for p in procs if p.dead]
        alive = [p for p in procs if not p.dead]
        return gone, alive


def _session(tmp_path: Path) -> _Session:
    """构造最小会话（沙箱副本目录真实存在，便于 rmtree 断言）。"""
    session_dir = tmp_path / "sessions" / "bhv_test_destroy"
    sandbox = session_dir / "sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    isolated = sandbox / "sample.bat"
    isolated.write_text("@echo off\r\nexit /b 0\r\n", encoding="ascii")
    return _Session(
        session_id="bhv_test_destroy",
        sample_path=tmp_path / "sample.bat",
        isolated_path=isolated,
        session_dir=session_dir,
        watch_dirs=[session_dir],
        registry_keys=[],
    )


def _runner() -> ProcessIsolationRunner:
    """无退避等待的 runner（测试内把重试间隔/等待压到 0）。"""
    runner = ProcessIsolationRunner()
    runner._destroy_wait_timeout = 0.0
    runner._destroy_kill_timeout = 0.0
    runner._destroy_rmtree_interval = 0.0
    return runner


LOGGER = "winreverse.forensics.behavior"


# ---------------------------------------------------------------------------
# 1) kill 升级路径
# ---------------------------------------------------------------------------


class TestTerminateEscalation:
    """kill 后仍存活 → 再 kill 一轮；仍存活 → 登记 survivor 并 ERROR 记日志。"""

    def test_persistent_process_is_re_killed_and_registered(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        proc = _FakeProc(1001, die_on_terminate=False, die_after_kills=None)
        monkeypatch.setattr(behavior, "psutil", _FakePsutil({1001: proc}))
        session = _session(tmp_path)
        session.sample_pids.add(1001)

        with caplog.at_level(logging.WARNING, logger=LOGGER):
            _runner()._terminate_sample_tree(session)

        assert proc.terminate_calls == 1
        assert proc.kill_calls == 2, "第一轮 kill + 最后一轮重新 kill"
        assert session.sample_pids == set()
        assert session.survivor_pids == {1001}
        assert "仍存活" in caplog.text and "重新 kill" in caplog.text
        assert "最终仍存活" in caplog.text, "最后一轮仍存活必须记 ERROR（不静默）"

    def test_process_dying_on_second_kill_is_not_registered(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        proc = _FakeProc(1002, die_after_kills=2)
        monkeypatch.setattr(behavior, "psutil", _FakePsutil({1002: proc}))
        session = _session(tmp_path)
        session.sample_pids.add(1002)

        with caplog.at_level(logging.WARNING, logger=LOGGER):
            _runner()._terminate_sample_tree(session)

        assert proc.kill_calls == 2
        assert session.survivor_pids == set(), "重新 kill 后已退出 → 不登记 survivor"
        assert "最终仍存活" not in caplog.text

    def test_process_dying_on_terminate_needs_no_kill(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = _FakeProc(1003, die_on_terminate=True)
        monkeypatch.setattr(behavior, "psutil", _FakePsutil({1003: proc}))
        session = _session(tmp_path)
        session.sample_pids.add(1003)

        _runner()._terminate_sample_tree(session)

        assert proc.terminate_calls == 1
        assert proc.kill_calls == 0, "terminate 已退出 → 无需 kill 升级"
        assert session.survivor_pids == set()

    def test_children_are_terminated_too(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        child = _FakeProc(2002, die_on_terminate=True)
        parent = _FakeProc(2001, die_on_terminate=True, children=(child,))
        monkeypatch.setattr(behavior, "psutil", _FakePsutil({2001: parent}))
        session = _session(tmp_path)
        session.sample_pids.add(2001)

        _runner()._terminate_sample_tree(session)

        assert parent.terminate_calls == 1
        assert child.terminate_calls == 1, "子进程必须在终止范围内"

    def test_vanished_pid_is_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(behavior, "psutil", _FakePsutil({}))
        session = _session(tmp_path)
        session.sample_pids.add(9999)

        _runner()._terminate_sample_tree(session)

        assert session.sample_pids == set()
        assert session.survivor_pids == set()

    def test_no_sample_pids_returns_early(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(behavior, "psutil", _FakePsutil({}))
        session = _session(tmp_path)

        _runner()._terminate_sample_tree(session)

        assert session.survivor_pids == set()

    def test_kill_raising_nosuchprocess_is_tolerated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """kill 抛 NoSuchProcess（进程恰好自退）→ 两处 kill 循环都容错跳过，不冒泡。"""
        proc = _FakeProc(1004, raise_on_kill=True)
        monkeypatch.setattr(behavior, "psutil", _FakePsutil({1004: proc}))
        session = _session(tmp_path)
        session.sample_pids.add(1004)

        with caplog.at_level(logging.WARNING, logger=LOGGER):
            _runner()._terminate_sample_tree(session)

        assert proc.kill_calls == 2, "两轮 kill 各调用一次（异常被容错）"
        assert session.survivor_pids == {1004}, "wait 仍报存活 → 登记 survivor"


# ---------------------------------------------------------------------------
# 2) rmtree 重试前的重杀
# ---------------------------------------------------------------------------


class TestReapSurvivors:
    """``_reap_survivors``：重试前再 kill 一次，并更新 survivor 集合。"""

    def test_no_survivors_returns_immediately(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(behavior, "psutil", _FakePsutil({}))
        session = _session(tmp_path)

        _runner()._reap_survivors(session)

        assert session.survivor_pids == set()

    def test_survivor_dies_on_reap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        proc = _FakeProc(3001, die_after_kills=1)
        monkeypatch.setattr(behavior, "psutil", _FakePsutil({3001: proc}))
        session = _session(tmp_path)
        session.survivor_pids = {3001}

        with caplog.at_level(logging.WARNING, logger=LOGGER):
            _runner()._reap_survivors(session)

        assert proc.kill_calls == 1
        assert session.survivor_pids == set()
        assert "rmtree 重试前重杀存活进程" in caplog.text

    def test_survivor_kept_when_still_alive(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = _FakeProc(3002, die_after_kills=None)
        monkeypatch.setattr(behavior, "psutil", _FakePsutil({3002: proc}))
        session = _session(tmp_path)
        session.survivor_pids = {3002}

        _runner()._reap_survivors(session)

        assert session.survivor_pids == {3002}

    def test_vanished_survivor_is_dropped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(behavior, "psutil", _FakePsutil({}))
        session = _session(tmp_path)
        session.survivor_pids = {3003}

        _runner()._reap_survivors(session)

        assert session.survivor_pids == set()


class TestRemoveIsolatedCopyRetry:
    """``_remove_isolated_copy``：每次重试前先重杀，兜底不静默。"""

    def test_success_on_first_attempt_does_not_reap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = _session(tmp_path)
        reap_calls: list[int] = []
        monkeypatch.setattr(session, "survivor_pids", {4001}, raising=False)
        runner = _runner()
        monkeypatch.setattr(
            runner, "_reap_survivors", lambda s: reap_calls.append(1), raising=False
        )

        runner._remove_isolated_copy(session)

        assert not (session.isolated_path.parent).exists()
        assert reap_calls == [], "一次成功不需要重杀"

    def test_retry_reaps_before_each_attempt(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = _session(tmp_path)
        attempts: list[Path] = []
        reap_calls: list[int] = []
        real_rmtree = shutil.rmtree

        def _flaky_rmtree(target: Any, *args: Any, **kwargs: Any) -> None:
            attempts.append(Path(target))
            if len(attempts) < 3:
                raise OSError(32, "The process cannot access the file (模拟句柄占用)")
            real_rmtree(target, *args, **kwargs)

        monkeypatch.setattr(behavior.shutil, "rmtree", _flaky_rmtree)
        runner = _runner()
        monkeypatch.setattr(
            runner, "_reap_survivors", lambda s: reap_calls.append(1), raising=False
        )

        runner._remove_isolated_copy(session)

        assert len(attempts) == 3
        assert len(reap_calls) == 2, "第 2、3 次尝试前各重杀一次（失败后不空转）"
        assert not session.isolated_path.parent.exists()

    def test_missing_dir_is_tolerated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = _session(tmp_path)
        shutil.rmtree(session.isolated_path.parent)
        runner = _runner()

        runner._remove_isolated_copy(session)  # 不抛

    def test_exhausted_retries_raise_behavior_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = _session(tmp_path)
        runner = _runner()
        runner._destroy_rmtree_retries = 2
        monkeypatch.setattr(
            behavior.shutil,
            "rmtree",
            lambda *a, **k: (_ for _ in ()).throw(OSError(32, "占用中")),
        )

        with pytest.raises(BehaviorError, match="沙箱副本删除失败"):
            runner._remove_isolated_copy(session)


# ---------------------------------------------------------------------------
# 3) destroy 全链路（含 survivor 收口）
# ---------------------------------------------------------------------------


class TestDestroyIntegration:
    """``destroy`` 串起 terminate → remove；survivor 路径下仍删除副本并保留报告。"""

    def test_destroy_registers_survivor_and_still_removes_copy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        proc = _FakeProc(5001, die_after_kills=None)
        monkeypatch.setattr(behavior, "psutil", _FakePsutil({5001: proc}))
        runner = _runner()
        session = _session(tmp_path)
        (session.session_dir / "behavior_report.json").write_text("{}", encoding="utf-8")
        runner._sessions[session.session_id] = session
        session.sample_pids.add(5001)

        with caplog.at_level(logging.ERROR, logger=LOGGER):
            runner.destroy(session.session_id)

        assert not (session.session_dir / "sandbox").exists(), "沙箱副本必须删除"
        assert (session.session_dir / "behavior_report.json").is_file(), "行为报告保留"
        assert session.survivor_pids == {5001}
        assert "最终仍存活" in caplog.text
        assert session.session_id not in runner._sessions, "会话已注销"

    def test_destroy_cleans_up_and_deregisters_on_clean_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = _FakeProc(5002, die_on_terminate=True)
        monkeypatch.setattr(behavior, "psutil", _FakePsutil({5002: proc}))
        runner = _runner()
        session = _session(tmp_path)
        runner._sessions[session.session_id] = session
        session.sample_pids.add(5002)

        runner.destroy(session.session_id)

        assert not (session.session_dir / "sandbox").exists()
        assert session.survivor_pids == set()
        with pytest.raises(BehaviorError, match="会话不存在"):
            runner.destroy(session.session_id)
