"""测试模块：winreverse.forensics.behavior（destroy 终止循环的逐进程容错）。

覆盖点：terminate 抛 NoSuchProcess/AccessDenied 只跳过自身不中止整树终止
（P1 建议的替身注入弧——既有 destroy 测试替身的 terminate 从不抛异常）、
建树阶段 AccessDenied 与 children() 枚举失败按 pid 跳过、_reap_survivors
的 kill 容错与 survivor 追踪收敛。

口径：behavior 经 memanalysis_api → yara_api 拉入 Windows 专有依赖 yara，
缺依赖的 Linux 上如实报 collection error＝基线接受态，待 Windows 实机依赖
就位后实跑回填（与既有 test_behavior_destroy_escalation.py 同链同口径，
禁加平台守卫）。
"""

from __future__ import annotations

import logging
from pathlib import Path

import psutil
import pytest

from winreverse.forensics import behavior
from winreverse.forensics.behavior import ProcessIsolationRunner, _Session


class _FakeProc:
    """最小 psutil.Process 替身：terminate/kill/children 可注入真实 psutil 异常。"""

    def __init__(
        self,
        pid: int,
        *,
        raise_on_terminate: Exception | None = None,
        die_on_terminate: bool = False,
        raise_on_kill: Exception | None = None,
        die_after_kills: int | None = None,
        raise_on_children: Exception | None = None,
        children: tuple[_FakeProc, ...] = (),
    ) -> None:
        self.pid = pid
        self.dead = False
        self.terminate_calls = 0
        self.kill_calls = 0
        self._raise_on_terminate = raise_on_terminate
        self._die_on_terminate = die_on_terminate
        self._raise_on_kill = raise_on_kill
        self._die_after_kills = die_after_kills
        self._raise_on_children = raise_on_children
        self._children = list(children)

    def children(self, recursive: bool = True) -> list[_FakeProc]:
        if self._raise_on_children is not None:
            raise self._raise_on_children
        return list(self._children)

    def terminate(self) -> None:
        self.terminate_calls += 1
        if self._raise_on_terminate is not None:
            # 抛 NoSuchProcess 语义上意味着进程已消失 → wait_procs 视为已退出
            if isinstance(self._raise_on_terminate, psutil.NoSuchProcess):
                self.dead = True
            raise self._raise_on_terminate
        if self._die_on_terminate:
            self.dead = True

    def kill(self) -> None:
        self.kill_calls += 1
        if self._raise_on_kill is not None:
            if isinstance(self._raise_on_kill, psutil.NoSuchProcess):
                self.dead = True
            raise self._raise_on_kill
        if self._die_after_kills is not None and self.kill_calls >= self._die_after_kills:
            self.dead = True

    def is_running(self) -> bool:
        return not self.dead


class _FakePsutil:
    """psutil 命名空间替身：Process 可注入 AccessDenied，wait_procs 按 dead 分组。"""

    def __init__(
        self,
        procs: dict[int, _FakeProc] | None = None,
        denied_pids: set[int] | None = None,
    ) -> None:
        self._procs = procs or {}
        self._denied = denied_pids or set()
        self.NoSuchProcess = psutil.NoSuchProcess
        self.AccessDenied = psutil.AccessDenied
        self.ZombieProcess = psutil.ZombieProcess

    def Process(self, pid: int) -> _FakeProc:
        if pid in self._denied:
            raise psutil.AccessDenied(pid)
        proc = self._procs.get(pid)
        if proc is None:
            raise psutil.NoSuchProcess(pid)
        return proc

    @staticmethod
    def wait_procs(
        procs: list[_FakeProc], timeout: float | None = None
    ) -> tuple[list[_FakeProc], list[_FakeProc]]:
        _ = timeout
        return [p for p in procs if p.dead], [p for p in procs if not p.dead]


def _session(tmp_path: Path) -> _Session:
    """构造最小会话（沙箱副本目录真实存在，便于 destroy 路径复用）。"""
    session_dir = tmp_path / "sessions" / "bhv_test_tolerance"
    sandbox = session_dir / "sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    isolated = sandbox / "sample.bat"
    isolated.write_text("@echo off\r\nexit /b 0\r\n", encoding="ascii")
    return _Session(
        session_id="bhv_test_tolerance",
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


class TestTerminateLoopTolerance:
    """terminate 循环：单进程异常只跳过自身，不中止整树终止。"""

    def test_terminate_nosuchprocess_skipped_and_child_still_terminated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """根进程 terminate 时已自退（NoSuchProcess）→ 跳过但子进程照常收到 terminate。"""
        child = _FakeProc(2002, die_on_terminate=True)
        parent = _FakeProc(2001, raise_on_terminate=psutil.NoSuchProcess(2001), children=(child,))
        monkeypatch.setattr(behavior, "psutil", _FakePsutil({2001: parent}))
        session = _session(tmp_path)
        session.sample_pids.add(2001)

        _runner()._terminate_sample_tree(session)

        assert parent.terminate_calls == 1
        assert child.terminate_calls == 1, "父进程异常必须 continue 而非中止整树终止"
        assert parent.kill_calls == 0
        assert child.kill_calls == 0
        assert session.survivor_pids == set()
        assert session.sample_pids == set()

    def test_terminate_access_denied_escalates_to_kill(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """terminate 抛 AccessDenied（权限不足）→ 该进程照常进入 kill 升级链。"""
        proc = _FakeProc(1005, raise_on_terminate=psutil.AccessDenied(1005), die_after_kills=1)
        monkeypatch.setattr(behavior, "psutil", _FakePsutil({1005: proc}))
        session = _session(tmp_path)
        session.sample_pids.add(1005)

        _runner()._terminate_sample_tree(session)

        assert proc.terminate_calls == 1
        assert proc.kill_calls == 1, "terminate 失败不绕过 kill 升级"
        assert session.survivor_pids == set(), "kill 后已退出 → 不登记 survivor"


class TestTreeLookupTolerance:
    """建树阶段：查找/枚举异常按 pid 跳过，不影响其余 pid 入列。"""

    def test_process_lookup_access_denied_is_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """psutil.Process 抛 AccessDenied（非 NoSuchProcess）同样被容错跳过。"""
        monkeypatch.setattr(behavior, "psutil", _FakePsutil(denied_pids={1006}))
        session = _session(tmp_path)
        session.sample_pids.add(1006)

        _runner()._terminate_sample_tree(session)

        assert session.sample_pids == set()
        assert session.survivor_pids == set()

    def test_children_enumeration_failure_skips_only_that_pid(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """children() 枚举失败的 pid 不入终止列表，同批其他 pid 不受影响。"""
        broken = _FakeProc(1007, raise_on_children=psutil.NoSuchProcess(1007))
        healthy = _FakeProc(1008, die_on_terminate=True)
        monkeypatch.setattr(behavior, "psutil", _FakePsutil({1007: broken, 1008: healthy}))
        session = _session(tmp_path)
        session.sample_pids |= {1007, 1008}

        _runner()._terminate_sample_tree(session)

        assert broken.terminate_calls == 0, "枚举失败的 pid 整体跳过（未入终止列表）"
        assert healthy.terminate_calls == 1
        assert session.sample_pids == set()


class TestReapSurvivorsTolerance:
    """``_reap_survivors`` 的 kill 容错与 survivor 追踪收敛。"""

    def test_kill_nosuchprocess_drops_survivor(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """kill 抛 NoSuchProcess＝进程已消失 → 容错并从 survivor 追踪剔除。"""
        proc = _FakeProc(3001, raise_on_kill=psutil.NoSuchProcess(3001))
        monkeypatch.setattr(behavior, "psutil", _FakePsutil({3001: proc}))
        session = _session(tmp_path)
        session.survivor_pids = {3001}

        with caplog.at_level(logging.WARNING, logger=LOGGER):
            _runner()._reap_survivors(session)

        assert proc.kill_calls == 1
        assert session.survivor_pids == set()
        assert "rmtree 重试前重杀存活进程" in caplog.text

    def test_kill_access_denied_also_drops_tracking(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """kill 抛 AccessDenied → 容错不冒泡；异常分支先于 wait 直接跳过该 pid。

        钉扎当前契约：kill 被拒的 pid 同样被剔出重杀追踪（except continue
        短路了 wait/add），进程可能仍存活但不再重试——若未来改为保留追踪，
        本用例会刻意失败以提示契约变更。
        """
        proc = _FakeProc(3002, raise_on_kill=psutil.AccessDenied(3002))
        monkeypatch.setattr(behavior, "psutil", _FakePsutil({3002: proc}))
        session = _session(tmp_path)
        session.survivor_pids = {3002}

        _runner()._reap_survivors(session)

        assert proc.kill_calls == 1
        assert session.survivor_pids == set(), "当前契约：kill 异常的 pid 剔出重杀追踪"
