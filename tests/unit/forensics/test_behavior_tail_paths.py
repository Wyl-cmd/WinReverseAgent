"""被测模块: winreverse.forensics.behavior 收尾路径（真机 coverage 缺 9 行）。

覆盖点: _snapshot_dir 快照期间文件消失（stat OSError）跳过、
_default_registry_keys 非 Windows 回落空列表契约、run() 收尾
proc.poll() OSError 时 exit_code 回落 None。
258-259 / 651 两行为真机 winreg 运行时弧（需真实注册表值变更），登记不硬凑。
本机（Linux）因 yara 依赖链 collection error = 官方基线接受态；
直连 import，不加平台守卫（依 WINREVERSE_TASKS.md L5-L6）。
"""

from __future__ import annotations

from pathlib import Path

import pytest

import winreverse.forensics.behavior as behavior_module
from winreverse.forensics.behavior import (
    BehaviorError,
    ProcessIsolationRunner,
    _default_registry_keys,
    _snapshot_dir,
)


class _VanishingFile:
    """is_file 为真但 stat 抛 OSError 的替身（模拟快照竞态）。"""

    def is_file(self) -> bool:
        return True

    def stat(self):
        raise OSError("file vanished during walk")


class _VanishingDir:
    """rglob 产出一个会消失文件的替身目录。"""

    def is_dir(self) -> bool:
        return True

    def rglob(self, pattern: str):
        return [_VanishingFile()]


class TestSnapshotDirRace:
    def test_stat_oserror_skips_entry(self) -> None:
        """快照期间文件消失（stat OSError）时跳过该条目而不崩溃（220-221）。"""
        assert _snapshot_dir(_VanishingDir()) == {}  # type: ignore[arg-type]


class TestDefaultRegistryKeysContract:
    def test_non_windows_returns_empty_windows_returns_pairs(self) -> None:
        """双平台契约：非 Windows 回落空列表；Windows 返回 (hive, 子键) 二元组（269-270）。"""
        keys = _default_registry_keys()
        assert isinstance(keys, list)
        assert keys == [] or all(len(entry) == 2 for entry in keys)


class TestRunPollOSErrorFallback:
    def test_poll_oserror_sets_exit_code_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """样本收尾 poll() 抛 OSError 时报告 exit_code 回落 None 且不中断 run（508-509）。"""
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ")

        class _OSErrorPollProc:
            pid = 4242

            def poll(self) -> int:
                raise OSError("process handle invalid")

        runner = ProcessIsolationRunner(sessions_root=tmp_path / "sess")
        monkeypatch.setattr(behavior_module, "_snapshot_registry", lambda keys: {})
        monkeypatch.setattr(behavior_module, "_snapshot_processes", lambda: {})
        monkeypatch.setattr(behavior_module.subprocess, "Popen", lambda *a, **k: _OSErrorPollProc())
        monkeypatch.setattr(runner, "_poll_loop", lambda session, duration, started: None)

        session_id = runner.prepare(str(sample), {})
        summary = runner.run(session_id, duration=1)

        assert summary["session_id"] == session_id
        report = runner._require_session(session_id).report
        assert report is not None
        assert report.exit_code is None


class TestRunGuards:
    def test_run_unknown_session_raises(self, tmp_path: Path) -> None:
        """未知会话 ID 调 run 报 BehaviorError（守卫语义回归）。"""
        runner = ProcessIsolationRunner(sessions_root=tmp_path / "sess")
        with pytest.raises(BehaviorError, match="会话不存在"):
            runner.run("bhv_nope", duration=1)
