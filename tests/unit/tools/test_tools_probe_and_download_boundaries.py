# 被测模块：winreverse.tools.version_checker（WheelUpdater._get_installed_version）
#           + winreverse.tools.updater（ToolUpdater._download_with_retry）
# 覆盖点：version_checker.py:484-485 pip show 子进程异常容错；updater.py:658 retry_times=0 空循环回落
"""pip 版本探测子进程异常容错 + 零重试下载边界测试。"""

from __future__ import annotations

import subprocess

import pytest

from winreverse.tools import version_checker as vc_mod
from winreverse.tools.updater import ToolUpdater
from winreverse.tools.version_checker import WheelUpdater


class TestGetInstalledVersionSubprocessErrors:
    """pip show 子进程抛 SubprocessError/OSError 时必须容错返回 None 而非向外传播。"""

    def test_timeout_expired_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # pip 挂起触发超时：TimeoutExpired 是 SubprocessError 子类，命中 except 首分支
        def _boom(*args: object, **kwargs: object) -> None:
            raise subprocess.TimeoutExpired(cmd=["pip", "show", "x"], timeout=30)

        monkeypatch.setattr(vc_mod.subprocess, "run", _boom)
        assert WheelUpdater._get_installed_version("some-pkg") is None

    def test_oserror_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # 解释器/pip 缺失：FileNotFoundError 是 OSError 子类，命中 except 第二分支
        def _boom(*args: object, **kwargs: object) -> None:
            raise FileNotFoundError("python 不存在")

        monkeypatch.setattr(vc_mod.subprocess, "run", _boom)
        assert WheelUpdater._get_installed_version("some-pkg") is None


class TestDownloadWithRetryZeroBudget:
    """retry_times=0 是合法边界：range(1, 1) 为空，不发任何请求、不落盘，直接返回 None。"""

    def test_zero_retry_returns_none_without_io(self) -> None:
        # object.__new__ 跳过 __init__：retry_times=0 路径不触碰任何实例状态，
        # 用 .invalid 保留域名保证即使实现错误也只会因网络失败而非真实下载
        checker = object.__new__(ToolUpdater)
        result = checker._download_with_retry(
            "https://.invalid/winreverse-probe.zip",
            tool_name="probe-tool",
            retry_times=0,
            timeout=1,
        )
        assert result is None
