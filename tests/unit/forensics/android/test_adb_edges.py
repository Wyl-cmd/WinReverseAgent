"""测试模块：winreverse.forensics.android.adb 边界分支（独立新文件，不动既有用例）。

覆盖点：adb 路径解析回退、_run 三类失败（二进制缺失/超时/非零退出码）、
devices/ps 输出畸形行跳过、pull/push/install 前置校验、install -r 参数、
logcat 过滤参数、screenshot 失败、pair 参数校验、disconnect 两形态。
模块仅依赖 subprocess/shutil，平台无关，Linux 可直接实跑。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from winreverse.forensics.android import adb
from winreverse.forensics.android.adb import AdbClient, AdbError

_SERIAL = "emulator-5554"


def _make_client(monkeypatch: pytest.MonkeyPatch) -> AdbClient:
    """构造绕过磁盘解析的 AdbClient（adb 路径解析另行单测）。"""
    monkeypatch.setattr(
        AdbClient, "_resolve_adb", staticmethod(lambda p: Path("/fake/platform-tools/adb"))
    )
    return AdbClient()


def _stub_run(
    monkeypatch: pytest.MonkeyPatch, client: AdbClient, stdout: str = ""
) -> list[list[str]]:
    """把 client._run 替换为记录调用并返回固定 stdout 的替身，返回调用记录。"""
    calls: list[list[str]] = []

    def fake_run(args: list[str], *, timeout: int = adb._DEFAULT_TIMEOUT) -> str:
        calls.append(list(args))
        return stdout

    monkeypatch.setattr(client, "_run", fake_run)
    return calls


class TestResolveAdb:
    """_resolve_adb 的 PATH 回退分支。"""

    def test_falls_back_to_which(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """显式路径与项目内候选都不存在时，回落到 PATH 查找结果。"""
        monkeypatch.setattr(adb.shutil, "which", lambda name: "/usr/bin/adb")
        resolved = AdbClient._resolve_adb(None)
        assert resolved == Path("/usr/bin/adb")


class TestRunFailures:
    """_run 的三类失败路径。"""

    def test_missing_binary_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """subprocess 报 FileNotFoundError → AdbError「adb 二进制不可用」。"""
        client = _make_client(monkeypatch)

        def raise_missing(cmd: list[str], **kwargs: object) -> None:
            raise FileNotFoundError(cmd)

        monkeypatch.setattr(adb.subprocess, "run", raise_missing)
        with pytest.raises(AdbError, match="adb 二进制不可用"):
            client._run(["devices"])

    def test_timeout_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """命令超时 → AdbError「adb 命令超时」并带原始参数。"""
        client = _make_client(monkeypatch)

        def raise_timeout(cmd: list[str], **kwargs: object) -> None:
            raise subprocess.TimeoutExpired(cmd="adb devices", timeout=30)

        monkeypatch.setattr(adb.subprocess, "run", raise_timeout)
        with pytest.raises(AdbError, match=r"adb 命令超时.*devices"):
            client._run(["devices"])

    def test_success_returns_stdout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """返回码为 0 → 原样返回 stdout（utf-8 文本模式由 subprocess 承担）。"""
        client = _make_client(monkeypatch)
        completed = subprocess.CompletedProcess(
            args=["adb"], returncode=0, stdout="OK\n", stderr=""
        )
        monkeypatch.setattr(adb.subprocess, "run", lambda cmd, **kw: completed)
        assert client._run(["devices"]) == "OK\n"

    def test_nonzero_exit_raises_with_stderr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """返回码非零 → AdbError 携带 stderr 内容。"""
        client = _make_client(monkeypatch)
        completed = subprocess.CompletedProcess(
            args=["adb"], returncode=1, stdout="", stderr="device offline\n"
        )
        monkeypatch.setattr(adb.subprocess, "run", lambda cmd, **kw: completed)
        with pytest.raises(AdbError, match=r"adb 命令失败.*device offline"):
            client._run(["shell", "echo"])


class TestOutputParsing:
    """devices / ps 输出畸形行的容错解析。"""

    def test_list_devices_skips_blank_and_short_lines(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """空行与单字段行被跳过；model: 前缀被剥离；无 model 字段则为空串。"""
        client = _make_client(monkeypatch)
        stdout = (
            "List of devices attached\n"
            "\n"
            "restarting\n"  # 单字段行 → 跳过
            f"{_SERIAL} device product:sdk model:Pixel_6 device:generic\n"
            "1A2B3C unauthorized\n"
        )
        _stub_run(monkeypatch, client, stdout=stdout)
        devices = client.list_devices()
        assert [(d.serial, d.state) for d in devices] == [
            (_SERIAL, "device"),
            ("1A2B3C", "unauthorized"),
        ]
        assert devices[0].model == "Pixel_6"
        assert devices[1].model == ""

    def test_list_processes_skips_rows_with_missing_columns(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """不足 9 列的 ps 行被跳过，完整行按表头取 USER/PID/NAME。"""
        client = _make_client(monkeypatch)
        header = "USER PID PPID VSZ RSS WCHAN ADDR S NAME"
        stdout = (
            f"{header}\n"
            "root 1 0 123 456 0 S init\n"  # 8 列 → 跳过
            "u0_a1 1234 1 223 456 0 0 S com.evil.rat\n"
        )
        _stub_run(monkeypatch, client, stdout=stdout)
        processes = client.list_processes(_SERIAL)
        assert processes == [{"user": "u0_a1", "pid": "1234", "name": "com.evil.rat"}]


class TestTransferValidation:
    """pull/push/install 的本地路径前置校验。"""

    def test_pull_file_raises_when_adb_produced_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """adb pull 成功返回但本地无产物 → AdbError；父目录已预先创建。"""
        client = _make_client(monkeypatch)
        _stub_run(monkeypatch, client)
        local = tmp_path / "nested" / "evidence.bin"
        with pytest.raises(AdbError, match="未产出本地文件"):
            client.pull_file(_SERIAL, "/sdcard/evidence.bin", local)
        assert local.parent.is_dir()

    def test_push_file_requires_local_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """本地文件不存在 → AdbError，且不发起 adb 调用。"""
        client = _make_client(monkeypatch)
        calls = _stub_run(monkeypatch, client)
        with pytest.raises(AdbError, match="本地文件不存在"):
            client.push_file(_SERIAL, tmp_path / "agent.bin", "/data/local/tmp/agent.bin")
        assert calls == []

    def test_install_apk_requires_local_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """APK 不存在 → AdbError。"""
        client = _make_client(monkeypatch)
        with pytest.raises(AdbError, match="APK 不存在"):
            client.install_apk(_SERIAL, tmp_path / "missing.apk")

    def test_install_apk_replace_flag_controls_dash_r(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """replace=True 附加 -r；replace=False 不附加。"""
        client = _make_client(monkeypatch)
        apk = tmp_path / "sample.apk"
        apk.write_bytes(b"PK\x03\x04")
        calls = _stub_run(monkeypatch, client, stdout="Success\n")
        assert client.install_apk(_SERIAL, apk, replace=True) == "Success\n"
        assert calls[-1] == ["-s", _SERIAL, "install", "-r", str(apk)]
        client.install_apk(_SERIAL, apk, replace=False)
        assert calls[-1] == ["-s", _SERIAL, "install", str(apk)]


class TestCommandAssembly:
    """logcat / pair / disconnect 的命令组装与参数校验。"""

    def test_logcat_appends_filter_tag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """filter_tag 生成「-s <tag>」后缀。"""
        client = _make_client(monkeypatch)
        calls = _stub_run(monkeypatch, client)
        client.logcat(_SERIAL, lines=50, filter_tag="RAT")
        assert calls == [["-s", _SERIAL, "shell", "logcat -d -t 50 -s RAT"]]

    def test_pair_rejects_bad_pairing_code(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """非 6 位数字配对码 → AdbError，不发起 adb 调用。"""
        client = _make_client(monkeypatch)
        calls = _stub_run(monkeypatch, client)
        with pytest.raises(AdbError, match="6 位数字"):
            client.pair("192.168.1.10:37025", "12ab")
        assert calls == []

    def test_pair_rejects_host_without_port(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """host_port 缺少端口段 → AdbError「ip:配对端口」。"""
        client = _make_client(monkeypatch)
        with pytest.raises(AdbError, match="ip:配对端口"):
            client.pair("192.168.1.10", "123456")

    def test_pair_passes_through_valid_inputs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """合法 ip:port + 6 位配对码原样透传 adb pair。"""
        client = _make_client(monkeypatch)
        calls = _stub_run(monkeypatch, client, stdout="Success pairing\n")
        assert client.pair("192.168.1.10:37025", "123456") == "Success pairing\n"
        assert calls == [["pair", "192.168.1.10:37025", "123456"]]

    def test_disconnect_with_and_without_target(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """disconnect 无参断开全部，带参断开指定 ip:port。"""
        client = _make_client(monkeypatch)
        calls = _stub_run(monkeypatch, client)
        client.disconnect()
        client.disconnect("192.168.1.10:5555")
        assert calls == [["disconnect"], ["disconnect", "192.168.1.10:5555"]]


class TestScreenshotFailure:
    """screenshot 的失败路径（字节流不经 _run）。"""

    def test_failed_screencap_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """exec-out 返回非零 → AdbError「截图失败」并带 stderr 摘要。"""
        client = _make_client(monkeypatch)
        completed = subprocess.CompletedProcess(
            args=["adb"], returncode=1, stdout=b"", stderr=b"screencap failed"
        )
        monkeypatch.setattr(adb.subprocess, "run", lambda cmd, **kw: completed)
        with pytest.raises(AdbError, match=r"截图失败.*screencap failed"):
            client.screenshot(_SERIAL, tmp_path / "shot.png")
