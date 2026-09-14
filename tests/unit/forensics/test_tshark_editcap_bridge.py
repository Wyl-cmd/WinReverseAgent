"""测试模块：winreverse.forensics.network（TsharkBridge / EditcapBridge）。

覆盖：tshark/editcap 路径解析优先级与缺失报错、_run 错误分支（FileNotFoundError /
TimeoutExpired / 非零退出含 duration 容忍）、-D 接口解析与 loopback 识别、
live_capture 时长边界与参数拼装、read_pcap 过滤/字段提取、edit_pcap 编辑分支。
全程 mock subprocess.run，不依赖真实 tshark，Linux 可跑。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from winreverse.forensics import network as network_mod
from winreverse.forensics.network import (
    EditcapBridge,
    NetworkToolError,
    TsharkBridge,
)


def _fake_run(
    *,
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
    error: Exception | None = None,
):
    """构造替换 network_mod.subprocess.run 的假实现，并记录调用参数。"""
    calls: list[list[str]] = []

    def _run(args: list[str], **kwargs: object):
        calls.append(args)
        if error is not None:
            raise error
        return subprocess.CompletedProcess(args, returncode, stdout, stderr)

    return _run, calls


def _bridge(tmp_path: Path) -> TsharkBridge:
    """用显式存在的假 tshark 文件构造桥接（绕过 PATH 解析）。"""
    fake = tmp_path / "tshark.exe"
    fake.write_bytes(b"fake")
    return TsharkBridge(tshark_path=fake)


# =============================================================================
# 路径解析
# =============================================================================


class TestResolveTshark:
    """tshark 路径解析：显式路径 → tools/tshark/tshark.exe → PATH → 报错。"""

    def test_explicit_path_wins(self, tmp_path: Path) -> None:
        fake = tmp_path / "my-tshark.exe"
        fake.write_bytes(b"x")
        assert TsharkBridge(tshark_path=fake).tshark_path == fake

    def test_fallback_to_builtin_tools_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """显式路径无效时回退 cwd 下内置 tools/tshark/tshark.exe。"""
        monkeypatch.chdir(tmp_path)
        builtin = tmp_path / "tools" / "tshark" / "tshark.exe"
        builtin.parent.mkdir(parents=True)
        builtin.write_bytes(b"x")
        monkeypatch.setattr(network_mod.shutil, "which", lambda _: None)
        assert TsharkBridge().tshark_path == builtin

    def test_fallback_to_path_lookup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """内置目录也没有时走 shutil.which。"""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(network_mod.shutil, "which", lambda _: "/usr/bin/tshark")
        assert TsharkBridge().tshark_path == Path("/usr/bin/tshark")

    def test_missing_everywhere_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(network_mod.shutil, "which", lambda _: None)
        with pytest.raises(NetworkToolError, match="找不到 tshark"):
            TsharkBridge()


# =============================================================================
# _run 错误分支（经 version() 触发）
# =============================================================================


class TestTsharkRunErrors:
    """_run 的异常与失败语义。"""

    def test_version_returns_first_line(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        run, calls = _fake_run(stdout="TShark (Wireshark) 4.4.2 (Windows)\n...other\n")
        monkeypatch.setattr(network_mod.subprocess, "run", run)
        bridge = _bridge(tmp_path)
        assert bridge.version() == "TShark (Wireshark) 4.4.2 (Windows)"
        assert calls[0][1:] == ["-v"]

    def test_nonzero_exit_without_duration_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        run, _ = _fake_run(returncode=2, stderr="Error opening interface")
        monkeypatch.setattr(network_mod.subprocess, "run", run)
        with pytest.raises(NetworkToolError, match="tshark 失败"):
            _bridge(tmp_path).version()

    def test_nonzero_exit_with_duration_tolerated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """-a duration 到期部分版本返回非零，解析 pcap 时应视为正常结束。"""
        pcap = tmp_path / "c.pcap"
        pcap.write_bytes(b"x")
        run, _ = _fake_run(returncode=1, stderr="capturing stopped after duration:2 reached")
        monkeypatch.setattr(network_mod.subprocess, "run", run)
        result = _bridge(tmp_path).read_pcap(pcap)
        assert result.packet_count == 0

    def test_binary_missing_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        run, _ = _fake_run(error=FileNotFoundError(2, "No such file"))
        monkeypatch.setattr(network_mod.subprocess, "run", run)
        with pytest.raises(NetworkToolError, match="tshark 不可用"):
            _bridge(tmp_path).version()

    def test_timeout_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        run, _ = _fake_run(error=subprocess.TimeoutExpired(cmd="tshark", timeout=1))
        monkeypatch.setattr(network_mod.subprocess, "run", run)
        with pytest.raises(NetworkToolError, match="超时"):
            _bridge(tmp_path).version()


# =============================================================================
# list_interfaces 解析
# ==============================================================================


class TestListInterfaces:
    """tshark -D 输出解析：编号/名称/描述/loopback。"""

    _D_OUTPUT = (
        "1. eth0 (Ethernet adapter Ethernet)\n"
        "2. lo (Loopback Pseudo-Interface 1)\n"
        "3. \\Device\\NPF_{A1B2C3D4-1111-2222-3333-444455556666}\n"
        "4. any\n"
        "garbage line without number\n"
    )

    def test_parse_interfaces(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        run, calls = _fake_run(stdout=self._D_OUTPUT)
        monkeypatch.setattr(network_mod.subprocess, "run", run)
        interfaces = _bridge(tmp_path).list_interfaces()

        assert calls[0][1:] == ["-D"]
        assert len(interfaces) == 4  # 垃圾行被跳过
        eth0 = interfaces[0]
        assert (eth0.index, eth0.name, eth0.description) == (1, "eth0", "Ethernet adapter Ethernet")
        assert eth0.loopback is False
        assert interfaces[1].loopback is True  # 描述含 Loopback
        assert interfaces[2].description == ""  # 无括号描述
        assert interfaces[3].name == "any"

    def test_loopback_by_short_name(self) -> None:
        """name 以 lo 开头（如 lo0）也识别为环回。"""
        m = network_mod._INTERFACE_PATTERN.match("1. lo0")
        assert m is not None
        name = m.group(2)
        assert ("loopback" in name.lower()) or name.startswith("lo")

    def test_to_dict_roundtrip(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        run, _ = _fake_run(stdout="1. lo (Loopback)\n")
        monkeypatch.setattr(network_mod.subprocess, "run", run)
        d = _bridge(tmp_path).list_interfaces()[0].to_dict()
        assert d == {"index": 1, "name": "lo", "description": "Loopback", "loopback": True}


# =============================================================================
# live_capture
# ==============================================================================


class TestLiveCapture:
    """实时抓包：时长边界、参数拼装、产出校验。"""

    def test_duration_out_of_bounds_rejected(self, tmp_path: Path) -> None:
        bridge = _bridge(tmp_path)
        for bad in (0, -5, 3601):
            with pytest.raises(NetworkToolError, match="抓包时长"):
                bridge.live_capture(tmp_path / "out.pcap", duration_seconds=bad)

    def test_args_and_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        out = tmp_path / "sub" / "cap.pcap"

        def run(args: list[str], **kwargs: object):
            assert "-i" in args and args[args.index("-i") + 1] == "2"
            assert args[args.index("-a") + 1] == "duration:5"
            assert args[args.index("-w") + 1] == str(out)
            assert args[args.index("-f") + 1] == "host 1.2.3.4"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(b"pcap")
            return subprocess.CompletedProcess(args, 0, "", "")

        monkeypatch.setattr(network_mod.subprocess, "run", run)
        bridge = _bridge(tmp_path)
        result = bridge.live_capture(
            out, interface=2, duration_seconds=5, capture_filter="host 1.2.3.4"
        )
        assert result == out and out.is_file()

    def test_no_pcap_produced_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """命令成功但未产出文件（无权限/接口号错误）时应报错。"""
        run, _ = _fake_run()
        monkeypatch.setattr(network_mod.subprocess, "run", run)
        with pytest.raises(NetworkToolError, match="抓包未产出 pcap"):
            _bridge(tmp_path).live_capture(tmp_path / "none.pcap", duration_seconds=1)


# =============================================================================
# read_pcap
# ==============================================================================


class TestReadPcap:
    """pcap 解析：存在性、过滤与字段参数、行统计。"""

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(NetworkToolError, match="pcap 不存在"):
            _bridge(tmp_path).read_pcap(tmp_path / "no.pcap")

    def test_line_count_and_blank_filtering(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pcap = tmp_path / "c.pcap"
        pcap.write_bytes(b"x")
        run, calls = _fake_run(stdout="line1\n\nline2\n  \nline3\n")
        monkeypatch.setattr(network_mod.subprocess, "run", run)
        result = _bridge(tmp_path).read_pcap(pcap)
        assert result.packet_count == 3
        assert result.lines == ["line1", "line2", "line3"]
        assert result.file == str(pcap)
        assert result.display_filter == ""
        assert calls[0][1:3] == ["-r", str(pcap)]

    def test_filter_and_fields_args(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        pcap = tmp_path / "c.pcap"
        pcap.write_bytes(b"x")
        run, calls = _fake_run(stdout="ip.src\thttp.host\n1.1.1.1\thost\n")
        monkeypatch.setattr(network_mod.subprocess, "run", run)
        result = _bridge(tmp_path).read_pcap(
            pcap, display_filter="http.request", fields=["ip.src", "http.host"]
        )
        args = calls[0]
        assert args[args.index("-Y") + 1] == "http.request"
        assert args[args.index("-e") + 1] == "ip.src"
        assert args[args.index("-T") + 1] == "fields"
        assert args[args.index("-E") + 1] == "header=y"
        assert result.packet_count == 2  # 含表头行
        assert result.display_filter == "http.request"

    def test_to_dict_truncates_lines(self) -> None:
        from winreverse.forensics.network import PcapReadResult

        result = PcapReadResult(file="x.pcap", lines=[f"l{i}" for i in range(1500)])
        d = result.to_dict()
        assert len(d["lines"]) == 1000  # to_dict 截断到 1000 行
        assert result.packet_count == 0  # 默认值不受 lines 影响


# =============================================================================
# EditcapBridge
# ==============================================================================


class TestEditcapBridge:
    """editcap 桥接：可用性、编辑参数、失败分支。"""

    def _available_bridge(self, tmp_path: Path) -> EditcapBridge:
        fake = tmp_path / "editcap.exe"
        fake.write_bytes(b"x")
        return EditcapBridge(editcap_path=fake)

    def test_unavailable_when_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(network_mod.shutil, "which", lambda _: None)
        assert EditcapBridge().is_available() is False

    def test_edit_when_unavailable_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(network_mod.shutil, "which", lambda _: None)
        with pytest.raises(NetworkToolError, match="editcap 不可用"):
            EditcapBridge().edit_pcap(tmp_path / "in.pcap", tmp_path / "out.pcap")

    def test_missing_input_raises(self, tmp_path: Path) -> None:
        with pytest.raises(NetworkToolError, match="pcap 不存在"):
            self._available_bridge(tmp_path).edit_pcap(tmp_path / "no.pcap", tmp_path / "o.pcap")

    def test_edit_args_keep_and_dedup(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        src = tmp_path / "in.pcap"
        src.write_bytes(b"pcap")
        out = tmp_path / "sub" / "out.pcap"

        def run(args: list[str], **kwargs: object):
            assert "-r" in args  # keep_first_n → 保留选中
            assert "-d" in args  # remove_duplicates
            assert args[args.index("-d") + 1 :] == [str(src), str(out), "1-10"]
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(b"pcap")
            return subprocess.CompletedProcess(args, 0, "", "")

        monkeypatch.setattr(network_mod.subprocess, "run", run)
        result = self._available_bridge(tmp_path).edit_pcap(
            src, out, keep_first_n=10, remove_duplicates=True
        )
        assert result == out and out.is_file()

    def test_edit_failure_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        src = tmp_path / "in.pcap"
        src.write_bytes(b"pcap")
        run, _ = _fake_run(returncode=1, stderr="boom")
        monkeypatch.setattr(network_mod.subprocess, "run", run)
        with pytest.raises(NetworkToolError, match="editcap 失败"):
            self._available_bridge(tmp_path).edit_pcap(src, tmp_path / "o.pcap")

    def test_edit_timeout_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        src = tmp_path / "in.pcap"
        src.write_bytes(b"pcap")
        run, _ = _fake_run(error=subprocess.TimeoutExpired(cmd="editcap", timeout=1))
        monkeypatch.setattr(network_mod.subprocess, "run", run)
        with pytest.raises(NetworkToolError, match="editcap 超时"):
            self._available_bridge(tmp_path).edit_pcap(src, tmp_path / "o.pcap")
