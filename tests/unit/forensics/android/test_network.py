"""测试模块：winreverse.forensics.network

tshark/editcap 桥接测试。内置 tools/tshark/tshark.exe 存在时做真实调用
（windows_only + 文件存在守卫）；live_capture 用 mock 验证参数拼装。
"""

from __future__ import annotations

import struct
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from winreverse.forensics.network import (
    EditcapBridge,
    NetworkToolError,
    TsharkBridge,
)

_BUILTIN_TSHARK = Path("tools/tshark/tshark.exe")


def _builtin_available() -> bool:
    """内置 tshark 是否就位（非项目根/未安装时跳过真实调用测试）。"""
    return _BUILTIN_TSHARK.is_file()


def _make_pcap(path: Path, count: int = 3) -> Path:
    """构造含 count 个 ICMP 包的最小 pcap。"""
    pcap_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"data"
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(icmp),
        1,
        0,
        64,
        1,
        1,
        bytes([1, 2, 3, 4]),
        bytes([5, 6, 7, 8]),
    )
    eth = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x08\x00"
    packet = eth + ip + icmp
    pkt_hdr = struct.pack("<IIII", 0, 0, len(packet), len(packet))
    path.write_bytes(pcap_hdr + (pkt_hdr + packet) * count)
    return path


class TestTsharkResolution:
    """tshark 路径解析测试。"""

    def test_missing_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """三处都找不到时给指引。"""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("shutil.which", lambda name: None)
        with pytest.raises(NetworkToolError, match="找不到 tshark"):
            TsharkBridge()

    def test_explicit_path(self, tmp_path: Path) -> None:
        """显式路径优先。"""
        fake = tmp_path / "tshark.exe"
        fake.write_bytes(b"")
        assert TsharkBridge(fake).tshark_path == fake


class TestTsharkReal:
    """内置 tshark 真实调用测试（需要 tools/tshark/tshark.exe）。"""

    @pytest.mark.skipif(not _builtin_available(), reason="内置 tshark 未安装")
    def test_version(self) -> None:
        """真实 tshark -v 输出版本行。"""
        bridge = TsharkBridge()
        assert "TShark" in bridge.version()

    @pytest.mark.skipif(not _builtin_available(), reason="内置 tshark 未安装")
    def test_list_interfaces(self) -> None:
        """真实接口枚举至少返回一个接口。"""
        bridge = TsharkBridge()
        interfaces = bridge.list_interfaces()
        assert len(interfaces) >= 1
        assert interfaces[0].index >= 1

    @pytest.mark.skipif(not _builtin_available(), reason="内置 tshark 未安装")
    def test_read_pcap_with_fields(self, tmp_path: Path) -> None:
        """真实解析自构造 pcap：字段提取与显示过滤。"""
        pcap = _make_pcap(tmp_path / "t.pcap", count=3)
        bridge = TsharkBridge()
        result = bridge.read_pcap(pcap, fields=["ip.src", "ip.dst"])
        assert result.packet_count == 4  # 1 表头 + 3 行
        assert any("1.2.3.4" in line for line in result.lines)

        filtered = bridge.read_pcap(pcap, display_filter="icmp", fields=["ip.proto"])
        assert filtered.packet_count >= 1

    def test_read_pcap_missing_file(self, tmp_path: Path) -> None:
        """pcap 不存在报错。"""
        with patch.object(TsharkBridge, "_resolve_tshark", return_value=tmp_path / "x.exe"):
            bridge = TsharkBridge.__new__(TsharkBridge)
            bridge._tshark_path = tmp_path / "x.exe"
            with pytest.raises(NetworkToolError, match="不存在"):
                bridge.read_pcap(tmp_path / "nope.pcap")


class TestLiveCapture:
    """实时抓包参数与失败路径测试（mock 子进程）。"""

    def _bridge_with_mock(self, tmp_path: Path) -> TsharkBridge:
        fake = tmp_path / "tshark.exe"
        fake.write_bytes(b"")
        return TsharkBridge(fake)

    def test_duration_bounds(self, tmp_path: Path) -> None:
        """时长越界被拒绝。"""
        bridge = self._bridge_with_mock(tmp_path)
        with pytest.raises(NetworkToolError, match="时长"):
            bridge.live_capture(tmp_path / "a.pcap", duration_seconds=0)
        with pytest.raises(NetworkToolError, match="时长"):
            bridge.live_capture(tmp_path / "a.pcap", duration_seconds=999999)

    def test_capture_invocation_args(self, tmp_path: Path) -> None:
        """抓包命令拼装正确（接口/时长/过滤），产物校验。"""
        bridge = self._bridge_with_mock(tmp_path)
        out = tmp_path / "cap.pcap"

        def fake_run(self: object, args: list[str], *, timeout: int = 300) -> str:
            Path(args[args.index("-w") + 1]).write_bytes(b"pcap")
            return ""

        with patch.object(TsharkBridge, "_run", fake_run):
            result = bridge.live_capture(
                out, interface=3, duration_seconds=10, capture_filter="host 1.2.3.4"
            )
        assert result == out
        # 校验 mock 收到的参数
        captured: dict[str, list[str]] = {}

        def capture_run(self: object, args: list[str], *, timeout: int = 300) -> str:
            captured["args"] = args
            Path(args[args.index("-w") + 1]).write_bytes(b"pcap")
            return ""

        with patch.object(TsharkBridge, "_run", capture_run):
            bridge.live_capture(out, interface=2, duration_seconds=5, capture_filter="tcp port 443")
        args = captured["args"]
        assert args[args.index("-i") + 1] == "2"
        assert args[args.index("-a") + 1] == "duration:5"
        assert args[args.index("-f") + 1] == "tcp port 443"
        _ = MagicMock

    def test_capture_no_output_raises(self, tmp_path: Path) -> None:
        """无产物时报错（模拟无权限）。"""
        bridge = self._bridge_with_mock(tmp_path)
        with (
            patch.object(TsharkBridge, "_run", lambda self, args, *, timeout=300: ""),
            pytest.raises(NetworkToolError, match="管理员权限"),
        ):
            bridge.live_capture(tmp_path / "none.pcap", duration_seconds=5)


class TestEditcapBridge:
    """editcap 桥接测试。"""

    def test_unavailable_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """editcap 缺失时给指引。"""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("shutil.which", lambda name: None)
        bridge = EditcapBridge()
        assert bridge.is_available() is False
        with pytest.raises(NetworkToolError, match="editcap"):
            bridge.edit_pcap("a.pcap", "b.pcap")

    def test_edit_keep_first_n(self, tmp_path: Path) -> None:
        """保留前 N 包（真实 editcap，若内置）。"""
        if not (Path("tools/tshark/editcap.exe").is_file()):
            pytest.skip("内置 editcap 未安装")
        src = _make_pcap(tmp_path / "in.pcap", count=5)
        bridge = EditcapBridge()
        out = bridge.edit_pcap(src, tmp_path / "out.pcap", keep_first_n=2)
        assert out.is_file()
        tshark = TsharkBridge()
        result = tshark.read_pcap(out)
        assert result.packet_count == 2
