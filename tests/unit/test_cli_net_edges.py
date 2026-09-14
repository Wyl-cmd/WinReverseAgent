"""测试模块：winreverse.cli.net 边界分支。

覆盖 _bridge 的 --tshark 路径构造转发、net read 空白 fields 的委托值、
net edit 未给可选参数时的默认委托（keep_first_n=None / remove_duplicates=False）。
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from winreverse.cli import app
from winreverse.forensics.network import PcapReadResult

runner = CliRunner()

TSHARK = "winreverse.forensics.network.TsharkBridge"
EDITCAP = "winreverse.forensics.network.EditcapBridge"


class TestTsharkPathForwarding:
    """--tshark 显式路径应原样传入 TsharkBridge 构造（_bridge 的真值分支）。"""

    def test_interfaces_forwards_tshark_path(self) -> None:
        with patch(TSHARK) as cls:
            cls.return_value.list_interfaces.return_value = []
            result = runner.invoke(app, ["net", "interfaces", "--tshark", "C:\\bin\\tshark.exe"])
        assert result.exit_code == 0
        cls.assert_called_once_with("C:\\bin\\tshark.exe")

    def test_capture_forwards_tshark_path(self, tmp_path: Path) -> None:
        out = tmp_path / "c.pcap"
        with patch(TSHARK) as cls:
            cls.return_value.live_capture.return_value = out
            result = runner.invoke(
                app,
                ["net", "capture", "0", "-o", str(out), "--tshark", "/usr/bin/tshark"],
            )
        assert result.exit_code == 0
        cls.assert_called_once_with("/usr/bin/tshark")


class TestReadEditDefaults:
    """read/edit 未给可选参数时的委托默认值。"""

    def test_read_whitespace_only_fields_passes_empty_list(self, tmp_path: Path) -> None:
        # 现行为：fields 非空字符串（即使全为空白）会拆分为空列表而非 None
        pcap = tmp_path / "c.pcap"
        with patch(TSHARK) as cls:
            cls.return_value.read_pcap.return_value = PcapReadResult(file=str(pcap), packet_count=0)
            result = runner.invoke(app, ["net", "read", str(pcap), "--fields", " , "])
        assert result.exit_code == 0
        assert cls.return_value.read_pcap.call_args.kwargs["fields"] == []

    def test_edit_defaults_without_options(self, tmp_path: Path) -> None:
        src, dst = tmp_path / "in.pcap", tmp_path / "out.pcap"
        with patch(EDITCAP) as editor_cls:
            editor_cls.return_value.edit_pcap.return_value = dst
            result = runner.invoke(app, ["net", "edit", str(src), str(dst)])
        assert result.exit_code == 0
        kwargs = editor_cls.return_value.edit_pcap.call_args.kwargs
        assert kwargs["keep_first_n"] is None
        assert kwargs["remove_duplicates"] is False
