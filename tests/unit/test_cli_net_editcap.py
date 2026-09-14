"""测试模块：winreverse.cli.net edit 命令的 editcap_override 分支。

覆盖 --tshark 指定路径时同目录 editcap.exe 的自动发现（存在/不存在）、
未给 --tshark 时 EditcapBridge 收到 None。全程 patch，不触网。
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from winreverse.cli import app

runner = CliRunner()

TSHARK = "winreverse.forensics.network.TsharkBridge"
EDITCAP = "winreverse.forensics.network.EditcapBridge"


class TestEditcapOverrideDiscovery:
    """edit 命令按 --tshark 同目录发现 editcap.exe。"""

    def test_sibling_editcap_exe_is_used(self, tmp_path: Path) -> None:
        (tmp_path / "tshark.exe").write_bytes(b"fake")
        (tmp_path / "editcap.exe").write_bytes(b"fake")
        src, dst = tmp_path / "in.pcap", tmp_path / "out.pcap"
        with patch(EDITCAP) as editor_cls:
            editor_cls.return_value.edit_pcap.return_value = dst
            result = runner.invoke(
                app, ["net", "edit", str(src), str(dst), "--tshark", str(tmp_path / "tshark.exe")]
            )
        assert result.exit_code == 0
        assert editor_cls.call_args.args[0] == tmp_path / "editcap.exe"

    def test_missing_sibling_falls_back_to_none(self, tmp_path: Path) -> None:
        (tmp_path / "tshark.exe").write_bytes(b"fake")  # 无同目录 editcap.exe
        src, dst = tmp_path / "in.pcap", tmp_path / "out.pcap"
        with patch(EDITCAP) as editor_cls:
            editor_cls.return_value.edit_pcap.return_value = dst
            result = runner.invoke(
                app, ["net", "edit", str(src), str(dst), "--tshark", str(tmp_path / "tshark.exe")]
            )
        assert result.exit_code == 0
        assert editor_cls.call_args.args[0] is None

    def test_no_tshark_option_passes_none(self, tmp_path: Path) -> None:
        src, dst = tmp_path / "in.pcap", tmp_path / "out.pcap"
        with patch(TSHARK), patch(EDITCAP) as editor_cls:
            editor_cls.return_value.edit_pcap.return_value = dst
            result = runner.invoke(app, ["net", "edit", str(src), str(dst)])
        assert result.exit_code == 0
        assert editor_cls.call_args.args[0] is None
