"""测试模块：winreverse.forensics.sandbox_wsb

覆盖点：build_wsb_config 的 XML 结构/安全默认值/参数校验边界、
write_wsb_config 落盘与父目录创建、is_sandbox_available 判定。
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from types import SimpleNamespace

import pytest

from winreverse.forensics.sandbox_wsb import (
    SandboxConfigError,
    build_wsb_config,
    is_sandbox_available,
    write_wsb_config,
)


@pytest.fixture
def sample_file(tmp_path):
    """主机侧真实样本文件（build_wsb_config 要求样本存在）。"""
    sample = tmp_path / "malware.exe"
    sample.write_bytes(b"MZ")
    return sample


class TestBuildWsbConfig:
    """build_wsb_config：XML 生成与校验。"""

    def test_default_security_settings(self, sample_file) -> None:
        """默认配置：关网络、只读映射样本目录、内存 4096。"""
        content = build_wsb_config(sample_file)
        root = ET.fromstring(content)
        assert root.tag == "Configuration"
        assert root.findtext("Networking") == "Disable"  # 木马引爆安全默认
        assert root.findtext("MemoryInMB") == "4096"
        folder = root.find("MappedFolders/MappedFolder")
        assert folder is not None
        assert folder.findtext("HostFolder") == str(sample_file.parent.resolve())
        assert folder.findtext("ReadOnly") == "true"
        assert root.find("LogonCommand") is None  # 未给登录命令则无该节点

    def test_no_xml_declaration_line(self, sample_file) -> None:
        """wsb 不需要 xml 声明行。"""
        content = build_wsb_config(sample_file)
        assert not content.startswith("<?xml")
        assert content.splitlines()[0].strip() == "<Configuration>"

    def test_networking_enabled(self, sample_file) -> None:
        """networking=True 时网络节点为 Default。"""
        root = ET.fromstring(build_wsb_config(sample_file, networking=True))
        assert root.findtext("Networking") == "Default"

    def test_logon_command(self, sample_file) -> None:
        """logon_command 写入 LogonCommand/Command。"""
        root = ET.fromstring(
            build_wsb_config(sample_file, logon_command="start C:\\Users\\WDAGUtility\\m.exe")
        )
        assert root.findtext("LogonCommand/Command") == "start C:\\Users\\WDAGUtility\\m.exe"

    def test_custom_mapped_folder(self, sample_file, tmp_path) -> None:
        """显式 mapped_folder 覆盖默认的样本所在目录。"""
        extra = tmp_path / "tools"
        extra.mkdir()
        root = ET.fromstring(build_wsb_config(sample_file, mapped_folder=extra))
        assert root.findtext("MappedFolders/MappedFolder/HostFolder") == str(extra.resolve())

    @pytest.mark.parametrize("memory_mb", [512, 65536])
    def test_memory_bounds_inclusive(self, sample_file, memory_mb) -> None:
        """内存上下界（512/65536）为闭区间，合法值可通过。"""
        root = ET.fromstring(build_wsb_config(sample_file, memory_mb=memory_mb))
        assert root.findtext("MemoryInMB") == str(memory_mb)

    @pytest.mark.parametrize("memory_mb", [511, 65537, 0, -1])
    def test_memory_out_of_bounds_rejected(self, sample_file, memory_mb) -> None:
        """越界内存参数抛 SandboxConfigError。"""
        with pytest.raises(SandboxConfigError, match="内存参数非法"):
            build_wsb_config(sample_file, memory_mb=memory_mb)

    def test_missing_sample_rejected(self, tmp_path) -> None:
        """样本不存在时抛 SandboxConfigError（路径回显在消息里）。"""
        ghost = tmp_path / "not_exist.exe"
        with pytest.raises(SandboxConfigError, match="样本不存在"):
            build_wsb_config(ghost)


class TestWriteWsbConfig:
    """write_wsb_config：落盘行为。"""

    def test_writes_file_and_creates_parents(self, sample_file, tmp_path) -> None:
        """生成内容与 build_wsb_config 一致，且自动创建多级父目录。"""
        out = tmp_path / "a" / "b" / "sample_sandbox.wsb"
        result = write_wsb_config(sample_file, out, logon_command="cmd")
        assert result == out
        assert out.is_file()
        assert out.read_text(encoding="utf-8") == build_wsb_config(sample_file, logon_command="cmd")

    def test_propagates_config_error(self, tmp_path) -> None:
        """样本非法时错误上抛（不落盘半成品文件）。"""
        out = tmp_path / "x.wsb"
        with pytest.raises(SandboxConfigError):
            write_wsb_config(tmp_path / "ghost.exe", out)
        assert not out.exists()


class TestIsSandboxAvailable:
    """is_sandbox_available：以 WindowsSandbox.exe 存在性判定。"""

    def test_true_when_sandbox_exe_exists(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "winreverse.forensics.sandbox_wsb.Path",
            lambda _p: SimpleNamespace(is_file=lambda: True),
        )
        assert is_sandbox_available() is True

    def test_false_when_sandbox_exe_missing(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "winreverse.forensics.sandbox_wsb.Path",
            lambda _p: SimpleNamespace(is_file=lambda: False),
        )
        assert is_sandbox_available() is False
