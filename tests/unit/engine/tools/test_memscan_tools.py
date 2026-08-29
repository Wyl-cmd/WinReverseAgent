"""测试模块：winreverse.engine.tools.memscan_tools

覆盖 7 个内存取证工具的输入校验、会话依赖、core 层委托与错误路径。
进程会话通过向 memory_tools._sessions 注入 MagicMock 模拟；
数据文件使用合成内容，不依赖真实进程与管理员权限。
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from winreverse.core import memdump_api
from winreverse.core.memanalysis_api import carve_pe
from winreverse.engine.tools import memscan_tools
from winreverse.engine.tools.memory_tools import _clear_sessions, _sessions
from winreverse.engine.tools.memscan_tools import MEMSCAN_TOOLS

# =============================================================================
# fixtures
# =============================================================================


@pytest.fixture
def attached_session() -> MagicMock:
    """向会话表注入一个已附加进程的 mock Pymem（用后清理）。"""
    pm = MagicMock()
    pm.process_handle = 1234
    _sessions[4242] = pm
    yield pm
    _clear_sessions()


def _build_fake_pe(size_of_image: int = 0x2000) -> bytes:
    """构造仅头部有效的最小 PE（与分析层测试同规格）。"""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 1700000000, 0, 0, 0xF0, 0x210E)
    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 56, size_of_image)
    return bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + bytearray(40)


# =============================================================================
# 工具清单完整性
# =============================================================================


class TestMemscanToolInventory:
    """MEMSCAN_TOOLS 清单测试。"""

    def test_seven_tools_registered(self) -> None:
        """共 7 个内存取证工具。"""
        assert len(MEMSCAN_TOOLS) == 7

    def test_tool_names(self) -> None:
        """工具命名空间统一为 memory.*。"""
        names = {t.name for t in MEMSCAN_TOOLS}
        assert names == {
            "memory.regions",
            "memory.dump",
            "memory.dump_minidump",
            "memory.strings",
            "memory.iocs",
            "memory.carve_pe",
            "memory.analyze",
        }

    def test_tools_have_description(self) -> None:
        """所有工具必须有非空描述。"""
        for tool in MEMSCAN_TOOLS:
            assert tool.description


# =============================================================================
# memory.regions
# =============================================================================


class TestMemoryRegionsTool:
    """memory.regions 工具测试。"""

    def test_requires_attach_first(self) -> None:
        """未附加进程时返回错误提示。"""
        tool = memscan_tools.MemoryRegionsTool()
        result = tool.execute({"pid": 9999})
        assert result["status"] == "error"
        assert "memory.attach" in result["error_message"]

    def test_missing_pid_raises_param_error(self) -> None:
        """缺少 pid 参数返回参数错误。"""
        tool = memscan_tools.MemoryRegionsTool()
        result = tool.execute({})
        assert result["status"] == "error"
        assert "缺少必需参数" in result["error_message"]

    def test_regions_summary(
        self, attached_session: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """正常枚举：可疑区域与可执行区域分开展示。"""
        from winreverse.core.memdump_api import (
            MEM_COMMIT,
            MEM_IMAGE,
            MEM_PRIVATE,
            PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE,
            PAGE_READWRITE,
            MemoryRegion,
        )

        regions = [
            MemoryRegion(0x1000, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE),
            MemoryRegion(0x2000, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_IMAGE),
            MemoryRegion(0x3000, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE, MEM_PRIVATE),
        ]
        monkeypatch.setattr(
            memdump_api, "enumerate_regions", lambda handle, only_committed=True: regions
        )
        tool = memscan_tools.MemoryRegionsTool()
        result = tool.execute({"pid": 4242})
        assert result["status"] == "success"
        assert result["total"] == 3
        assert result["suspicious_count"] == 1
        assert result["suspicious"][0]["base_address"] == "0x3000"
        # 默认仅展示可执行区域（排除纯 RW 数据区）
        assert all(r["protect"] in ("RX", "RWX") for r in result["regions"])

    def test_regions_include_all(
        self, attached_session: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """include_all=true 返回全部已提交区域。"""
        from winreverse.core.memdump_api import (
            MEM_COMMIT,
            MEM_PRIVATE,
            PAGE_READWRITE,
            MemoryRegion,
        )

        regions = [MemoryRegion(0x1000, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE)]
        monkeypatch.setattr(
            memdump_api, "enumerate_regions", lambda handle, only_committed=True: regions
        )
        tool = memscan_tools.MemoryRegionsTool()
        result = tool.execute({"pid": 4242, "include_all": True})
        assert result["total"] == 1
        assert len(result["regions"]) == 1


# =============================================================================
# memory.dump / memory.dump_minidump
# =============================================================================


class TestMemoryDumpTool:
    """memory.dump 工具测试。"""

    def test_dump_with_default_output_dir(
        self, attached_session: MagicMock, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """未指定输出目录时使用 output/memory_dumps/<pid>_<时间戳>。"""
        captured: dict[str, object] = {}

        def fake_dump(handle: int, output_dir: object, **kwargs: object) -> memdump_api.DumpResult:
            captured["handle"] = handle
            captured["output_dir"] = str(output_dir)
            return memdump_api.DumpResult(
                output_dir=str(output_dir),
                manifest_path=str(Path(str(output_dir)) / "manifest.json"),
                region_count=10,
                dumped_count=8,
            )

        monkeypatch.setattr(memdump_api, "dump_process", fake_dump)
        monkeypatch.chdir(tmp_path)
        tool = memscan_tools.MemoryDumpTool()
        result = tool.execute({"pid": 4242})
        assert result["status"] == "success"
        assert str(captured["handle"]) == "1234"
        # 默认输出目录为相对项目根的 output/memory_dumps/<pid>_<时间戳>
        assert os.path.normpath(str(captured["output_dir"])).startswith(
            os.path.join("output", "memory_dumps", "4242_")
        )
        assert result["dumped_count"] == 8

    def test_dump_with_custom_output_dir(
        self, attached_session: MagicMock, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """自定义输出目录透传给 core 层。"""
        captured: dict[str, object] = {}

        def fake_dump(handle: int, output_dir: object, **kwargs: object) -> memdump_api.DumpResult:
            captured["output_dir"] = output_dir
            return memdump_api.DumpResult(output_dir=str(output_dir), manifest_path="m")

        monkeypatch.setattr(memdump_api, "dump_process", fake_dump)
        tool = memscan_tools.MemoryDumpTool()
        result = tool.execute({"pid": 4242, "output_dir": str(tmp_path / "custom")})
        assert result["status"] == "success"
        assert captured["output_dir"] == str(tmp_path / "custom")

    def test_dump_requires_session(self) -> None:
        """未附加进程时返回错误。"""
        tool = memscan_tools.MemoryDumpTool()
        result = tool.execute({"pid": 1})
        assert result["status"] == "error"


class TestMemoryMinidumpTool:
    """memory.dump_minidump 工具测试。"""

    def test_minidump_default_path(
        self, attached_session: MagicMock, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """默认输出到 output/memory_dumps/<pid>.dmp。"""
        captured: dict[str, object] = {}

        def fake_minidump(handle: int, pid: int, output_path: object, **kwargs: object) -> Path:
            captured["output_path"] = output_path
            return Path(str(output_path))

        monkeypatch.setattr(memdump_api, "dump_minidump", fake_minidump)
        monkeypatch.chdir(tmp_path)
        tool = memscan_tools.MemoryMinidumpTool()
        result = tool.execute({"pid": 4242})
        assert result["status"] == "success"
        assert os.path.normpath(result["output_path"]) == os.path.join(
            "output", "memory_dumps", "4242.dmp"
        )

    def test_minidump_requires_session(self) -> None:
        """未附加进程时返回错误。"""
        tool = memscan_tools.MemoryMinidumpTool()
        result = tool.execute({"pid": 1, "output_path": "x.dmp"})
        assert result["status"] == "error"


# =============================================================================
# memory.strings / memory.iocs / memory.carve_pe / memory.analyze（文件类）
# =============================================================================


class TestMemoryFileTools:
    """文件分析类工具测试（真实 core 层，合成数据）。"""

    def test_strings_tool(self, tmp_path: Path) -> None:
        """字符串工具返回截断标志与命中列表。"""
        dump_file = tmp_path / "region.bin"
        dump_file.write_bytes(b"first_string_here\x00second_string_here\x00")
        tool = memscan_tools.MemoryStringsTool()
        result = tool.execute({"path": str(dump_file), "limit": 1})
        assert result["status"] == "success"
        assert result["count"] >= 2
        assert len(result["strings"]) == 1
        assert result["truncated"] is True

    def test_strings_missing_file(self) -> None:
        """文件不存在返回错误。"""
        tool = memscan_tools.MemoryStringsTool()
        result = tool.execute({"path": "Z:/no/such/file.bin"})
        assert result["status"] == "error"
        assert "不存在" in result["error_message"]

    def test_iocs_tool(self, tmp_path: Path) -> None:
        """IOC 工具按 kind 分类统计。"""
        dump_file = tmp_path / "region.bin"
        dump_file.write_bytes(b"c2 server http://bad.example.top/x\x00")
        tool = memscan_tools.MemoryIocsTool()
        result = tool.execute({"path": str(dump_file)})
        assert result["status"] == "success"
        assert result["by_kind"]["url"] >= 1
        assert result["count"] == len(result["iocs"])

    def test_carve_pe_tool_without_output(self, tmp_path: Path) -> None:
        """不传 output_dir 时仅报告不落盘。"""
        dump_file = tmp_path / "region.bin"
        dump_file.write_bytes(_build_fake_pe() + b"\x00" * 0x2000)
        tool = memscan_tools.MemoryCarvePeTool()
        result = tool.execute({"path": str(dump_file)})
        assert result["status"] == "success"
        assert result["count"] == 1
        assert result["pes"][0]["arch"] == "x64"
        assert result["written_files"] == []

    def test_carve_pe_tool_with_output(self, tmp_path: Path) -> None:
        """传入 output_dir 时落盘雕刻文件。"""
        dump_file = tmp_path / "region.bin"
        dump_file.write_bytes(_build_fake_pe() + b"\x00" * 0x2000)
        out_dir = tmp_path / "carved"
        tool = memscan_tools.MemoryCarvePeTool()
        result = tool.execute({"path": str(dump_file), "output_dir": str(out_dir)})
        assert result["status"] == "success"
        assert len(result["written_files"]) == 1
        assert Path(result["written_files"][0]).is_file()

    def test_carve_pe_matches_core_layer(self, tmp_path: Path) -> None:
        """工具层与 core 层雕刻结果一致。"""
        data = _build_fake_pe() + b"\x00" * 0x2000
        dump_file = tmp_path / "region.bin"
        dump_file.write_bytes(data)
        tool = memscan_tools.MemoryCarvePeTool()
        result = tool.execute({"path": str(dump_file)})
        core_result = carve_pe(data)
        assert result["pes"][0]["offset"] == core_result[0].offset
        assert result["pes"][0]["sha256"] == core_result[0].sha256


class TestMemoryAnalyzeTool:
    """memory.analyze 一键分析工具测试。"""

    def _make_dump_dir(self, tmp_path: Path) -> Path:
        """构造含 manifest 的最小转储目录。"""
        dump_dir = tmp_path / "dump"
        dump_dir.mkdir()
        content = b"ioc_marker http://c2.evil.top\x00"
        (dump_dir / "region_0000.bin").write_bytes(content)
        manifest = {
            "pid": 4242,
            "created_at": "2026-08-29T00:00:00+00:00",
            "regions": [
                {
                    "file": "region_0000.bin",
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "suspicious": True,
                }
            ],
        }
        (dump_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return dump_dir

    def test_analyze_requires_dump_dir(self) -> None:
        """缺少 dump_dir 参数返回参数错误。"""
        tool = memscan_tools.MemoryAnalyzeTool()
        result = tool.execute({})
        assert result["status"] == "error"
        assert "缺少必需参数" in result["error_message"]

    def test_analyze_full_flow(self, tmp_path: Path) -> None:
        """一键分析返回结构化报告（含可疑区域与 IOC）。"""
        dump_dir = self._make_dump_dir(tmp_path)
        tool = memscan_tools.MemoryAnalyzeTool()
        result = tool.execute({"dump_dir": str(dump_dir)})
        assert result["status"] == "success"
        assert result["pid"] == 4242
        assert len(result["files"]) == 1
        assert result["total_ioc_count"] >= 1
        assert len(result["suspicious_regions"]) == 1

    def test_analyze_with_yara_rules(self, tmp_path: Path) -> None:
        """传入规则文件路径可触发 YARA 扫描。"""
        dump_dir = self._make_dump_dir(tmp_path)
        rules_file = tmp_path / "rules.yar"
        rules_file.write_text(
            'rule test_marker { strings: $a = "ioc_marker" ascii condition: $a }',
            encoding="utf-8",
        )
        tool = memscan_tools.MemoryAnalyzeTool()
        result = tool.execute({"dump_dir": str(dump_dir), "rules_path": str(rules_file)})
        assert result["status"] == "success"
        assert "region_0000.bin" in result["yara_matches"]
        assert result["yara_matches"]["region_0000.bin"][0]["rule"] == "test_marker"

    def test_analyze_missing_manifest(self, tmp_path: Path) -> None:
        """目录缺 manifest 时返回错误。"""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        tool = memscan_tools.MemoryAnalyzeTool()
        result = tool.execute({"dump_dir": str(empty_dir)})
        assert result["status"] == "error"
        assert "manifest.json 缺失" in result["error_message"]
