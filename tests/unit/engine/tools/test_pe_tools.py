"""测试模块：winreverse.engine.tools.pe_tools

测试 PE 分析工具集。使用 mock 避免 PE 文件解析的真实 IO。
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from winreverse.engine.tools.pe_tools import (
    PE_TOOLS,
    PEExportsTool,
    PEImportsTool,
    PEMetaTool,
    PEParseTool,
    PESectionsTool,
    PESuspiciousImportsTool,
)


@pytest.fixture
def mock_pe() -> MagicMock:
    """mock 的 PE 实例。"""
    pe = MagicMock()
    pe.FILE_HEADER.Machine = 0x8664  # AMD64
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = 4096
    pe.DIRECTORY_ENTRY_IMPORT = []
    pe.DIRECTORY_ENTRY_EXPORT = MagicMock()
    pe.DIRECTORY_ENTRY_EXPORT.symbols = []
    pe.sections = []
    pe.get_imphash.return_value = "a" * 32
    return pe


@pytest.fixture
def mock_parse(mock_pe: MagicMock) -> MagicMock:
    """mock pe_api.parse 返回 mock PE。"""
    with patch("winreverse.engine.tools.pe_tools.pe_api.parse", return_value=mock_pe) as m:
        yield m


class TestPEParseTool:
    """pe.parse 工具测试。"""

    def test_success(self, mock_parse: MagicMock, mock_pe: MagicMock) -> None:
        """成功解析 PE 文件。"""
        mock_pe.DIRECTORY_ENTRY_IMPORT = [MagicMock(dll=b"kernel32.dll", imports=[])]
        mock_pe.sections = [MagicMock()]

        tool = PEParseTool()
        result = tool.execute({"file_path": "test.exe"})

        assert result["status"] == "success"
        assert result["entry_point"] == 4096
        assert result["is_64bit"] is True
        assert result["imphash"] == "a" * 32
        assert result["num_sections"] == 1
        assert result["num_imports"] == 0
        mock_parse.assert_called_once_with("test.exe")

    def test_missing_file_path(self) -> None:
        """缺少 file_path 参数时返回 error。"""
        tool = PEParseTool()
        result = tool.execute({})
        assert result["status"] == "error"
        assert "file_path" in result["error_message"]

    def test_parse_failure(self, mock_parse: MagicMock) -> None:
        """parse 抛异常时返回 error。"""
        mock_parse.side_effect = OSError("文件不存在")
        tool = PEParseTool()
        result = tool.execute({"file_path": "nonexistent.exe"})
        assert result["status"] == "error"
        assert "文件不存在" in result["error_message"]


class TestPEImportsTool:
    """pe.imports 工具测试。"""

    def test_success(self, mock_parse: MagicMock, mock_pe: MagicMock) -> None:
        """成功查询导入表。"""
        imp_entry = MagicMock()
        imp_entry.dll = b"kernel32.dll"
        imp = MagicMock()
        imp.name = b"CreateFileA"
        imp.ordinal = 1
        imp_entry.imports = [imp]
        mock_pe.DIRECTORY_ENTRY_IMPORT = [imp_entry]

        tool = PEImportsTool()
        result = tool.execute({"file_path": "test.exe"})

        assert result["status"] == "success"
        assert result["count"] == 1
        assert result["imports"][0]["dll"] == "kernel32.dll"
        assert result["imports"][0]["name"] == "CreateFileA"

    def test_missing_file_path(self) -> None:
        """缺少参数时返回 error。"""
        tool = PEImportsTool()
        result = tool.execute({})
        assert result["status"] == "error"


class TestPEExportsTool:
    """pe.exports 工具测试。"""

    def test_success(self, mock_parse: MagicMock, mock_pe: MagicMock) -> None:
        """成功查询导出表。"""
        exp = MagicMock()
        exp.name = b"TestExport"
        exp.ordinal = 5
        mock_pe.DIRECTORY_ENTRY_EXPORT.symbols = [exp]

        tool = PEExportsTool()
        result = tool.execute({"file_path": "test.exe"})

        assert result["status"] == "success"
        assert result["count"] == 1
        assert result["exports"][0]["name"] == "TestExport"
        assert result["exports"][0]["ordinal"] == 5

    def test_missing_file_path(self) -> None:
        """缺少参数时返回 error。"""
        tool = PEExportsTool()
        result = tool.execute({})
        assert result["status"] == "error"


class TestPESectionsTool:
    """pe.sections 工具测试。"""

    def test_success(self, mock_parse: MagicMock, mock_pe: MagicMock) -> None:
        """成功查询节区。"""
        section = MagicMock()
        section.Name = b".text\x00\x00\x00"
        section.Misc_VirtualSize = 4096
        section.VirtualAddress = 4096
        section.SizeOfRawData = 2048
        section.Characteristics = 0x60000020
        mock_pe.sections = [section]

        tool = PESectionsTool()
        result = tool.execute({"file_path": "test.exe"})

        assert result["status"] == "success"
        assert result["count"] == 1
        assert result["sections"][0]["name"] == ".text"
        assert result["sections"][0]["virtual_size"] == 4096

    def test_missing_file_path(self) -> None:
        """缺少参数时返回 error。"""
        tool = PESectionsTool()
        result = tool.execute({})
        assert result["status"] == "error"


class TestPESuspiciousImportsTool:
    """pe.suspicious_imports 工具测试。"""

    def test_success_with_suspicious(self, mock_parse: MagicMock, mock_pe: MagicMock) -> None:
        """检测到可疑导入。"""
        imp_entry = MagicMock()
        imp_entry.dll = b"kernel32.dll"
        imp = MagicMock()
        imp.name = b"WriteProcessMemory"
        imp_entry.imports = [imp]
        mock_pe.DIRECTORY_ENTRY_IMPORT = [imp_entry]

        tool = PESuspiciousImportsTool()
        result = tool.execute({"file_path": "test.exe"})

        assert result["status"] == "success"
        assert "WriteProcessMemory" in result["suspicious"]

    def test_success_no_suspicious(self, mock_parse: MagicMock, mock_pe: MagicMock) -> None:
        """无可疑导入时返回空列表。"""
        mock_pe.DIRECTORY_ENTRY_IMPORT = []

        tool = PESuspiciousImportsTool()
        result = tool.execute({"file_path": "test.exe"})

        assert result["status"] == "success"
        assert result["suspicious"] == []
        assert result["count"] == 0

    def test_missing_file_path(self) -> None:
        """缺少参数时返回 error。"""
        tool = PESuspiciousImportsTool()
        result = tool.execute({})
        assert result["status"] == "error"


class TestPEMetaTool:
    """pe.meta 工具测试。"""

    def test_success(self, mock_parse: MagicMock) -> None:
        """成功获取元信息。"""
        tool = PEMetaTool()
        result = tool.execute({"file_path": "test.exe"})

        assert result["status"] == "success"
        assert result["entry_point"] == 4096
        assert result["is_64bit"] is True
        assert result["imphash"] == "a" * 32

    def test_missing_file_path(self) -> None:
        """缺少参数时返回 error。"""
        tool = PEMetaTool()
        result = tool.execute({})
        assert result["status"] == "error"


class TestPEToolsList:
    """PE_TOOLS 列表测试。"""

    def test_all_tools_registered(self) -> None:
        """PE_TOOLS 应包含 6 个工具。"""
        assert len(PE_TOOLS) == 6

    def test_tool_names(self) -> None:
        """工具名应符合命名规范。"""
        names = [t.name for t in PE_TOOLS]
        assert "pe.parse" in names
        assert "pe.imports" in names
        assert "pe.exports" in names
        assert "pe.sections" in names
        assert "pe.suspicious_imports" in names
        assert "pe.meta" in names
