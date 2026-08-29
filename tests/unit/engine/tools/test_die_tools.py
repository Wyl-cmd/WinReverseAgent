"""测试模块：winreverse.engine.tools.die_tools

测试 DIE 扫描工具。
"""

from __future__ import annotations

import base64
from typing import Any
from unittest.mock import patch

import pytest

from winreverse.engine.tools.die_tools import (
    DIE_TOOLS,
    DieScanFileTool,
    DieScanMemoryTool,
)


@pytest.fixture
def mock_die_result() -> dict[str, Any]:
    """mock 的 DIE 扫描结果。"""
    return {"detects": [{"name": "UPX", "version": "4.2", "type": "packer"}]}


class TestDieScanFileTool:
    """die.scan_file 工具测试。"""

    def test_success(self, mock_die_result: dict[str, Any]) -> None:
        """成功扫描文件。"""
        with (
            patch(
                "winreverse.engine.tools.die_tools.die_api.scan_file",
                return_value=mock_die_result,
            ),
            patch(
                "winreverse.engine.tools.die_tools.die_api.get_version",
                return_value="3.21",
            ),
        ):
            tool = DieScanFileTool()
            result = tool.execute({"file_path": "test.exe"})

        assert result["status"] == "success"
        assert result["result"] == mock_die_result
        assert result["version"] == "3.21"

    def test_with_options(self, mock_die_result: dict[str, Any]) -> None:
        """带扫描选项。"""
        with (
            patch(
                "winreverse.engine.tools.die_tools.die_api.scan_file",
                return_value=mock_die_result,
            ) as mock_scan,
            patch(
                "winreverse.engine.tools.die_tools.die_api.get_version",
                return_value="3.21",
            ),
        ):
            tool = DieScanFileTool()
            result = tool.execute(
                {
                    "file_path": "test.exe",
                    "deep": True,
                    "heuristic": True,
                    "recursive": True,
                }
            )

        assert result["status"] == "success"
        mock_scan.assert_called_once_with("test.exe", True, True, True)

    def test_missing_file_path(self) -> None:
        """缺少 file_path 参数时返回 error。"""
        tool = DieScanFileTool()
        result = tool.execute({})
        assert result["status"] == "error"
        assert "file_path" in result["error_message"]

    def test_scan_failure(self) -> None:
        """扫描失败时返回 error。"""
        with patch(
            "winreverse.engine.tools.die_tools.die_api.scan_file",
            side_effect=RuntimeError("DIE 扫描失败"),
        ):
            tool = DieScanFileTool()
            result = tool.execute({"file_path": "nonexistent.exe"})

        assert result["status"] == "error"
        assert "扫描失败" in result["error_message"]


class TestDieScanMemoryTool:
    """die.scan_memory 工具测试。"""

    def test_success_with_base64(self, mock_die_result: dict[str, Any]) -> None:
        """成功扫描 base64 编码数据。"""
        data_b64 = base64.b64encode(b"MZ test").decode("ascii")
        with (
            patch(
                "winreverse.engine.tools.die_tools.die_api.scan_bytes",
                return_value=mock_die_result,
            ),
            patch(
                "winreverse.engine.tools.die_tools.die_api.get_version",
                return_value="3.21",
            ),
        ):
            tool = DieScanMemoryTool()
            result = tool.execute({"data": data_b64})

        assert result["status"] == "success"
        assert result["result"] == mock_die_result

    def test_success_with_bytes(self, mock_die_result: dict[str, Any]) -> None:
        """成功扫描 bytes 输入。"""
        with (
            patch(
                "winreverse.engine.tools.die_tools.die_api.scan_bytes",
                return_value=mock_die_result,
            ),
            patch(
                "winreverse.engine.tools.die_tools.die_api.get_version",
                return_value="3.21",
            ),
        ):
            tool = DieScanMemoryTool()
            result = tool.execute({"data": b"MZ test"})

        assert result["status"] == "success"

    def test_missing_data(self) -> None:
        """缺少 data 参数时返回 error。"""
        tool = DieScanMemoryTool()
        result = tool.execute({})
        assert result["status"] == "error"
        assert "data" in result["error_message"]


class TestDieToolsList:
    """DIE_TOOLS 列表测试。"""

    def test_registered(self) -> None:
        """DIE_TOOLS 应包含 2 个工具。"""
        assert len(DIE_TOOLS) == 2
        names = [t.name for t in DIE_TOOLS]
        assert "die.scan_file" in names
        assert "die.scan_memory" in names
