"""测试模块：winreverse.engine.tools.yara_tools

测试 YARA 扫描工具。
"""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import pytest

from winreverse.core.yara_api import YaraMatch
from winreverse.engine.tools.yara_tools import (
    YARA_TOOLS,
    YaraScanFileTool,
    YaraScanMemoryTool,
)


@pytest.fixture
def mock_rules() -> MagicMock:
    """mock 的 YARA 规则对象。"""
    return MagicMock()


@pytest.fixture
def mock_match() -> YaraMatch:
    """mock 的 YARA 匹配结果。"""
    return YaraMatch(
        rule="test_rule",
        namespace="default",
        tags=["malware"],
        meta={"author": "test"},
        strings=[],
    )


class TestYaraScanFileTool:
    """yara.scan_file 工具测试。"""

    def test_success(self, mock_rules: MagicMock, mock_match: YaraMatch) -> None:
        """成功扫描文件。"""
        with (
            patch(
                "winreverse.engine.tools.yara_tools.yara_api.compile_source",
                return_value=mock_rules,
            ),
            patch(
                "winreverse.engine.tools.yara_tools.yara_api.scan_file",
                return_value=[mock_match],
            ),
        ):
            tool = YaraScanFileTool()
            result = tool.execute(
                {
                    "rule_text": "rule test { condition: true }",
                    "file_path": "test.exe",
                }
            )

        assert result["status"] == "success"
        assert result["count"] == 1
        assert result["matches"][0]["rule"] == "test_rule"
        assert result["matches"][0]["namespace"] == "default"
        assert "malware" in result["matches"][0]["tags"]

    def test_no_matches(self, mock_rules: MagicMock) -> None:
        """无命中时返回空列表。"""
        with (
            patch(
                "winreverse.engine.tools.yara_tools.yara_api.compile_source",
                return_value=mock_rules,
            ),
            patch(
                "winreverse.engine.tools.yara_tools.yara_api.scan_file",
                return_value=[],
            ),
        ):
            tool = YaraScanFileTool()
            result = tool.execute(
                {
                    "rule_text": "rule test { condition: true }",
                    "file_path": "test.exe",
                }
            )

        assert result["status"] == "success"
        assert result["count"] == 0
        assert result["matches"] == []

    def test_missing_rule_text(self) -> None:
        """缺少 rule_text 参数时返回 error。"""
        tool = YaraScanFileTool()
        result = tool.execute({"file_path": "test.exe"})
        assert result["status"] == "error"
        assert "rule_text" in result["error_message"]

    def test_missing_file_path(self) -> None:
        """缺少 file_path 参数时返回 error。"""
        tool = YaraScanFileTool()
        result = tool.execute({"rule_text": "rule test { condition: true }"})
        assert result["status"] == "error"
        assert "file_path" in result["error_message"]

    def test_compile_error(self) -> None:
        """规则编译失败时返回 error。"""
        with patch(
            "winreverse.engine.tools.yara_tools.yara_api.compile_source",
            side_effect=ValueError("YARA 规则语法错误"),
        ):
            tool = YaraScanFileTool()
            result = tool.execute(
                {
                    "rule_text": "invalid rule",
                    "file_path": "test.exe",
                }
            )

        assert result["status"] == "error"
        assert "语法错误" in result["error_message"]


class TestYaraScanMemoryTool:
    """yara.scan_memory 工具测试。"""

    def test_success_with_base64(self, mock_rules: MagicMock, mock_match: YaraMatch) -> None:
        """成功扫描 base64 编码数据。"""
        data_b64 = base64.b64encode(b"test data").decode("ascii")
        with (
            patch(
                "winreverse.engine.tools.yara_tools.yara_api.compile_source",
                return_value=mock_rules,
            ),
            patch(
                "winreverse.engine.tools.yara_tools.yara_api.scan_bytes",
                return_value=[mock_match],
            ),
        ):
            tool = YaraScanMemoryTool()
            result = tool.execute(
                {
                    "rule_text": "rule test { condition: true }",
                    "data": data_b64,
                }
            )

        assert result["status"] == "success"
        assert result["count"] == 1

    def test_success_with_bytes(self, mock_rules: MagicMock, mock_match: YaraMatch) -> None:
        """成功扫描 bytes 输入。"""
        with (
            patch(
                "winreverse.engine.tools.yara_tools.yara_api.compile_source",
                return_value=mock_rules,
            ),
            patch(
                "winreverse.engine.tools.yara_tools.yara_api.scan_bytes",
                return_value=[mock_match],
            ),
        ):
            tool = YaraScanMemoryTool()
            result = tool.execute(
                {
                    "rule_text": "rule test { condition: true }",
                    "data": b"test data",
                }
            )

        assert result["status"] == "success"

    def test_missing_data(self) -> None:
        """缺少 data 参数时返回 error。"""
        tool = YaraScanMemoryTool()
        result = tool.execute({"rule_text": "rule test { condition: true }"})
        assert result["status"] == "error"
        assert "data" in result["error_message"]


class TestYaraToolsList:
    """YARA_TOOLS 列表测试。"""

    def test_registered(self) -> None:
        """YARA_TOOLS 应包含 2 个工具。"""
        assert len(YARA_TOOLS) == 2
        names = [t.name for t in YARA_TOOLS]
        assert "yara.scan_file" in names
        assert "yara.scan_memory" in names
