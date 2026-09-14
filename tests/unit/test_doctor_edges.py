"""测试模块：winreverse.doctor 边界分支（独立新文件，不动既有 test_doctor*.py）。

覆盖点：_check_python_version 旧版本 error、_check_wheels/_check_tools 空清单
error、_check_tools 全通过 ok 与可选 SHA256 不匹配 warn、_check_tool_updates
解析失败 warn。全 stub 驱动、不依赖仓库根 tools/manifest.yaml，平台无关。
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from winreverse.doctor import (
    _check_python_version,
    _check_tool_updates,
    _check_tools,
    _check_wheels,
)


class TestCheckPythonVersion:
    """_check_python_version 的旧版本分支。"""

    def test_old_python_is_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Python < 3.12 → error，消息含实际版本号。"""
        monkeypatch.setattr("winreverse.doctor.sys.version_info", (3, 11, 9, "final", 0))
        result = _check_python_version()
        assert result.status == "error"
        assert "3.11.9" in result.message
        assert "3.12" in result.detail


class TestCheckWheelsEmpty:
    """_check_wheels 的空清单分支。"""

    def test_empty_manifest_report_is_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """WheelChecker 返回 0 条目 → error「清单为空」。"""
        from winreverse.tools import version_checker

        class _StubWheelChecker:
            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            def check_all(self) -> SimpleNamespace:
                return SimpleNamespace(
                    results=[],
                    passed=False,
                    missing_wheels=[],
                    mismatched_wheels=[],
                )

        monkeypatch.setattr(version_checker, "WheelChecker", _StubWheelChecker)
        with patch.object(Path, "exists", return_value=True):
            result = _check_wheels()
        assert result.status == "error"
        assert "清单为空" in result.message


class TestCheckToolsEdges:
    """_check_tools 的空清单 / 全通过 / 可选不匹配分支。"""

    @staticmethod
    def _patch_stub_checker(
        monkeypatch: pytest.MonkeyPatch,
        results: list[SimpleNamespace],
        mismatched: list[SimpleNamespace],
    ) -> None:
        """ToolChecker 替身（_check_tools 函数内延迟导入，模块级替换生效）。"""
        from winreverse.tools import version_checker

        class _StubToolChecker:
            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            def check_all(self) -> SimpleNamespace:
                return SimpleNamespace(
                    results=results,
                    missing_tools=[r for r in results if r.status == "missing"],
                    mismatched_tools=mismatched,
                    empty_sha256_tools=[],
                )

        monkeypatch.setattr(version_checker, "ToolChecker", _StubToolChecker)

    @staticmethod
    def _tool_result(status: str = "ok", required: bool = True) -> SimpleNamespace:
        return SimpleNamespace(name="tshark", version="4.6.7", status=status, required=required)

    def test_empty_manifest_report_is_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """0 个工具条目 → error「清单为空（0 个工具条目）」。"""
        self._patch_stub_checker(monkeypatch, [], [])
        with patch.object(Path, "exists", return_value=True):
            result = _check_tools()
        assert result.status == "error"
        assert "清单为空（0 个工具条目）" in result.message

    def test_all_tools_ok_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """全部 ok → status ok，消息标注 3/3。"""
        self._patch_stub_checker(monkeypatch, [self._tool_result() for _ in range(3)], [])
        with patch.object(Path, "exists", return_value=True):
            result = _check_tools()
        assert result.status == "ok"
        assert result.message.startswith("3/3")

    def test_optional_sha256_mismatch_is_warn(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """可选工具 SHA256 不匹配 → 仅 warn，detail 标注「可选 SHA256 不匹配」。"""
        mismatched = [self._tool_result(status="sha256_mismatch", required=False)]
        self._patch_stub_checker(
            monkeypatch,
            [self._tool_result(), *mismatched],
            mismatched,
        )
        with patch.object(Path, "exists", return_value=True):
            result = _check_tools()
        assert result.status == "warn"
        assert "可选 SHA256 不匹配" in result.detail
        assert "tshark==4.6.7" in result.detail


class TestCheckToolUpdatesParseFailure:
    """_check_tool_updates 的解析失败分支。"""

    def test_updater_raising_is_warn(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ToolUpdater 构造抛 ValueError → warn「更新检查失败」。"""
        from winreverse.tools import updater as updater_module

        def broken_init(self: object, *args: object, **kwargs: object) -> None:
            raise ValueError("boom: manifest 结构非法")

        monkeypatch.setattr(updater_module.ToolUpdater, "__init__", broken_init)
        with patch.object(Path, "exists", return_value=True):
            result = _check_tool_updates()
        assert result.status == "warn"
        assert "更新检查失败" in result.message
        assert "boom" in result.detail
