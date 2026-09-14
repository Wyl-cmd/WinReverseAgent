"""测试模块：winreverse.doctor 分支密闭覆盖（独立新文件，不动既有 test_doctor.py）。

覆盖（全部全 mock 驱动、不依赖仓库根的 tools/manifest.yaml，平台无关）：
- _check_tools 必选/可选缺失分类与解析异常分支
- _check_wheels 的 manifest 读取失败分支
- print_report 输出渲染与 win32 stdout 重配置分支
- main() 退出码映射（ok→0 / warn→1 / error→2）

注：ToolChecker.__init__ 会立刻打开 entry 计算 SHA256，「entry 缺失」场景
无法用真实 ToolChecker 表达（__init__ 直接抛 FileNotFoundError），故缺失
场景用 stub checker 驱动 doctor 的分类逻辑（被测对象是 _check_tools 本身）；
manifest 存在性检查以 patch.object(Path, "exists") 放行，使密闭 stub 生效
（Windows 实机有真实 manifest 时行为一致，均由 stub 决定结果）。
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from winreverse.doctor import CheckResult, DoctorReport, _check_tools, _check_wheels


class TestCheckToolsBranches:
    """_check_tools 必选/可选缺失分类与解析异常分支（密闭，不依赖真实仓库）。"""

    @staticmethod
    def _patch_stub_checker(
        monkeypatch: pytest.MonkeyPatch, results: list[SimpleNamespace]
    ) -> None:
        """把 ToolChecker 替换为返回固定结果的 stub（_check_tools 函数内延迟导入，
        调用时从 version_checker 模块属性解析，故模块级替换生效）。"""
        from winreverse.tools import version_checker

        class _StubToolChecker:
            def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
                pass

            def check_all(self):  # type: ignore[no-untyped-def]
                return SimpleNamespace(
                    results=results,
                    missing_tools=[r for r in results if r.status == "missing"],
                    mismatched_tools=[r for r in results if r.status == "sha256_mismatch"],
                    empty_sha256_tools=[],
                )

        monkeypatch.setattr(version_checker, "ToolChecker", _StubToolChecker)

    @staticmethod
    def _tool_result(status: str, required: bool) -> SimpleNamespace:
        return SimpleNamespace(name="tshark", version="4.6.7", status=status, required=required)

    def test_required_tool_missing_is_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """必选工具缺失 → error，detail 标注「必选缺失」并列出 name==version。"""
        self._patch_stub_checker(monkeypatch, [self._tool_result("missing", required=True)])
        with patch.object(Path, "exists", return_value=True):
            result = _check_tools()
        assert result.status == "error"
        assert "必选缺失" in result.detail
        assert "tshark==4.6.7" in result.detail

    def test_optional_tool_missing_is_warn(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """可选工具缺失 → 仅 warn，detail 标注「可选缺失」，不阻塞。"""
        self._patch_stub_checker(monkeypatch, [self._tool_result("missing", required=False)])
        with patch.object(Path, "exists", return_value=True):
            result = _check_tools()
        assert result.status == "warn"
        assert "可选缺失" in result.detail

    def test_required_sha256_mismatch_is_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """必选工具 SHA256 不匹配 → error，detail 标注「必选 SHA256 不匹配」。"""
        self._patch_stub_checker(monkeypatch, [self._tool_result("sha256_mismatch", required=True)])
        with patch.object(Path, "exists", return_value=True):
            result = _check_tools()
        assert result.status == "error"
        assert "必选 SHA256 不匹配" in result.detail

    def test_tool_checker_raising_is_reported_as_parse_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ToolChecker 构造/校验抛 OSError/ValueError → error「manifest 解析失败」。"""
        from winreverse.tools import version_checker

        def broken_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            raise FileNotFoundError("boom: manifest 不可读")

        monkeypatch.setattr(version_checker.ToolChecker, "__init__", broken_init)
        with patch.object(Path, "exists", return_value=True):
            result = _check_tools()
        assert result.status == "error"
        assert "manifest 解析失败" in result.message
        assert "boom" in result.detail


class TestCheckWheelsParseFailure:
    """_check_wheels 的 manifest 读取失败分支。"""

    def test_unreadable_manifest_is_parse_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """manifest 存在性检查放行但实际不可读 → error「manifest 解析失败」。"""
        from winreverse.tools import version_checker

        original_init = version_checker.WheelChecker.__init__

        def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            kwargs["wheels_manifest"] = tmp_path / "wheels_manifest.yaml"  # 不存在
            kwargs["wheels_dir"] = tmp_path / "wheels"
            kwargs["check_importable"] = False
            return original_init(self, *args, **kwargs)

        monkeypatch.setattr(version_checker.WheelChecker, "__init__", patched_init)
        with patch.object(Path, "exists", return_value=True):
            result = _check_wheels()
        assert result.status == "error"
        assert "manifest 解析失败" in result.message


class TestPrintReport:
    """print_report 输出渲染与 Windows UTF-8 重配置分支。"""

    @staticmethod
    def _report(status: str) -> DoctorReport:
        return DoctorReport(checks=[CheckResult(name="示例检查", status=status, message="msg")])

    def _render(self, report: DoctorReport, monkeypatch: pytest.MonkeyPatch) -> str:
        import io

        buffer = io.StringIO()
        monkeypatch.setattr("sys.stdout", buffer)
        from winreverse.doctor import print_report

        print_report(report)
        return buffer.getvalue()

    def test_ok_report_prints_pass_summary(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """全部 ok 时输出表格与「全部检查通过」。"""
        out = self._render(self._report("ok"), monkeypatch)
        assert "WinReverseAgent 环境自检报告" in out
        assert "示例检查" in out
        assert "全部检查通过" in out

    def test_warn_report_prints_warning_summary(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """warn 时输出「存在警告项」。"""
        out = self._render(self._report("warn"), monkeypatch)
        assert "存在警告项" in out

    def test_error_report_prints_failure_summary(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """error 时输出「存在错误项」。"""
        out = self._render(self._report("error"), monkeypatch)
        assert "存在错误项" in out

    def test_win32_reconfigures_stdout_utf8(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """win32 下打印前把 stdout 重配置为 UTF-8 + replace。"""
        import io
        import sys

        calls: list[dict[str, str]] = []

        class _Stream:
            def reconfigure(self, **kwargs: str) -> None:
                calls.append(kwargs)

        class _CaptureStream(_Stream):
            def __init__(self) -> None:
                self.buffer = io.StringIO()

            def write(self, text: str) -> int:
                return self.buffer.write(text)

            def flush(self) -> None:
                self.buffer.flush()

        capture = _CaptureStream()
        monkeypatch.setattr(sys, "platform", "win32")
        # print_report 内 Console() 取当前 sys.stdout；捕获流同时支持重配置
        monkeypatch.setattr("sys.stdout", capture)
        from winreverse.doctor import print_report

        print_report(self._report("ok"))
        assert calls == [{"encoding": "utf-8", "errors": "replace"}]
        assert "全部检查通过" in capture.buffer.getvalue()


class TestMainExitCodes:
    """main() 退出码映射：ok→0 / warn→1 / error→2。"""

    def _run_main(self, monkeypatch: pytest.MonkeyPatch, status: str, tmp_path: Path) -> int:
        import io

        monkeypatch.setattr("sys.stdout", io.StringIO())
        monkeypatch.setattr(
            "winreverse.doctor.run_all_checks", lambda: _single_check_report(status)
        )
        from winreverse.doctor import main as doctor_main

        return doctor_main()

    def test_ok_returns_zero(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        assert self._run_main(monkeypatch, "ok", tmp_path) == 0

    def test_warn_returns_one(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        assert self._run_main(monkeypatch, "warn", tmp_path) == 1

    def test_error_returns_two(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        assert self._run_main(monkeypatch, "error", tmp_path) == 2


def _single_check_report(status: str) -> DoctorReport:
    """构造单检查项报告（TestMainExitCodes / TestPrintReport 用）。"""
    return DoctorReport(checks=[CheckResult(name="示例检查", status=status, message="msg")])
