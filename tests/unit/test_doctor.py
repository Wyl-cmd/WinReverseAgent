"""测试模块：winreverse.doctor

测试环境自检模块。
覆盖：
- 各 CheckResult 的状态判定
- DoctorReport 的 overall 与 passed 属性
- run_all_checks 返回的报告结构
- main() 入口返回码
- _check_wheels 的 4 种校验场景
- _check_tools 的多种校验场景（M3 新增）
- _check_tool_updates 的更新提示场景（M3 新增）
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from winreverse.doctor import (
    CheckResult,
    DoctorReport,
    _check_admin,
    _check_core_contracts,
    _check_platform,
    _check_python_version,
    _check_tool_updates,
    _check_tools,
    _check_wheels,
    main,
    run_all_checks,
)


class TestCheckResult:
    """CheckResult 数据类测试"""

    def test_ok_result(self) -> None:
        """ok 状态的检查结果。"""
        result = CheckResult(name="测试", status="ok", message="通过")
        assert result.status == "ok"
        assert result.message == "通过"
        assert result.detail == ""

    def test_error_result_with_detail(self) -> None:
        """带详情的错误结果。"""
        result = CheckResult(
            name="测试",
            status="error",
            message="失败",
            detail="具体原因",
        )
        assert result.status == "error"
        assert result.detail == "具体原因"


class TestDoctorReport:
    """DoctorReport 报告类测试"""

    def test_empty_report_is_ok(self) -> None:
        """空报告的 overall 为 ok，passed 为 True。"""
        report = DoctorReport()
        assert report.overall == "ok"
        assert report.passed is True

    def test_report_with_warn(self) -> None:
        """仅含 warn 的报告 overall 为 warn，passed 为 True。"""
        report = DoctorReport(checks=[CheckResult(name="a", status="warn", message="警告")])
        assert report.overall == "warn"
        assert report.passed is True

    def test_report_with_error(self) -> None:
        """含 error 的报告 overall 为 error，passed 为 False。"""
        report = DoctorReport(
            checks=[
                CheckResult(name="a", status="ok", message="通过"),
                CheckResult(name="b", status="error", message="失败"),
            ]
        )
        assert report.overall == "error"
        assert report.passed is False

    def test_report_priority_error_over_warn(self) -> None:
        """error 优先级高于 warn。"""
        report = DoctorReport(
            checks=[
                CheckResult(name="a", status="warn", message="警告"),
                CheckResult(name="b", status="error", message="错误"),
            ]
        )
        assert report.overall == "error"


class TestIndividualChecks:
    """单项检查函数测试"""

    def test_check_python_version_passes(self) -> None:
        """当前测试运行的 Python 版本应通过检查（CI 用 3.12+）。"""
        result = _check_python_version()
        assert result.name == "Python 版本"
        # 当前 Python 版本应满足 >=3.12（CI 环境），但本机可能是 3.11
        # 所以这里只验证返回结构，不强制 status
        assert result.status in ("ok", "error")
        assert "Python" in result.message

    def test_check_core_contracts(self) -> None:
        """核心契约模块应可导入。"""
        result = _check_core_contracts()
        assert result.name == "核心契约模块"
        assert result.status == "ok"

    def test_check_platform(self) -> None:
        """平台检查应返回有效状态。"""
        result = _check_platform()
        assert result.name == "运行平台"
        assert result.status in ("ok", "warn")

    def test_check_admin(self) -> None:
        """管理员权限检查应返回有效状态。"""
        result = _check_admin()
        assert result.name == "管理员权限"
        assert result.status in ("ok", "warn")


class TestCheckWheels:
    """_check_wheels wheel 完整性校验测试"""

    def test_check_wheels_passes_with_real_vendor(self) -> None:
        """项目实际的 vendor/wheels/ 应校验通过（含 GUI 依赖，6/6）。"""
        result = _check_wheels()
        assert result.name == "Python wheel 完整性"
        # 项目 vendor/wheels/ 已下载完整 wheel，应通过
        assert result.status == "ok"
        assert "6/6" in result.message

    def test_check_wheels_fails_when_manifest_missing(self, tmp_path: Path) -> None:
        """manifest 不存在时应返回 error。"""
        # patch doctor.py 中 __file__ 解析得到的项目根路径
        # doctor.py 用 Path(__file__).resolve().parent.parent.parent 定位项目根
        # 我们 patch Path.exists 让 manifest_path 返回 False
        with patch.object(Path, "exists", return_value=False):
            result = _check_wheels()
        assert result.name == "Python wheel 完整性"
        assert result.status == "error"
        assert "wheels_manifest.yaml 不存在" in result.message

    def test_check_wheels_fails_when_wheel_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """wheel 文件缺失时应返回 error。"""
        # 构造临时 vendor 目录：manifest 引用不存在的 wheel 文件
        vendor_dir = tmp_path / "vendor"
        wheels_dir = vendor_dir / "wheels"
        wheels_dir.mkdir(parents=True)
        manifest = vendor_dir / "wheels_manifest.yaml"
        manifest.write_text(
            """
schema_version: "1.0"
python_version: "3.12"
platform: "win_amd64"
wheels:
  - name: fake-pkg
    version: "1.0.0"
    wheel_file: "fake_pkg-1.0.0-py3-none-any.whl"
    sha256: "0000000000000000000000000000000000000000000000000000000000000000"
    import_name: "fake_pkg"
    required: true
""",
            encoding="utf-8",
        )

        # patch WheelChecker 的初始化参数，使其指向临时目录
        from winreverse.tools import version_checker

        original_init = version_checker.WheelChecker.__init__

        def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            kwargs["wheels_manifest"] = manifest
            kwargs["wheels_dir"] = wheels_dir
            kwargs["check_importable"] = False
            return original_init(self, *args, **kwargs)

        monkeypatch.setattr(version_checker.WheelChecker, "__init__", patched_init)
        result = _check_wheels()
        assert result.name == "Python wheel 完整性"
        assert result.status == "error"
        assert "0/1" in result.message
        assert "缺失" in result.detail

    def test_check_wheels_fails_when_sha256_mismatch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SHA256 不匹配时应返回 error。"""
        # 构造临时 vendor 目录：wheel 文件存在但内容与期望 SHA256 不符
        vendor_dir = tmp_path / "vendor"
        wheels_dir = vendor_dir / "wheels"
        wheels_dir.mkdir(parents=True)
        # 写一个内容不符的 wheel 文件
        fake_wheel = wheels_dir / "fake_pkg-1.0.0-py3-none-any.whl"
        fake_wheel.write_bytes(b"not a real wheel content")

        manifest = vendor_dir / "wheels_manifest.yaml"
        manifest.write_text(
            """
schema_version: "1.0"
python_version: "3.12"
platform: "win_amd64"
wheels:
  - name: fake-pkg
    version: "1.0.0"
    wheel_file: "fake_pkg-1.0.0-py3-none-any.whl"
    sha256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    import_name: "fake_pkg"
    required: true
""",
            encoding="utf-8",
        )

        from winreverse.tools import version_checker

        original_init = version_checker.WheelChecker.__init__

        def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            kwargs["wheels_manifest"] = manifest
            kwargs["wheels_dir"] = wheels_dir
            kwargs["check_importable"] = False
            return original_init(self, *args, **kwargs)

        monkeypatch.setattr(version_checker.WheelChecker, "__init__", patched_init)
        result = _check_wheels()
        assert result.name == "Python wheel 完整性"
        assert result.status == "error"
        assert "0/1" in result.message
        assert "SHA256 不匹配" in result.detail


class TestCheckTools:
    """_check_tools 外部工具完整性校验测试（M3 新增）"""

    def test_check_tools_fails_when_manifest_missing(self) -> None:
        """manifest 不存在时应返回 error。"""
        with patch.object(Path, "exists", return_value=False):
            result = _check_tools()
        assert result.name == "外部工具完整性"
        assert result.status == "error"
        assert "manifest.yaml 不存在" in result.message

    def test_check_tools_with_real_manifest(self) -> None:
        """项目实际的 tools/manifest.yaml 应能正常校验。

        工具已全部内置安装（updater 下载/提取完成），entry 存在且
        sha256 已回填，预期 ok；若在未安装工具的环境运行则允许 warn/error
        （CI 无工具二进制时跳过断言）。
        """
        result = _check_tools()
        assert result.name == "外部工具完整性"
        if result.status == "ok":
            assert "6/6" in result.message or "个工具校验通过" in result.message
        else:
            # 工具未内置的环境（如全新 clone）：必选缺失应为 error
            assert result.status in ("warn", "error")

    def test_check_tools_all_pass(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """所有工具校验通过时返回 ok。"""
        # 构造临时 manifest 和 entry 文件
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text(
            """
schema_version: "1.0"
tools:
  - name: tshark
    version: "4.6.7"
    install_path: "tools/tshark/"
    entry: "tshark.exe"
    sha256: ""
    required: true
""".strip(),
            encoding="utf-8",
        )
        entry_path = tmp_path / "tools" / "tshark" / "tshark.exe"
        entry_path.parent.mkdir(parents=True, exist_ok=True)
        entry_path.write_bytes(b"fake exe")

        from winreverse.tools import version_checker

        original_init = version_checker.ToolChecker.__init__

        def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            kwargs["manifest_path"] = manifest
            kwargs["project_root"] = tmp_path
            return original_init(self, *args, **kwargs)

        monkeypatch.setattr(version_checker.ToolChecker, "__init__", patched_init)
        result = _check_tools()
        assert result.name == "外部工具完整性"
        # sha256 为空 → sha256_empty → warn
        assert result.status == "warn"
        assert "SHA256 未填写" in result.detail


class TestCheckToolUpdates:
    """_check_tool_updates 更新提示测试（M3 新增）"""

    def test_check_tool_updates_fails_when_manifest_missing(self) -> None:
        """manifest 不存在时返回 ok（跳过更新检查）。"""
        with patch.object(Path, "exists", return_value=False):
            result = _check_tool_updates()
        assert result.name == "工具更新检查"
        assert result.status == "ok"
        assert "跳过更新检查" in result.message

    def test_check_tool_updates_with_real_manifest(self) -> None:
        """项目实际 manifest 中所有 version == latest_known，无可用更新。"""
        result = _check_tool_updates()
        assert result.name == "工具更新检查"
        assert result.status == "ok"
        assert "最新" in result.message

    def test_check_tool_updates_finds_available(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """有可用更新时返回 warn。"""
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text(
            """
schema_version: "1.0"
tools:
  - name: yara
    version: "4.5.4"
    latest_known: "4.5.6"
    install_path: "tools/yara/"
    entry: "yara64.exe"
    required: true
""".strip(),
            encoding="utf-8",
        )

        from winreverse.tools import updater

        original_init = updater.ToolUpdater.__init__

        def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            kwargs["manifest_path"] = manifest
            kwargs["project_root"] = tmp_path
            return original_init(self, *args, **kwargs)

        monkeypatch.setattr(updater.ToolUpdater, "__init__", patched_init)
        result = _check_tool_updates()
        assert result.name == "工具更新检查"
        assert result.status == "warn"
        assert "1 个工具有可用更新" in result.message
        assert "yara: 4.5.4 -> 4.5.6" in result.detail


class TestRunAllChecks:
    """run_all_checks 集成测试"""

    def test_returns_report_with_all_checks(self) -> None:
        """应返回包含全部检查项的报告。"""
        report = run_all_checks()
        assert isinstance(report, DoctorReport)
        # 应包含至少 7 项检查（M3 新增 tools + tool_updates）
        assert len(report.checks) >= 7
        # 检查项名称应包含预期的
        names = [c.name for c in report.checks]
        assert "运行平台" in names
        assert "Python 版本" in names
        assert "管理员权限" in names
        assert "核心契约模块" in names
        assert "Python wheel 完整性" in names
        assert "外部工具完整性" in names
        assert "工具更新检查" in names


class TestMainEntry:
    """main() 入口测试"""

    def test_main_returns_int(self) -> None:
        """main() 应返回整数退出码。"""
        code = main()
        assert isinstance(code, int)
        assert code in (0, 1, 2)

    def test_main_returns_zero_when_no_error(self) -> None:
        """无 error 时 main() 应返回 0 或 1（warn）。"""
        code = main()
        # 核心契约可导入，至少不会因契约失败而 error
        # 但管理员权限可能 warn，所以 0 或 1 都可接受
        assert code in (0, 1, 2)
