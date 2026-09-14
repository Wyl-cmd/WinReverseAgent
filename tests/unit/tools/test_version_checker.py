"""测试模块：winreverse.tools.version_checker（ToolChecker / WheelChecker / VersionChecker）。

覆盖：tmp manifest 驱动的 ok / missing / sha256_mismatch / sha256_empty /
not_importable / KeyError / 非法 manifest 异常路径，报告聚合属性
（overall / passed / missing_tools / mismatched_tools / empty_sha256_tools）
与 VersionChecker 统一入口的 severity 归并逻辑。全程不依赖仓库内真实
manifest 与网络，Linux/Windows 均可运行。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

from winreverse.tools.version_checker import (
    ToolChecker,
    VersionChecker,
    WheelChecker,
)

TOOL_PAYLOAD = b"fake tshark.exe payload"
WHEEL_PAYLOAD = b"fake wheel payload"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_tool(
    root: Path,
    *,
    name: str = "tshark",
    sha256: str = "",
    required: bool = True,
    install: bool = True,
    version: str = "4.6.7",
) -> Path:
    """在 tmp 根下构造 tools/manifest.yaml + 可选的 entry 文件。"""
    if install:
        entry = root / "tools" / name / f"{name}.exe"
        entry.parent.mkdir(parents=True, exist_ok=True)
        entry.write_bytes(TOOL_PAYLOAD)
    manifest = root / "manifest.yaml"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        'schema_version: "1.0"',
        "tools:",
        f"  - name: {name}",
        f'    version: "{version}"',
        f'    install_path: "tools/{name}/"',
        f'    entry: "{name}.exe"',
    ]
    if sha256:
        lines.append(f'    sha256: "{sha256}"')
    else:
        lines.append('    sha256: ""')
    lines.append(f"    required: {'true' if required else 'false'}")
    manifest.write_text("\n".join(lines), encoding="utf-8")
    return manifest


def _write_wheel_manifest(
    root: Path,
    *,
    name: str = "pymem",
    sha256: str = "",
    required: bool = True,
    import_name: str | None = None,
    install: bool = True,
    wheel_file: str = "pymem-1.14.0-py3-none-any.whl",
) -> tuple[Path, Path]:
    """在 tmp 根下构造 wheels_manifest.yaml + 可选的 wheel 文件，返回 (manifest, wheels_dir)。"""
    wheels_dir = root / "wheels"
    if install:
        wheels_dir.mkdir(parents=True, exist_ok=True)
        (wheels_dir / wheel_file).write_bytes(WHEEL_PAYLOAD)
    entry: dict[str, object] = {
        "name": name,
        "version": "1.14.0",
        "wheel_file": wheel_file,
        "sha256": sha256,
        "required": required,
    }
    if import_name is not None:
        entry["import_name"] = import_name
    manifest = root / "wheels_manifest.yaml"
    manifest.write_text(
        yaml.safe_dump({"wheels": [entry]}, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return manifest, wheels_dir


class TestToolChecker:
    """ToolChecker：单工具四态校验 + 异常路径。"""

    def test_ok_with_matching_sha256(self, tmp_path: Path) -> None:
        """entry 存在且 SHA256 匹配 → ok，report 整体 ok / passed。"""
        checker = ToolChecker(
            manifest_path=_write_tool(tmp_path, sha256=_sha256(TOOL_PAYLOAD)),
            project_root=tmp_path,
        )
        result = checker.check_tool("tshark")
        assert result.status == "ok"
        assert result.actual_sha256 == _sha256(TOOL_PAYLOAD)
        report = checker.check_all()
        assert report.overall == "ok"
        assert report.passed is True

    def test_sha256_match_is_case_insensitive(self, tmp_path: Path) -> None:
        """manifest 中大写 SHA256 也应匹配（比对双方统一小写）。"""
        checker = ToolChecker(
            manifest_path=_write_tool(tmp_path, sha256=_sha256(TOOL_PAYLOAD).upper()),
            project_root=tmp_path,
        )
        assert checker.check_tool("tshark").status == "ok"

    def test_sha256_mismatch_required_is_error(self, tmp_path: Path) -> None:
        """必选工具 SHA256 不匹配 → error / passed=False，且进 mismatched_tools。"""
        checker = ToolChecker(
            manifest_path=_write_tool(tmp_path, sha256="0" * 64),
            project_root=tmp_path,
        )
        result = checker.check_tool("tshark")
        assert result.status == "sha256_mismatch"
        report = checker.check_all()
        assert report.overall == "error"
        assert report.passed is False
        assert [r.name for r in report.mismatched_tools] == ["tshark"]

    def test_sha256_mismatch_optional_is_warn(self, tmp_path: Path) -> None:
        """可选工具 SHA256 不匹配只降级为 warn，不阻塞 passed。"""
        checker = ToolChecker(
            manifest_path=_write_tool(tmp_path, sha256="0" * 64, required=False),
            project_root=tmp_path,
        )
        report = checker.check_all()
        assert report.overall == "warn"
        assert report.passed is True

    def test_missing_entry(self, tmp_path: Path) -> None:
        """entry 文件不存在 → missing，actual_sha256 为 None。"""
        checker = ToolChecker(
            manifest_path=_write_tool(tmp_path, sha256=_sha256(TOOL_PAYLOAD), install=False),
            project_root=tmp_path,
        )
        result = checker.check_tool("tshark")
        assert result.status == "missing"
        assert result.actual_sha256 is None
        report = checker.check_all()
        assert report.overall == "error"
        assert [r.name for r in report.missing_tools] == ["tshark"]

    def test_sha256_empty_only_checks_existence(self, tmp_path: Path) -> None:
        """manifest 未填 sha256 → sha256_empty（warn），但仍回填实际哈希。"""
        checker = ToolChecker(
            manifest_path=_write_tool(tmp_path, sha256=""),
            project_root=tmp_path,
        )
        result = checker.check_tool("tshark")
        assert result.status == "sha256_empty"
        assert result.actual_sha256 == _sha256(TOOL_PAYLOAD)
        report = checker.check_all()
        assert report.overall == "warn"
        assert report.passed is True
        assert [r.name for r in report.empty_sha256_tools] == ["tshark"]

    def test_unknown_tool_raises_key_error(self, tmp_path: Path) -> None:
        """未登记的工具名 → KeyError。"""
        checker = ToolChecker(
            manifest_path=_write_tool(tmp_path, sha256=_sha256(TOOL_PAYLOAD)),
            project_root=tmp_path,
        )
        with pytest.raises(KeyError, match="未在 manifest 中登记"):
            checker.check_tool("nope")

    def test_manifest_not_a_dict_raises_value_error(self, tmp_path: Path) -> None:
        """manifest 顶层为列表 → ValueError。"""
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text("- a\n- b\n", encoding="utf-8")
        checker = ToolChecker(manifest_path=manifest, project_root=tmp_path)
        with pytest.raises(ValueError, match="顶层应为字典"):
            checker._load_manifest()

    def test_manifest_missing_raises_file_not_found(self, tmp_path: Path) -> None:
        """manifest 文件不存在 → FileNotFoundError。"""
        checker = ToolChecker(manifest_path=tmp_path / "nope.yaml", project_root=tmp_path)
        with pytest.raises(FileNotFoundError):
            checker._load_manifest()


class TestWheelChecker:
    """WheelChecker：缺失 / 哈希不符 / import 校验路径。"""

    def test_missing_wheel(self, tmp_path: Path) -> None:
        manifest, wheels_dir = _write_wheel_manifest(
            tmp_path, sha256=_sha256(WHEEL_PAYLOAD), install=False
        )
        report = WheelChecker(wheels_manifest=manifest, wheels_dir=wheels_dir).check_all()
        assert report.results[0].status == "missing"
        assert report.overall == "error"  # 必选缺失
        assert report.missing_wheels[0].name == "pymem"

    def test_sha256_mismatch(self, tmp_path: Path) -> None:
        manifest, wheels_dir = _write_wheel_manifest(tmp_path, sha256="f" * 64)
        report = WheelChecker(wheels_manifest=manifest, wheels_dir=wheels_dir).check_all()
        assert report.results[0].status == "sha256_mismatch"
        assert report.mismatched_wheels, "应进入 mismatched_wheels 列表"

    def test_ok(self, tmp_path: Path) -> None:
        manifest, wheels_dir = _write_wheel_manifest(tmp_path, sha256=_sha256(WHEEL_PAYLOAD))
        report = WheelChecker(wheels_manifest=manifest, wheels_dir=wheels_dir).check_all()
        assert report.results[0].status == "ok"
        assert report.passed is True

    def test_optional_missing_is_only_warn_level(self, tmp_path: Path) -> None:
        """可选 wheel 缺失不算失败：overall 仍为 ok（该报告无 warn 级）、passed=True，
        缺失仅体现在 results / missing_wheels 中。"""
        manifest, wheels_dir = _write_wheel_manifest(
            tmp_path, sha256=_sha256(WHEEL_PAYLOAD), required=False, install=False
        )
        report = WheelChecker(wheels_manifest=manifest, wheels_dir=wheels_dir).check_all()
        assert report.overall == "ok"
        assert report.passed is True
        assert [r.name for r in report.missing_wheels] == ["pymem"]

    def test_not_importable_via_real_importlib(self, tmp_path: Path) -> None:
        """check_importable=True + 不存在的模块名 → not_importable（真实 importlib 路径）。"""
        manifest, wheels_dir = _write_wheel_manifest(
            tmp_path,
            sha256=_sha256(WHEEL_PAYLOAD),
            import_name="no_such_module_winreverse_test",
        )
        checker = WheelChecker(
            wheels_manifest=manifest, wheels_dir=wheels_dir, check_importable=True
        )
        assert checker.check_wheel("pymem").status == "not_importable"

    def test_unknown_wheel_raises_key_error(self, tmp_path: Path) -> None:
        manifest, wheels_dir = _write_wheel_manifest(tmp_path, sha256=_sha256(WHEEL_PAYLOAD))
        checker = WheelChecker(wheels_manifest=manifest, wheels_dir=wheels_dir)
        with pytest.raises(KeyError, match="未在 manifest 中登记"):
            checker.check_wheel("nope")


class TestVersionChecker:
    """VersionChecker：wheel + 工具 severity 归并（error > warn > ok）。"""

    def _tool_ok(self, tmp_path: Path) -> ToolChecker:
        return ToolChecker(
            manifest_path=_write_tool(tmp_path / "t", sha256=_sha256(TOOL_PAYLOAD)),
            project_root=tmp_path / "t",
        )

    def test_all_ok(self, tmp_path: Path) -> None:
        manifest, wheels_dir = _write_wheel_manifest(tmp_path, sha256=_sha256(WHEEL_PAYLOAD))
        checker = VersionChecker(
            wheels_manifest=manifest,
            wheels_dir=wheels_dir,
            tools_manifest=_write_tool(tmp_path / "t", sha256=_sha256(TOOL_PAYLOAD)),
            project_root=tmp_path / "t",
        )
        report = checker.check_all()
        assert report.overall == "ok"
        assert report.passed is True
        assert report.wheel_report.results[0].status == "ok"
        assert report.tool_report.results[0].status == "ok"
        # 单项入口与 check_all 一致
        assert checker.check_wheels().results[0].status == "ok"
        assert checker.check_tools().results[0].status == "ok"

    def test_tool_error_dominates_wheel_ok(self, tmp_path: Path) -> None:
        manifest, wheels_dir = _write_wheel_manifest(tmp_path, sha256=_sha256(WHEEL_PAYLOAD))
        checker = VersionChecker(
            wheels_manifest=manifest,
            wheels_dir=wheels_dir,
            tools_manifest=_write_tool(tmp_path / "t", sha256=_sha256(TOOL_PAYLOAD), install=False),
            project_root=tmp_path / "t",
        )
        report = checker.check_all()
        assert report.overall == "error"
        assert report.passed is False

    def test_wheel_error_dominates_tool_ok(self, tmp_path: Path) -> None:
        manifest, wheels_dir = _write_wheel_manifest(
            tmp_path, sha256=_sha256(WHEEL_PAYLOAD), install=False
        )
        tools_manifest = _write_tool(tmp_path / "t", sha256=_sha256(TOOL_PAYLOAD))
        checker = VersionChecker(
            wheels_manifest=manifest,
            wheels_dir=wheels_dir,
            tools_manifest=tools_manifest,
            project_root=tmp_path / "t",
        )
        assert checker.check_all().overall == "error"

    def test_warn_severity_from_either_side(self, tmp_path: Path) -> None:
        """wheel ok + 工具 sha256_empty → warn；两侧取较严重者。"""
        manifest, wheels_dir = _write_wheel_manifest(tmp_path, sha256=_sha256(WHEEL_PAYLOAD))
        checker = VersionChecker(
            wheels_manifest=manifest,
            wheels_dir=wheels_dir,
            tools_manifest=_write_tool(tmp_path / "t", sha256=""),
            project_root=tmp_path / "t",
        )
        report = checker.check_all()
        assert report.overall == "warn"
        assert report.passed is True
