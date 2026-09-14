"""被测模块: winreverse.tools.version_checker（WheelChecker / ToolChecker 边界）。

覆盖点: manifest 缺失与非字典顶层的异常路径、verify_sha256 对不存在文件
返回 (False, "")、sha256 未填写的 sha256_empty 分支、check_importable=True
的成功路径、check_all 对单条目 KeyError 的防御性跳过（不中断整批）。
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest
import yaml

from winreverse.tools.version_checker import ToolChecker, WheelChecker


def _write_wheel(tmp_path: Path, content: bytes = b"wheel-bytes") -> tuple[Path, str]:
    """写入一个假 wheel 文件，返回（路径, 实际 sha256 小写十六进制）。"""
    wheels_dir = tmp_path / "wheels"
    wheels_dir.mkdir(exist_ok=True)
    wheel_file = wheels_dir / "pkg-1.0.0-py3-none-any.whl"
    wheel_file.write_bytes(content)
    return wheel_file, hashlib.sha256(content).hexdigest()


def _write_manifest(tmp_path: Path, wheels: list[dict[str, Any]]) -> Path:
    manifest = tmp_path / "wheels_manifest.yaml"
    manifest.write_text(yaml.safe_dump({"wheels": wheels}), encoding="utf-8")
    return manifest


# =============================================================================
# WheelChecker — manifest 加载与 sha256 边界
# =============================================================================


class TestWheelCheckerManifestErrors:
    def test_missing_manifest_raises_file_not_found(self, tmp_path: Path) -> None:
        checker = WheelChecker(tmp_path / "nope.yaml", tmp_path / "wheels")
        with pytest.raises(FileNotFoundError):
            checker.check_wheel("pkg-a")

    def test_non_dict_manifest_raises_value_error(self, tmp_path: Path) -> None:
        manifest = tmp_path / "wheels_manifest.yaml"
        manifest.write_text("- just\n- a\n- list\n", encoding="utf-8")
        checker = WheelChecker(manifest, tmp_path / "wheels")
        with pytest.raises(ValueError, match="顶层应为字典"):
            checker.check_wheel("pkg-a")

    def test_manifest_cached_after_first_load(self, tmp_path: Path) -> None:
        """首次加载后 _manifest_data 缓存命中，不再读盘。"""
        _, sha = _write_wheel(tmp_path)
        manifest = _write_manifest(
            tmp_path,
            [
                {
                    "name": "pkg-a",
                    "version": "1.0.0",
                    "wheel_file": "pkg-1.0.0-py3-none-any.whl",
                    "sha256": sha,
                }
            ],
        )
        checker = WheelChecker(manifest, tmp_path / "wheels")
        first = checker.check_wheel("pkg-a")
        manifest.unlink()
        second = checker.check_wheel("pkg-a")
        assert first.status == "ok"
        assert second.status == "ok"


class TestVerifySha256:
    def test_missing_file_returns_false_and_empty_actual(self, tmp_path: Path) -> None:
        checker = WheelChecker(tmp_path / "m.yaml", tmp_path / "wheels")
        assert checker.verify_sha256(tmp_path / "ghost.whl", "deadbeef") == (False, "")

    def test_matching_and_mismatching_content(self, tmp_path: Path) -> None:
        wheel_file, sha = _write_wheel(tmp_path)
        checker = WheelChecker(tmp_path / "m.yaml", tmp_path / "wheels")
        matched, actual = checker.verify_sha256(wheel_file, sha.upper())
        assert matched is True
        assert actual == sha
        matched_bad, _ = checker.verify_sha256(wheel_file, "0" * 64)
        assert matched_bad is False


class TestCheckWheelBranches:
    def test_sha256_empty_branch_checks_existence_only(self, tmp_path: Path) -> None:
        """manifest 未填 sha256（YAML null）→ sha256_empty，附实际哈希。"""
        wheel_file, sha = _write_wheel(tmp_path)
        manifest = _write_manifest(
            tmp_path,
            [
                {
                    "name": "pkg-a",
                    "version": "1.0.0",
                    "wheel_file": wheel_file.name,
                    "sha256": None,
                }
            ],
        )
        checker = WheelChecker(manifest, tmp_path / "wheels")
        result = checker.check_wheel("pkg-a")
        assert result.status == "sha256_empty"
        assert result.actual_sha256 == sha
        assert result.required is True

    def test_check_importable_true_importable_module_is_ok(self, tmp_path: Path) -> None:
        """check_importable=True 且 import_name 可导入 → 最终 ok。"""
        wheel_file, sha = _write_wheel(tmp_path)
        manifest = _write_manifest(
            tmp_path,
            [
                {
                    "name": "pkg-a",
                    "version": "1.0.0",
                    "wheel_file": wheel_file.name,
                    "sha256": sha,
                    "import_name": "json",
                }
            ],
        )
        checker = WheelChecker(manifest, tmp_path / "wheels", check_importable=True)
        assert checker.check_wheel("pkg-a").status == "ok"

    def test_unknown_name_raises_key_error(self, tmp_path: Path) -> None:
        """包名未登记 → KeyError（契约：调用方应来自 manifest 自身）。"""
        _, sha = _write_wheel(tmp_path)
        manifest = _write_manifest(
            tmp_path,
            [
                {
                    "name": "pkg-a",
                    "version": "1.0.0",
                    "wheel_file": "pkg-1.0.0-py3-none-any.whl",
                    "sha256": sha,
                }
            ],
        )
        checker = WheelChecker(manifest, tmp_path / "wheels")
        with pytest.raises(KeyError):
            checker.check_wheel("pkg-zzz")


# =============================================================================
# check_all — 单条目异常的防御性跳过
# =============================================================================


class TestCheckAllDefensiveKeyError:
    def test_wheel_check_all_skips_key_error_entry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """check_wheel 抛 KeyError 时该条目被跳过，报告不抛错继续汇总。"""
        _, sha = _write_wheel(tmp_path)
        manifest = _write_manifest(
            tmp_path,
            [
                {
                    "name": "pkg-a",
                    "version": "1.0.0",
                    "wheel_file": "pkg-1.0.0-py3-none-any.whl",
                    "sha256": sha,
                },
                {
                    "name": "pkg-b",
                    "version": "2.0.0",
                    "wheel_file": "ghost.whl",
                    "sha256": "",
                },
            ],
        )
        checker = WheelChecker(manifest, tmp_path / "wheels")

        def _boom(name: str) -> Any:
            if name == "pkg-a":
                raise KeyError("injected")
            return checker.__class__.check_wheel(checker, name)

        monkeypatch.setattr(checker, "check_wheel", _boom)
        report = checker.check_all()
        assert [r.name for r in report.results] == ["pkg-b"]
        assert report.results[0].status == "missing"

    def test_tool_check_all_skips_key_error_entry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ToolChecker.check_tool 抛 KeyError 时条目跳过，报告继续汇总。"""
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text(
            yaml.safe_dump(
                {
                    "tools": [
                        {"name": "tool-a", "version": "1.0", "entry": "a.exe"},
                        {
                            "name": "tool-b",
                            "version": "2.0",
                            "entry": "b.exe",
                            "install_path": "tools/b/",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        checker = ToolChecker(manifest, tmp_path)

        def _boom(name: str) -> Any:
            if name == "tool-a":
                raise KeyError("injected")
            return ToolChecker.check_tool(checker, name)

        monkeypatch.setattr(checker, "check_tool", _boom)
        report = checker.check_all()
        assert [r.name for r in report.results] == ["tool-b"]
