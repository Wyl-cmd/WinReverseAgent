"""测试模块：winreverse.tools.updater 尾部路径。

覆盖：SHA256 预设匹配通过、旧备份目录清理、备份移动失败中止、
无旧安装时解压失败不伪造还原、manifest 回填失败契约返回、
entry 哈希读取异常、GitHub 仿冒域名解析、无版本号工具跳过、
回滚移动失败报告。下载一律 monkeypatch _download_with_retry，
不触网，Linux 可跑，无平台依赖。
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import Any

import pytest

from winreverse.tools.updater import ToolUpdater


def _write_manifest(tmp_path: Path, tool: dict[str, Any]) -> Path:
    """生成仅含单个工具的 manifest.yaml。"""
    import yaml

    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        yaml.dump({"schema_version": "1.0", "tools": [tool]}, allow_unicode=True),
        encoding="utf-8",
    )
    return manifest


def _tool(**overrides: Any) -> dict[str, Any]:
    """基础工具条目（zip 格式，带下载 URL，version != latest_known）。"""
    entry = {
        "name": "yara",
        "version": "4.5.4",
        "latest_known": "4.5.6",
        "download_url": "https://example.com/yara.zip",
        "download_format": "zip",
        "package_sha256": "",
        "install_path": "tools/yara/",
        "entry": "yara64.exe",
        "required": True,
    }
    entry.update(overrides)
    return entry


def _make_zip(path: Path, inner_name: str = "yara64.exe", content: bytes = b"new exe") -> str:
    """构造真实 zip 包，返回其 SHA256。"""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(inner_name, content)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _updater(tmp_path: Path, tool: dict[str, Any]) -> ToolUpdater:
    manifest = _write_manifest(tmp_path, tool)
    return ToolUpdater(manifest_path=manifest, project_root=tmp_path)


class TestUpdateTailPaths:
    """update() 尾部失败/成功分支。"""

    def test_preset_sha256_match_passes_check(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """预设 package_sha256 与下载包一致：校验通过并完成更新回填。"""
        zip_path = tmp_path / "dl.zip"
        zip_sha = _make_zip(zip_path)
        updater = _updater(tmp_path, _tool(package_sha256=zip_sha))
        monkeypatch.setattr(updater, "_download_with_retry", lambda *a, **k: zip_path)

        result = updater.update("yara")

        assert result.success is True
        manifest = updater._load_manifest()
        assert manifest["tools"][0]["version"] == "4.5.6"
        assert manifest["tools"][0]["package_sha256"] == zip_sha
        assert not zip_path.exists()

    def test_stale_backup_dir_replaced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """已存在 .bak 目录：先清理再备份旧版本。"""
        install_dir = tmp_path / "tools" / "yara"
        install_dir.mkdir(parents=True)
        (install_dir / "yara64.exe").write_bytes(b"old exe")
        bak_dir = tmp_path / "tools" / "yara.bak"
        bak_dir.mkdir()
        (bak_dir / "stale.txt").write_text("stale", encoding="utf-8")

        zip_path = tmp_path / "dl.zip"
        _make_zip(zip_path)
        updater = _updater(tmp_path, _tool())
        monkeypatch.setattr(updater, "_download_with_retry", lambda *a, **k: zip_path)

        result = updater.update("yara")

        assert result.success is True
        assert (bak_dir / "yara64.exe").read_bytes() == b"old exe"  # 旧版本已入备份
        assert not (bak_dir / "stale.txt").exists()  # 陈旧备份已被清理
        assert (install_dir / "yara64.exe").read_bytes() == b"new exe"

    def test_backup_move_failure_aborts_cleanly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """备份移动失败：按契约返回失败、清理 zip、不触碰安装目录。"""
        install_dir = tmp_path / "tools" / "yara"
        install_dir.mkdir(parents=True)
        (install_dir / "yara64.exe").write_bytes(b"old exe")

        zip_path = tmp_path / "dl.zip"
        _make_zip(zip_path)
        updater = _updater(tmp_path, _tool())
        monkeypatch.setattr(updater, "_download_with_retry", lambda *a, **k: zip_path)

        def _boom(src: object, dst: object) -> None:
            raise OSError("disk locked")

        monkeypatch.setattr("winreverse.tools.updater.shutil.move", _boom)

        result = updater.update("yara")

        assert result.success is False
        assert "备份旧版本失败" in result.message
        assert (install_dir / "yara64.exe").read_bytes() == b"old exe"
        assert not zip_path.exists()

    def test_extract_failure_without_prior_install_skips_restore(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """无旧安装时解压失败：不执行还原动作，仅清理 zip 返回失败。"""
        (tmp_path / "tools").write_text("i am a file", encoding="utf-8")  # 阻断 mkdir

        garbage = tmp_path / "dl.zip"
        garbage.write_bytes(b"not a zip")
        updater = _updater(tmp_path, _tool())
        monkeypatch.setattr(updater, "_download_with_retry", lambda *a, **k: garbage)

        result = updater.update("yara")

        assert result.success is False
        assert "解压失败" in result.message
        assert not (tmp_path / "tools" / "yara").exists()
        assert not (tmp_path / "tools" / "yara.bak").exists()
        assert not garbage.exists()

    def test_manifest_backfill_failure_returns_contract_result(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """清单回填失败：新版本保留但按契约返回失败并清理 zip。"""
        zip_path = tmp_path / "dl.zip"
        _make_zip(zip_path)
        updater = _updater(tmp_path, _tool())
        monkeypatch.setattr(updater, "_download_with_retry", lambda *a, **k: zip_path)

        def _boom() -> None:
            raise OSError("disk full")

        monkeypatch.setattr(updater, "_save_manifest", _boom)

        result = updater.update("yara")

        assert result.success is False
        assert "清单回填失败" in result.message
        assert (tmp_path / "tools" / "yara" / "yara64.exe").read_bytes() == b"new exe"
        assert not zip_path.exists()

    def test_entry_sha_read_error_returns_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """entry 文件读取抛 OSError 时返回空串而非崩溃。"""
        install_dir = tmp_path / "tools" / "yara"
        install_dir.mkdir(parents=True)
        (install_dir / "yara64.exe").write_bytes(b"exe")

        updater = _updater(tmp_path, _tool())

        def _boom(file_path: Path) -> str:
            raise OSError("read error")

        monkeypatch.setattr(updater, "_compute_sha256", _boom)
        assert updater._compute_entry_sha256("yara") == ""


class TestMiscTailPaths:
    """杂项尾部路径。"""

    def test_extract_github_tag_lookalike_domain_returns_none(self) -> None:
        """github.com 仿冒子串域名：index 失败走 ValueError 分支返回 None。"""
        assert ToolUpdater._extract_github_tag("https://github.com.evil.example/x/y") is None

    def test_builtin_strategy_skips_versionless_tools(self, tmp_path: Path) -> None:
        """builtin 策略：无 latest_known/version 的工具不产生结果项。"""
        updater = _updater(tmp_path, _tool(version="", latest_known=None))

        result = updater.fetch_latest_versions(["builtin"])

        assert "yara" not in result
        assert result == {}

    def test_rollback_move_failure_reports(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """回滚时目录交换失败：返回失败信息且不做恢复性移动。"""
        install_dir = tmp_path / "tools" / "yara"
        install_dir.mkdir(parents=True)
        (install_dir / "yara64.exe").write_bytes(b"current exe")
        bak_dir = tmp_path / "tools" / "yara.bak"
        bak_dir.mkdir()
        (bak_dir / "yara64.exe").write_bytes(b"backup exe")

        updater = _updater(tmp_path, _tool())

        def _boom(src: object, dst: object) -> None:
            raise OSError("move denied")

        monkeypatch.setattr("winreverse.tools.updater.shutil.move", _boom)

        result = updater.rollback("yara")

        assert result.success is False
        assert "回滚失败" in result.message
