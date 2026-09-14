"""测试模块：winreverse.tools.updater 更新/回滚执行流（update 与 rollback 语义）。

覆盖：update() 的无 download_url / 下载失败 / SHA256 不匹配（含删除残留包）/
坏 zip 解压失败回滚备份 / 成功解压并回填 manifest 各分支、_update_non_zip
手动安装与校验失败、rollback 备份交换、update_all 聚合计数。
下载一律 monkeypatch _download_with_retry，不触网，Linux 可跑。
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from winreverse.tools.updater import ToolUpdater, UpdateResult


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
    """构造真实 zip 包（解压后 entry 位于安装目录根部），返回其 SHA256。"""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(inner_name, content)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _updater(tmp_path: Path, tool: dict[str, Any]) -> ToolUpdater:
    manifest = _write_manifest(tmp_path, tool)
    return ToolUpdater(manifest_path=manifest, project_root=tmp_path)


# =============================================================================
# update() 分支
# ==============================================================================


class TestUpdateBranches:
    """update() 各失败/成功分支。"""

    def test_no_download_url(self, tmp_path: Path) -> None:
        updater = _updater(tmp_path, _tool(download_url=""))
        result = updater.update("yara")
        assert result.success is False
        assert "无 download_url" in result.message

    def test_download_failure(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        updater = _updater(tmp_path, _tool())
        monkeypatch.setattr(updater, "_download_with_retry", lambda *a, **k: None)
        result = updater.update("yara")
        assert result.success is False
        assert "下载失败" in result.message

    def test_sha256_mismatch_deletes_package(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """package_sha256 不匹配：更新失败且下载的 zip 被清理。"""
        zip_path = tmp_path / "dl.zip"
        _make_zip(zip_path)
        updater = _updater(tmp_path, _tool(package_sha256="ff" * 32))
        monkeypatch.setattr(updater, "_download_with_retry", lambda *a, **k: zip_path)
        result = updater.update("yara")
        assert result.success is False
        assert "SHA256 校验失败" in result.message
        assert not zip_path.exists()

    def test_bad_zip_restores_backup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """非 zip 载荷：解压失败后旧版本目录必须被还原。"""
        install_dir = tmp_path / "tools" / "yara"
        install_dir.mkdir(parents=True)
        (install_dir / "yara64.exe").write_bytes(b"old exe")

        garbage = tmp_path / "dl.zip"
        garbage.write_bytes(b"not a zip file")
        updater = _updater(tmp_path, _tool())
        monkeypatch.setattr(updater, "_download_with_retry", lambda *a, **k: garbage)

        result = updater.update("yara")
        assert result.success is False
        assert "解压失败" in result.message
        assert (install_dir / "yara64.exe").read_bytes() == b"old exe"  # 备份已还原

    def test_success_extracts_and_backfills_manifest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """成功路径：解压到 install_path、manifest 回填 version/package_sha256/sha256、清理 zip。"""
        zip_path = tmp_path / "dl.zip"
        zip_sha = _make_zip(zip_path)
        updater = _updater(tmp_path, _tool())
        monkeypatch.setattr(updater, "_download_with_retry", lambda *a, **k: zip_path)

        result = updater.update("yara")
        assert result.success is True, result.message

        entry = tmp_path / "tools" / "yara" / "yara64.exe"
        assert entry.read_bytes() == b"new exe"
        assert not zip_path.exists()  # 临时包已清理

        import yaml

        saved = yaml.safe_load(updater.manifest_path.read_text(encoding="utf-8"))
        saved_entry = saved["tools"][0]
        assert saved_entry["version"] == "4.5.6"  # 升到 latest_known
        assert saved_entry["package_sha256"] == zip_sha
        assert saved_entry["sha256"] == hashlib.sha256(b"new exe").hexdigest()

        # 更新后 version == latest_known → check_updates 不再报告
        assert updater.check_updates() == []


# =============================================================================
# _update_non_zip（自解压包手动安装流）
# ==============================================================================


class TestUpdateNonZip:
    """非 zip 格式：下载落盘 + SHA256 校验，不自动解压。"""

    def _fake_download(self, content: bytes, filename: str = "setup.exe"):
        def fake(url, tool_name, retry_times, timeout, dest_dir=None):
            assert dest_dir is not None
            dest_dir.mkdir(parents=True, exist_ok=True)
            p = dest_dir / filename
            p.write_bytes(content)
            return p

        return fake

    def test_manual_install_message(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        content = b"MZ fake sfx payload"
        updater = _updater(
            tmp_path,
            _tool(download_format="exe", package_sha256=hashlib.sha256(content).hexdigest()),
        )
        monkeypatch.setattr(updater, "_download_with_retry", self._fake_download(content))
        result = updater.update("yara")
        assert result.success is False  # 非自动安装，但文件已就绪
        assert "手动" in result.message
        assert (tmp_path / "downloads" / "setup.exe").read_bytes() == content

    def test_non_zip_sha_mismatch_deletes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        content = b"MZ fake sfx payload"
        updater = _updater(tmp_path, _tool(download_format="exe", package_sha256="ab" * 32))
        monkeypatch.setattr(updater, "_download_with_retry", self._fake_download(content))
        result = updater.update("yara")
        assert result.success is False
        assert "SHA256 校验失败" in result.message
        assert not (tmp_path / "downloads" / "setup.exe").exists()  # 残留包被删除


# =============================================================================
# rollback / update_all
# ==============================================================================


class TestRollbackAndUpdateAll:
    """rollback 备份交换与 update_all 聚合。"""

    def test_rollback_swaps_backup(self, tmp_path: Path) -> None:
        install_dir = tmp_path / "tools" / "yara"
        install_dir.mkdir(parents=True)
        (install_dir / "yara64.exe").write_bytes(b"v4.5.6")

        bak_dir = tmp_path / "tools" / "yara.bak"
        bak_dir.mkdir()
        (bak_dir / "yara64.exe").write_bytes(b"v4.5.4")

        updater = _updater(tmp_path, _tool())
        result = updater.rollback("yara")
        assert result.success is True
        assert "已回滚" in result.message
        # 备份版本就位，当前版本成为新备份
        assert (install_dir / "yara64.exe").read_bytes() == b"v4.5.4"
        assert (bak_dir / "yara64.exe").read_bytes() == b"v4.5.6"

    def test_rollback_unknown_tool(self, tmp_path: Path) -> None:
        updater = _updater(tmp_path, _tool())
        result = updater.rollback("ghost")
        assert isinstance(result, UpdateResult)
        assert result.success is False

    def test_update_all_counts(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """update_all 汇总各工具 update 结果的成功/失败计数。"""
        updater = _updater(tmp_path, _tool())
        results = iter(
            [
                UpdateResult(name="yara", success=True, message="ok"),
                UpdateResult(name="die", success=False, message="boom"),
            ]
        )
        # check_updates 返回两个待更新项，update 消费对应的成功/失败结果
        updates = [
            SimpleNamespace(name="yara", current="4.5.4", latest="4.5.6"),
            SimpleNamespace(name="die", current="1.0", latest="1.1"),
        ]
        monkeypatch.setattr(updater, "check_updates", lambda: updates)
        monkeypatch.setattr(updater, "update", lambda name: next(results))
        report = updater.update_all()
        assert report.success_count == 1
        assert report.failure_count == 1


# =============================================================================
# 纯本地辅助方法分支（manifest 解析 / GitHub API / entry SHA256）
# ==============================================================================


class TestManifestHelpers:
    """_get_tool_entry / _get_update_config 的异常与类型兜底分支。"""

    def test_get_tool_entry_unknown_raises_keyerror(self, tmp_path: Path) -> None:
        """未登记的工具应抛 KeyError（含工具名）。"""
        updater = _updater(tmp_path, _tool())
        with pytest.raises(KeyError, match="nmap"):
            updater._get_tool_entry("nmap")

    def test_get_tool_entry_non_dict_raises_valueerror(self, tmp_path: Path) -> None:
        """manifest 中条目不是字典（如字符串）时不得泄漏 AttributeError。

        回归：旧代码在生成器内对非 dict 条目调 t.get("name") 直接崩溃；
        修复后非 dict 条目被跳过，按"未登记"处理（KeyError 含工具名）。
        """
        import yaml

        manifest = tmp_path / "manifest.yaml"
        manifest.write_text(
            yaml.dump({"schema_version": "1.0", "tools": ["yara"]}, allow_unicode=True),
            encoding="utf-8",
        )
        updater = ToolUpdater(manifest_path=manifest, project_root=tmp_path)
        with pytest.raises((KeyError, ValueError), match="yara") as excinfo:
            updater._get_tool_entry("yara")
        assert not isinstance(excinfo.value, AttributeError)

    def test_get_update_config_non_dict_returns_empty(self, tmp_path: Path) -> None:
        """update 段类型异常（如字符串）时应返回空字典而非崩溃。"""
        import yaml

        manifest = tmp_path / "manifest.yaml"
        manifest.write_text(
            yaml.dump(
                {"schema_version": "1.0", "tools": [_tool()], "update": "oops"},
                allow_unicode=True,
            ),
            encoding="utf-8",
        )
        updater = ToolUpdater(manifest_path=manifest, project_root=tmp_path)
        assert updater._get_update_config() == {}


class TestGithubVersionProbe:
    """_extract_github_tag / _fetch_github_latest 的解析与网络失败分支。"""

    def test_extract_github_tag_owner_repo(self) -> None:
        url = "https://github.com/VirusTotal/yara/releases/download/4.5.4/yara.zip"
        assert ToolUpdater._extract_github_tag(url) == "VirusTotal/yara"

    def test_extract_github_tag_non_github_returns_none(self) -> None:
        assert ToolUpdater._extract_github_tag("https://example.com/yara.zip") is None

    def test_fetch_github_latest_strips_v_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """tag_name 'v4.6.7' 应去掉 v 前缀返回 '4.6.7'。"""
        import io
        import json as _json

        from winreverse.tools import updater as updater_mod

        class _FakeResp(io.BytesIO):
            def __enter__(self) -> _FakeResp:
                return self

            def __exit__(self, *args: object) -> None:
                pass

        payload = _json.dumps({"tag_name": "v4.6.7"}).encode()
        monkeypatch.setattr(updater_mod, "urlopen", lambda *a, **k: _FakeResp(payload))
        assert ToolUpdater._fetch_github_latest("VirusTotal/yara") == "4.6.7"

    def test_fetch_github_latest_network_failure_returns_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """网络异常（URLError）应返回 None 而非抛出。"""
        from urllib.error import URLError

        from winreverse.tools import updater as updater_mod

        def boom(*a: object, **k: object) -> object:
            raise URLError("no network")

        monkeypatch.setattr(updater_mod, "urlopen", boom)
        assert ToolUpdater._fetch_github_latest("VirusTotal/yara") is None


class TestEntrySha256Fallbacks:
    """_compute_entry_sha256 的早退分支：未知工具 / 无 entry / entry 文件缺失。"""

    def test_unknown_tool_returns_empty(self, tmp_path: Path) -> None:
        updater = _updater(tmp_path, _tool())
        assert updater._compute_entry_sha256("nmap") == ""

    def test_missing_entry_file_returns_empty(self, tmp_path: Path) -> None:
        """entry 字段存在但文件未安装时应返回空串（不抛异常）。"""
        updater = _updater(tmp_path, _tool())
        assert updater._compute_entry_sha256("yara") == ""

    def test_installed_entry_returns_sha256(self, tmp_path: Path) -> None:
        """entry 文件存在时应返回其 SHA256。"""
        import hashlib

        tool = _tool()
        entry_file = tmp_path / "tools" / "yara" / "yara64.exe"
        entry_file.parent.mkdir(parents=True)
        entry_file.write_bytes(b"installed exe")
        updater = _updater(tmp_path, tool)
        assert updater._compute_entry_sha256("yara") == hashlib.sha256(b"installed exe").hexdigest()


class TestUpdateAllNoUpdates:
    """update_all 在无可用更新时应返回空报告。"""

    def test_empty_report_when_nothing_to_update(self, tmp_path: Path) -> None:
        tool = _tool(latest_known="4.5.4")  # version == latest_known
        updater = _updater(tmp_path, tool)
        report = updater.update_all()
        assert report.results == []
        assert report.success_count == 0
        assert report.failure_count == 0
