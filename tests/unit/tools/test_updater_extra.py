"""测试模块：winreverse.tools.updater 补充分支。

覆盖 fetch_latest_versions 的 online 策略与 builtin 覆盖语义、
_extract_github_tag 残缺 URL、_fetch_github_latest 空/无 v 前缀 tag、
_compute_entry_sha256 缺 entry、_update_non_zip 下载失败与 SHA 回填、
_download_with_retry 的 dest_dir 落盘与重试耗尽、_update_manifest_field
未知工具静默、rollback 的仅备份/陈旧 .bak.new/OSError 恢复分支。
全程 monkeypatch，不触网，Linux 可跑。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.error import URLError

import pytest
import yaml

from winreverse.tools.updater import ToolUpdater

# =============================================================================
# 测试辅助
# =============================================================================


def _write_manifest(tmp_path: Path, tool: dict[str, Any]) -> Path:
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        yaml.dump({"schema_version": "1.0", "tools": [tool]}, allow_unicode=True),
        encoding="utf-8",
    )
    return manifest


def _tool(**overrides: Any) -> dict[str, Any]:
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


def _updater(tmp_path: Path, tool: dict[str, Any]) -> ToolUpdater:
    return ToolUpdater(manifest_path=_write_manifest(tmp_path, tool), project_root=tmp_path)


def _load_manifest(manifest_path: Path) -> dict[str, Any]:
    return yaml.safe_load(manifest_path.read_text(encoding="utf-8"))


class _FakeResp:
    """urlopen 桩：首次 read 返回全部载荷，其后返回空（模拟流结束）。"""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self, _size: int = -1) -> bytes:
        data, self._payload = self._payload, b""
        return data

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *args: object) -> None:
        return None


# =============================================================================
# fetch_latest_versions 策略
# =============================================================================


class TestFetchLatestVersionsStrategies:
    """online 策略覆盖 builtin、非 GitHub 源保留 builtin 结果。"""

    def test_online_overrides_builtin_for_github_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tool = _tool(
            download_url="https://github.com/owner1/repo1/releases/download/v1.0/a.zip",
            latest_known="1.0.0",
        )
        updater = _updater(tmp_path, tool)
        monkeypatch.setattr(ToolUpdater, "_fetch_github_latest", staticmethod(lambda repo: "9.9.9"))
        result = updater.fetch_latest_versions(["online"])
        assert result == {"yara": "9.9.9"}

    def test_online_none_keeps_builtin_result(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tool = _tool(
            download_url="https://github.com/owner1/repo1/releases/download/v1.0/a.zip",
            latest_known="1.0.0",
        )
        updater = _updater(tmp_path, tool)
        monkeypatch.setattr(ToolUpdater, "_fetch_github_latest", staticmethod(lambda repo: None))
        result = updater.fetch_latest_versions(["builtin", "online"])
        assert result == {"yara": "1.0.0"}

    def test_non_github_url_skipped_in_online_strategy(self, tmp_path: Path) -> None:
        updater = _updater(tmp_path, _tool(download_url="https://example.com/tool.zip"))
        # online-only：非 GitHub 源无 builtin 兜底也不得出现
        monkeypatch_free = updater.fetch_latest_versions(["online"])
        assert monkeypatch_free == {}


# =============================================================================
# _extract_github_tag / _fetch_github_latest
# =============================================================================


class TestGithubHelpers:
    """GitHub URL/Release 解析的边界。"""

    def test_owner_only_url_returns_none(self) -> None:
        assert ToolUpdater._extract_github_tag("https://github.com/owner") is None

    def test_empty_url_returns_none(self) -> None:
        assert ToolUpdater._extract_github_tag("") is None

    def test_tag_without_v_prefix_returned_as_is(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import winreverse.tools.updater as upd

        payload = json.dumps({"tag_name": "4.6.7"}).encode()
        monkeypatch.setattr(upd, "urlopen", lambda req, timeout: _FakeResp(payload))
        assert ToolUpdater._fetch_github_latest("owner/repo") == "4.6.7"

    def test_empty_tag_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import winreverse.tools.updater as upd

        payload = json.dumps({"tag_name": ""}).encode()
        monkeypatch.setattr(upd, "urlopen", lambda req, timeout: _FakeResp(payload))
        assert ToolUpdater._fetch_github_latest("owner/repo") is None


# =============================================================================
# _compute_entry_sha256 / _update_manifest_field
# =============================================================================


class TestEntryShaAndManifestField:
    """entry 缺失时返回空串；未知工具的字段更新静默无副作用。"""

    def test_empty_entry_returns_empty(self, tmp_path: Path) -> None:
        updater = _updater(tmp_path, _tool(entry=""))
        assert updater._compute_entry_sha256("yara") == ""

    def test_missing_entry_file_returns_empty(self, tmp_path: Path) -> None:
        updater = _updater(tmp_path, _tool(entry="ghost.exe"))
        assert updater._compute_entry_sha256("yara") == ""

    def test_present_entry_file_hashed(self, tmp_path: Path) -> None:
        install_dir = tmp_path / "tools" / "yara"
        install_dir.mkdir(parents=True)
        (install_dir / "yara64.exe").write_bytes(b"entry-bytes")
        updater = _updater(tmp_path, _tool())
        assert updater._compute_entry_sha256("yara") == hashlib.sha256(b"entry-bytes").hexdigest()

    def test_update_field_unknown_tool_is_noop(self, tmp_path: Path) -> None:
        manifest_path = _write_manifest(tmp_path, _tool())
        updater = ToolUpdater(manifest_path=manifest_path, project_root=tmp_path)
        updater._update_manifest_field("no-such-tool", "version", "9.9.9")
        manifest = _load_manifest(manifest_path)
        assert manifest["tools"][0]["version"] == "4.5.4"


# =============================================================================
# _update_non_zip：下载失败与 SHA 回填
# =============================================================================


class TestUpdateNonZipBranches:
    """非 zip 格式：下载失败失败退出；无预设 SHA 时计算并回填 manifest。"""

    def test_download_failure_reports_retry_exhausted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        updater = _updater(tmp_path, _tool(download_format="exe"))
        monkeypatch.setattr(updater, "_download_with_retry", lambda *a, **k: None)
        result = updater.update("yara")
        assert result.success is False
        assert "下载失败" in result.message

    def test_no_preset_sha_backfills_manifest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        content = b"MZ installer payload"
        pkg = tmp_path / "downloads" / "setup.exe"
        pkg.parent.mkdir(parents=True)
        pkg.write_bytes(content)
        manifest_path = _write_manifest(tmp_path, _tool(download_format="exe"))
        updater = ToolUpdater(manifest_path=manifest_path, project_root=tmp_path)
        monkeypatch.setattr(updater, "_download_with_retry", lambda *a, **k: pkg)

        result = updater.update("yara")
        assert result.success is False  # 手动安装流：文件就绪但非自动更新
        assert "手动" in result.message
        backfilled = _load_manifest(manifest_path)["tools"][0]["package_sha256"]
        assert backfilled == hashlib.sha256(content).hexdigest()


# =============================================================================
# _download_with_retry：dest_dir 落盘与重试耗尽
# =============================================================================


class TestDownloadWithRetry:
    """下载重试：指定目录按 URL 文件名落盘；连续失败耗尽重试返回 None。"""

    def test_dest_dir_uses_url_filename(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import winreverse.tools.updater as upd

        monkeypatch.setattr(upd, "urlopen", lambda req, timeout: _FakeResp(b"binary-data"))
        dest = tmp_path / "downloads"
        updater = _updater(tmp_path, _tool())
        got = updater._download_with_retry(
            "https://example.com/pkg/tool.exe", "yara", 3, 5, dest_dir=dest
        )
        assert got == dest / "tool.exe"
        assert got is not None and got.read_bytes() == b"binary-data"

    def test_retry_exhaustion_returns_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import winreverse.tools.updater as upd

        calls: list[int] = []

        def _always_down(req: object, timeout: object) -> _FakeResp:
            calls.append(1)
            raise URLError("connection refused")

        monkeypatch.setattr(upd, "urlopen", _always_down)
        updater = _updater(tmp_path, _tool())
        got = updater._download_with_retry("https://example.com/yara.zip", "yara", 3, 5)
        assert got is None
        assert len(calls) == 3


# =============================================================================
# rollback 补充分支
# =============================================================================


class TestRollbackExtraBranches:
    """rollback：仅备份无当前版本 / 陈旧 .bak.new 清理 / OSError 恢复。"""

    def test_rollback_with_missing_install_dir(self, tmp_path: Path) -> None:
        bak_dir = tmp_path / "tools" / "yara.bak"
        bak_dir.mkdir(parents=True)
        (bak_dir / "yara64.exe").write_bytes(b"old exe")
        updater = _updater(tmp_path, _tool())
        result = updater.rollback("yara")
        assert result.success is True
        assert (tmp_path / "tools" / "yara" / "yara64.exe").read_bytes() == b"old exe"
        # 无当前版本可挪入 .bak.new：备份整体就位后不再重建 .bak 目录
        assert not bak_dir.exists()

    def test_stale_bak_new_dir_is_removed(self, tmp_path: Path) -> None:
        install_dir = tmp_path / "tools" / "yara"
        install_dir.mkdir(parents=True)
        (install_dir / "yara64.exe").write_bytes(b"current")
        bak_dir = tmp_path / "tools" / "yara.bak"
        bak_dir.mkdir()
        (bak_dir / "yara64.exe").write_bytes(b"backup")
        stale = tmp_path / "tools" / "yara.bak.new"
        stale.mkdir()
        (stale / "junk").write_bytes(b"stale")
        updater = _updater(tmp_path, _tool())
        result = updater.rollback("yara")
        assert result.success is True
        assert not stale.exists()

    def test_oserror_mid_swap_restores_new_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        install_dir = tmp_path / "tools" / "yara"
        install_dir.mkdir(parents=True)
        (install_dir / "yara64.exe").write_bytes(b"current")
        bak_dir = tmp_path / "tools" / "yara.bak"
        bak_dir.mkdir()
        (bak_dir / "yara64.exe").write_bytes(b"backup")

        real_move = __import__("shutil").move
        calls: list[tuple[object, object]] = []

        def _flaky_move(src: object, dst: object) -> None:
            calls.append((src, dst))
            if len(calls) == 2:  # 第二步（备份 → 安装目录）失败
                raise OSError("disk full")
            real_move(src, dst)

        monkeypatch.setattr("winreverse.tools.updater.shutil.move", _flaky_move)
        updater = _updater(tmp_path, _tool())
        result = updater.rollback("yara")
        assert result.success is False
        assert "回滚失败" in result.message
        # 恢复逻辑：当前版本从 .bak.new 移回安装目录
        assert (install_dir / "yara64.exe").read_bytes() == b"current"
