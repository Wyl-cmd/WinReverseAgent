"""winreverse.tools.updater — retry_times 配置边界。

覆盖点：manifest update.retry_times<=0 时 _download_with_retry 空循环、
一次不试返回 None（updater.py 末尾 return None 弧），update() 公共路径
干净返回"下载失败"结果；retry_times=1 钉死"计数值=总尝试次数"语义。
"""

from __future__ import annotations

from pathlib import Path
from urllib.error import URLError

import pytest
import yaml

from winreverse.tools.updater import ToolUpdater


def _manifest(tmp_path: Path, retry_times: int) -> Path:
    """写一个含单个 zip 工具与自定义 retry_times 的 manifest。"""
    manifest: dict[str, object] = {
        "tools": [
            {
                "name": "demo",
                "version": "1.0.0",
                "latest_known": "2.0.0",
                "required": True,
                "entry": "demo.exe",
                "install_path": "tools/demo/",
                "download_url": "https://example.invalid/demo.zip",
                "download_format": "zip",
            }
        ],
        "update": {"retry_times": retry_times, "timeout_seconds": 5},
    }
    path = tmp_path / "manifest.yaml"
    path.write_text(yaml.dump(manifest, allow_unicode=True), encoding="utf-8")
    return path


class TestRetryTimesNonPositive:
    """retry_times<=0：range(1, n+1) 为空，一次都不尝试即判失败。"""

    @pytest.mark.parametrize("retry_times", [0, -3])
    def test_download_with_retry_non_positive_returns_none_without_attempts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retry_times: int
    ) -> None:
        import winreverse.tools.updater as upd

        def _must_not_call(*args: object, **kwargs: object) -> object:
            raise AssertionError("retry_times<=0 时不应发起任何网络请求")

        monkeypatch.setattr(upd, "urlopen", _must_not_call)
        updater = ToolUpdater(manifest_path=_manifest(tmp_path, retry_times), project_root=tmp_path)
        got = updater._download_with_retry(
            "https://example.invalid/demo.zip", "demo", retry_times, 5
        )
        assert got is None

    def test_update_reports_clean_failure_without_network(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """公共 update() 路径：retry_times=0 → 失败结果，不落任何临时 zip。"""
        import winreverse.tools.updater as upd

        def _must_not_call(*args: object, **kwargs: object) -> object:
            raise AssertionError("retry_times=0 时不应发起任何网络请求")

        monkeypatch.setattr(upd, "urlopen", _must_not_call)
        updater = ToolUpdater(manifest_path=_manifest(tmp_path, 0), project_root=tmp_path)
        result = updater.update("demo")

        assert result.success is False
        assert result.name == "demo"
        assert "重试 0 次后仍失败" in result.message
        assert not (tmp_path / "tools/demo").exists()


class TestRetryTimesIsTotalAttempts:
    """retry_times 语义钉死：计数值 = 总尝试次数（1 → 恰 1 次，无重试）。"""

    def test_single_attempt_means_no_retry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import winreverse.tools.updater as upd

        calls: list[int] = []

        def _always_down(req: object, timeout: object) -> object:
            calls.append(1)
            raise URLError("connection refused")

        monkeypatch.setattr(upd, "urlopen", _always_down)
        updater = ToolUpdater(manifest_path=_manifest(tmp_path, 1), project_root=tmp_path)
        got = updater._download_with_retry("https://example.invalid/demo.zip", "demo", 1, 5)

        assert got is None
        assert len(calls) == 1
