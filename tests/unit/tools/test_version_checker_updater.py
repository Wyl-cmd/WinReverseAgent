"""被测模块: winreverse.tools.version_checker（WheelUpdater 离线更新流）。

覆盖点: PyPI 查询成功/失败回退（urlopen 打桩）、pip 更新成功/失败/
异常路径（subprocess.run 打桩）、批量 update_all 汇总、manifest 加载
防御分支与版本字段回写。
网络与子进程边界全部 monkeypatch，Linux 可实跑，不发起真实请求。
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from urllib.error import URLError

import pytest
import yaml

import winreverse.tools.version_checker as vc
from winreverse.tools.version_checker import WheelUpdater

PYPI_INDEX = "https://pypi.org/pypi/<name>/json"


# =============================================================================
# 打桩辅助
# =============================================================================


class _FakeResponse:
    """模拟 urlopen 返回的 JSON 响应（上下文管理器协议）。"""

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc_info: object) -> bool:
        return False


def _fake_urlopen_by_name(responses: dict[str, dict[str, Any]], fail_names: set[str] | None = None):
    """按 URL 中的包名分发响应；fail_names 中的包名抛 URLError。"""
    fail_names = fail_names or set()

    def _fake(req: Any, timeout: float) -> _FakeResponse:
        name = req.get_full_url().rsplit("/", 2)[-2]
        if name in fail_names:
            raise URLError(f"network down for {name}")
        return _FakeResponse(responses[name])

    return _fake


def _fake_subprocess_run(install_results: dict[str, int], show_versions: dict[str, str]):
    """按 pip 子命令分发：install → 指定 returncode；show → 输出 Version 行。"""

    def _fake(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        cmd = args[0]
        name = cmd[-1]
        if "install" in cmd:
            return subprocess.CompletedProcess(cmd, install_results[name], "", "")
        version = show_versions.get(name)
        stdout = f"Name: {name}\nVersion: {version}\n" if version else ""
        return subprocess.CompletedProcess(cmd, 0 if version else 1, stdout, "")

    return _fake


def _write_manifest(tmp_path: Path, wheels: list[dict[str, Any]]) -> Path:
    manifest = tmp_path / "wheels_manifest.yaml"
    manifest.write_text(yaml.safe_dump({"wheels": wheels}), encoding="utf-8")
    return manifest


# =============================================================================
# fetch_latest_versions（PyPI 查询 + 回退）
# =============================================================================


class TestFetchLatestVersions:
    def test_success_and_network_failure_falls_back_to_manifest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """查询成功的包取 PyPI 版本，网络失败的包回退 manifest 版本。"""
        manifest = _write_manifest(
            tmp_path,
            [
                {"name": "pkg-a", "version": "1.0.0"},
                {"name": "pkg-b", "version": "3.2.1"},
            ],
        )
        monkeypatch.setattr(
            vc,
            "urlopen",
            _fake_urlopen_by_name({"pkg-a": {"info": {"version": "2.0.0"}}}, fail_names={"pkg-b"}),
        )
        updater = WheelUpdater(manifest, tmp_path / "wheels", online_index=PYPI_INDEX)
        assert updater.fetch_latest_versions() == {"pkg-a": "2.0.0", "pkg-b": "3.2.1"}

    def test_empty_version_string_treated_as_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PyPI 返回空版本号视为查询失败，回退 manifest 版本。"""
        manifest = _write_manifest(tmp_path, [{"name": "pkg-a", "version": "1.0.0"}])
        monkeypatch.setattr(
            vc, "urlopen", _fake_urlopen_by_name({"pkg-a": {"info": {"version": ""}}})
        )
        updater = WheelUpdater(manifest, tmp_path / "wheels", online_index=PYPI_INDEX)
        assert updater.fetch_latest_versions() == {"pkg-a": "1.0.0"}

    def test_entry_without_version_falls_back_to_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """manifest 条目缺 version 字段时回退空串。"""
        manifest = _write_manifest(tmp_path, [{"name": "pkg-a"}])
        monkeypatch.setattr(vc, "urlopen", _fake_urlopen_by_name({}, fail_names={"pkg-a"}))
        updater = WheelUpdater(manifest, tmp_path / "wheels", online_index=PYPI_INDEX)
        assert updater.fetch_latest_versions() == {"pkg-a": ""}

    def test_missing_manifest_yields_empty_result(self, tmp_path: Path) -> None:
        """manifest 文件不存在时不抛错，返回空字典。"""
        updater = WheelUpdater(tmp_path / "nope.yaml", tmp_path / "wheels")
        assert updater.fetch_latest_versions() == {}


# =============================================================================
# update / update_all（pip 子进程 + manifest 回写）
# =============================================================================


class TestUpdate:
    def test_success_syncs_manifest_version(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """pip install 成功 → 查询安装版本 → 回写 manifest version 字段。"""
        manifest = _write_manifest(tmp_path, [{"name": "pkg-a", "version": "1.0.0"}])
        monkeypatch.setattr(
            vc,
            "subprocess",
            _FakeSubprocessModule(_fake_subprocess_run({"pkg-a": 0}, {"pkg-a": "9.9.9"})),
        )
        updater = WheelUpdater(manifest, tmp_path / "wheels")
        assert updater.update("pkg-a") is True
        data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        assert data["wheels"][0]["version"] == "9.9.9"

    def test_nonzero_returncode_returns_false_keeps_manifest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """pip install 返回非零 → False，manifest 不被改写。"""
        manifest = _write_manifest(tmp_path, [{"name": "pkg-a", "version": "1.0.0"}])
        monkeypatch.setattr(
            vc,
            "subprocess",
            _FakeSubprocessModule(_fake_subprocess_run({"pkg-a": 1}, {})),
        )
        updater = WheelUpdater(manifest, tmp_path / "wheels")
        assert updater.update("pkg-a") is False
        data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        assert data["wheels"][0]["version"] == "1.0.0"

    def test_subprocess_error_returns_false(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """pip 子进程超时（SubprocessError）→ 捕获后返回 False。"""
        manifest = _write_manifest(tmp_path, [{"name": "pkg-a", "version": "1.0.0"}])

        def _timeout(*args: Any, **kwargs: Any) -> None:
            raise subprocess.TimeoutExpired(cmd="pip", timeout=300)

        monkeypatch.setattr(vc, "subprocess", _FakeSubprocessModule(_timeout))
        updater = WheelUpdater(manifest, tmp_path / "wheels")
        assert updater.update("pkg-a") is False

    def test_success_without_detectable_version_skips_manifest_write(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """pip show 查不到版本（returncode 1）→ 更新成功但不回写 manifest。"""
        manifest = _write_manifest(tmp_path, [{"name": "pkg-a", "version": "1.0.0"}])
        monkeypatch.setattr(
            vc,
            "subprocess",
            _FakeSubprocessModule(_fake_subprocess_run({"pkg-a": 0}, {})),
        )
        updater = WheelUpdater(manifest, tmp_path / "wheels")
        assert updater.update("pkg-a") is True
        data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        assert data["wheels"][0]["version"] == "1.0.0"


class TestGetInstalledVersion:
    def test_parses_version_line(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """pip show 输出中的 Version: 行被正确解析。"""
        monkeypatch.setattr(
            vc,
            "subprocess",
            _FakeSubprocessModule(_fake_subprocess_run({}, {"pkg-a": "1.2.3"})),
        )
        assert WheelUpdater._get_installed_version("pkg-a") == "1.2.3"

    def test_no_version_line_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """pip show 成功但输出无 Version 行 → None。"""

        def _fake(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            cmd = args[0]
            return subprocess.CompletedProcess(cmd, 0, "Name: pkg-a\n", "")

        monkeypatch.setattr(vc, "subprocess", _FakeSubprocessModule(_fake))
        assert WheelUpdater._get_installed_version("pkg-a") is None

    def test_pip_show_failure_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """pip show 返回非零（包未安装）→ None。"""
        monkeypatch.setattr(vc, "subprocess", _FakeSubprocessModule(_fake_subprocess_run({}, {})))
        assert WheelUpdater._get_installed_version("pkg-a") is None


class TestUpdateAll:
    def test_mixed_results_aggregated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """批量更新逐个串行执行，成功/失败按包名汇总。"""
        manifest = _write_manifest(
            tmp_path,
            [
                {"name": "pkg-a", "version": "1.0.0"},
                {"name": "pkg-b", "version": "2.0.0"},
            ],
        )
        monkeypatch.setattr(
            vc,
            "subprocess",
            _FakeSubprocessModule(
                _fake_subprocess_run({"pkg-a": 0, "pkg-b": 1}, {"pkg-a": "5.0.0"})
            ),
        )
        updater = WheelUpdater(manifest, tmp_path / "wheels")
        assert updater.update_all() == {"pkg-a": True, "pkg-b": False}


class TestLoadWheelsManifestDefensive:
    """_load_wheels_manifest 各防御分支：坏输入一律返回空列表不抛错。"""

    def _updater(self, tmp_path: Path, text: str | None) -> WheelUpdater:
        manifest = tmp_path / "wheels_manifest.yaml"
        if text is not None:
            manifest.write_text(text, encoding="utf-8")
        return WheelUpdater(manifest, tmp_path / "wheels")

    def test_missing_file(self, tmp_path: Path) -> None:
        assert self._updater(tmp_path, None)._load_wheels_manifest() == []

    def test_non_dict_yaml(self, tmp_path: Path) -> None:
        assert self._updater(tmp_path, "- a\n- b\n")._load_wheels_manifest() == []

    def test_missing_wheels_key(self, tmp_path: Path) -> None:
        assert self._updater(tmp_path, "other: 1\n")._load_wheels_manifest() == []

    def test_wheels_not_a_list(self, tmp_path: Path) -> None:
        assert self._updater(tmp_path, "wheels: 3\n")._load_wheels_manifest() == []


class TestUpdateWheelVersionDefensive:
    """_update_wheel_version 的 no-op 分支：坏 manifest 不抛错不写盘。"""

    def test_missing_manifest_noop(self, tmp_path: Path) -> None:
        WheelUpdater(tmp_path / "nope.yaml", tmp_path / "wheels")._update_wheel_version(
            "pkg-a", "2.0.0"
        )
        assert not (tmp_path / "nope.yaml").exists()

    def test_non_dict_manifest_noop(self, tmp_path: Path) -> None:
        manifest = tmp_path / "wheels_manifest.yaml"
        manifest.write_text("- a\n", encoding="utf-8")
        WheelUpdater(manifest, tmp_path / "wheels")._update_wheel_version("pkg-a", "2.0.0")
        assert manifest.read_text(encoding="utf-8") == "- a\n"

    def test_wheels_not_a_list_noop(self, tmp_path: Path) -> None:
        manifest = tmp_path / "wheels_manifest.yaml"
        manifest.write_text("wheels: 3\n", encoding="utf-8")
        WheelUpdater(manifest, tmp_path / "wheels")._update_wheel_version("pkg-a", "2.0.0")
        assert manifest.read_text(encoding="utf-8") == "wheels: 3\n"

    def test_unknown_name_rewrites_without_changes(self, tmp_path: Path) -> None:
        """目标包不在 manifest 中时安全重写，原有条目保持不变。"""
        manifest = _write_manifest(tmp_path, [{"name": "pkg-a", "version": "1.0.0"}])
        WheelUpdater(manifest, tmp_path / "wheels")._update_wheel_version("pkg-zzz", "2.0.0")
        data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        assert data["wheels"][0] == {"name": "pkg-a", "version": "1.0.0"}


class _FakeSubprocessModule:
    """替换 version_checker.subprocess 命名空间：只拦截 run，保留异常类。"""

    def __init__(self, run_func: Any) -> None:
        self.run = run_func
        self.SubprocessError = subprocess.SubprocessError
        self.TimeoutExpired = subprocess.TimeoutExpired
        self.CompletedProcess = subprocess.CompletedProcess
