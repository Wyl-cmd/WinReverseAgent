"""测试模块：winreverse.tools.updater

测试外部工具更新器。
覆盖：
- InstalledToolInfo / UpdateInfo / UpdateResult / UpdateAllReport 数据模型
- ToolUpdater 的 manifest 加载、list_installed、check_updates
- 已实现方法（fetch_latest_versions / update / update_all / rollback）的真实功能
"""

from __future__ import annotations

from pathlib import Path

import pytest

from winreverse.tools.updater import (
    InstalledToolInfo,
    ToolUpdater,
    UpdateAllReport,
    UpdateInfo,
    UpdateResult,
)

# =============================================================================
# 测试 fixture
# =============================================================================


@pytest.fixture
def sample_manifest_content() -> str:
    """示例 manifest YAML 内容。"""
    return """
schema_version: "1.0"
platform: "win64"

tools:
  - name: tshark
    version: "4.6.7"
    latest_known: "4.6.7"
    download_url: "https://example.com/tshark.zip"
    download_format: zip
    sha256: ""
    install_path: "tools/tshark/"
    entry: "tshark.exe"
    required: true
    arch: "x86_64"
    notes: "测试工具1"

  - name: yara
    version: "4.5.4"
    latest_known: "4.5.6"
    download_url: "https://example.com/yara.zip"
    download_format: zip
    sha256: "abc123"
    install_path: "tools/yara/"
    entry: "yara64.exe"
    required: true
    arch: "x86_64"
    notes: "测试工具2（有更新）"

  - name: radare2
    version: "6.1.8"
    latest_known: "6.1.8"
    download_url: "https://example.com/r2.zip"
    download_format: zip
    sha256: ""
    install_path: "tools/radare2/"
    entry: "r2.exe"
    required: false
    arch: "x86_64"
    notes: "可选工具"

update:
  default_source: "original"
  custom_mirror: ""
  timeout_seconds: 600
  retry_times: 3
  verify_ssl: true
""".strip()


@pytest.fixture
def manifest_file(tmp_path: Path, sample_manifest_content: str) -> Path:
    """创建临时 manifest.yaml 文件。"""
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(sample_manifest_content, encoding="utf-8")
    return manifest_path


@pytest.fixture
def project_root(tmp_path: Path) -> Path:
    """临时项目根目录。"""
    return tmp_path


# =============================================================================
# 数据模型测试
# =============================================================================


class TestInstalledToolInfo:
    """InstalledToolInfo 数据类测试。"""

    def test_basic_fields(self) -> None:
        """基本字段赋值。"""
        info = InstalledToolInfo(
            name="tshark",
            version="4.6.7",
            installed=True,
            required=True,
            entry="tshark.exe",
            install_path="tools/tshark/",
        )
        assert info.name == "tshark"
        assert info.version == "4.6.7"
        assert info.installed is True
        assert info.required is True
        assert info.entry == "tshark.exe"
        assert info.install_path == "tools/tshark/"


class TestUpdateInfo:
    """UpdateInfo 数据类测试。"""

    def test_basic_fields(self) -> None:
        """基本字段赋值。"""
        info = UpdateInfo(
            name="yara",
            current="4.5.4",
            latest="4.5.6",
            required=True,
        )
        assert info.name == "yara"
        assert info.current == "4.5.4"
        assert info.latest == "4.5.6"
        assert info.required is True


class TestUpdateResult:
    """UpdateResult 数据类测试。"""

    def test_basic_fields(self) -> None:
        """基本字段赋值。"""
        result = UpdateResult(name="yara", success=True, message="更新成功")
        assert result.name == "yara"
        assert result.success is True
        assert result.message == "更新成功"


class TestUpdateAllReport:
    """UpdateAllReport 报告类测试。"""

    def test_empty_report(self) -> None:
        """空报告的成功/失败计数为 0。"""
        report = UpdateAllReport()
        assert report.success_count == 0
        assert report.failure_count == 0

    def test_success_count(self) -> None:
        """成功计数。"""
        report = UpdateAllReport(
            results=[
                UpdateResult(name="a", success=True, message="ok"),
                UpdateResult(name="b", success=False, message="fail"),
                UpdateResult(name="c", success=True, message="ok"),
            ]
        )
        assert report.success_count == 2
        assert report.failure_count == 1


# =============================================================================
# ToolUpdater 测试
# =============================================================================


class TestToolUpdaterInit:
    """ToolUpdater 初始化测试。"""

    def test_init_basic(self, manifest_file: Path, project_root: Path) -> None:
        """初始化应正确存储参数。"""
        updater = ToolUpdater(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        assert updater.manifest_path == manifest_file
        assert updater.project_root == project_root

    def test_load_manifest_caching(self, manifest_file: Path, project_root: Path) -> None:
        """manifest 加载应缓存（第二次调用不重新读文件）。"""
        updater = ToolUpdater(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        data1 = updater._load_manifest()
        data2 = updater._load_manifest()
        assert data1 is data2  # 同一对象引用，证明走缓存


class TestToolUpdaterLoadManifest:
    """ToolUpdater._load_manifest 测试。"""

    def test_load_manifest_success(self, manifest_file: Path, project_root: Path) -> None:
        """正常加载 manifest。"""
        updater = ToolUpdater(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        data = updater._load_manifest()
        assert isinstance(data, dict)
        assert "tools" in data
        assert len(data["tools"]) == 3

    def test_load_manifest_file_not_found(self, tmp_path: Path) -> None:
        """manifest 不存在时应抛 FileNotFoundError。"""
        updater = ToolUpdater(
            manifest_path=tmp_path / "nonexistent.yaml",
            project_root=tmp_path,
        )
        with pytest.raises(FileNotFoundError, match="不存在"):
            updater._load_manifest()

    def test_load_manifest_invalid_top_level(self, tmp_path: Path, project_root: Path) -> None:
        """manifest 顶层非字典时应抛 ValueError。"""
        bad_manifest = tmp_path / "bad.yaml"
        bad_manifest.write_text("- list\n- not\n- dict\n", encoding="utf-8")
        updater = ToolUpdater(
            manifest_path=bad_manifest,
            project_root=project_root,
        )
        with pytest.raises(ValueError, match="顶层应为字典"):
            updater._load_manifest()


class TestToolUpdaterGetToolEntry:
    """ToolUpdater._get_tool_entry 测试。"""

    def test_get_tool_entry_success(self, manifest_file: Path, project_root: Path) -> None:
        """获取已登记工具的配置。"""
        updater = ToolUpdater(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        entry = updater._get_tool_entry("tshark")
        assert entry["name"] == "tshark"
        assert entry["version"] == "4.6.7"

    def test_get_tool_entry_not_found(self, manifest_file: Path, project_root: Path) -> None:
        """获取未登记工具时应抛 KeyError。"""
        updater = ToolUpdater(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        with pytest.raises(KeyError, match="未在 manifest 中登记"):
            updater._get_tool_entry("nonexistent")


class TestToolUpdaterGetUpdateConfig:
    """ToolUpdater._get_update_config 测试。"""

    def test_get_update_config_success(self, manifest_file: Path, project_root: Path) -> None:
        """获取 update 段配置。"""
        updater = ToolUpdater(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        cfg = updater._get_update_config()
        assert cfg["default_source"] == "original"
        assert cfg["timeout_seconds"] == 600

    def test_get_update_config_missing(self, tmp_path: Path, project_root: Path) -> None:
        """manifest 无 update 段时返回空字典。"""
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text('schema_version: "1.0"\ntools: []\n', encoding="utf-8")
        updater = ToolUpdater(
            manifest_path=manifest,
            project_root=project_root,
        )
        cfg = updater._get_update_config()
        assert cfg == {}


class TestToolUpdaterListInstalled:
    """ToolUpdater.list_installed 测试。"""

    def test_list_installed_all_present(self, manifest_file: Path, project_root: Path) -> None:
        """所有工具 entry 都存在时 installed 全为 True。"""
        updater = ToolUpdater(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        # 创建所有 entry 文件
        for _tool_name, entry, install_path in [
            ("tshark", "tshark.exe", "tools/tshark/"),
            ("yara", "yara64.exe", "tools/yara/"),
            ("radare2", "r2.exe", "tools/radare2/"),
        ]:
            entry_path = project_root / install_path / entry
            entry_path.parent.mkdir(parents=True, exist_ok=True)
            entry_path.write_bytes(b"fake exe content")

        result = updater.list_installed()
        assert len(result) == 3
        assert all(r.installed for r in result)
        # 验证字段
        tshark = next(r for r in result if r.name == "tshark")
        assert tshark.version == "4.6.7"
        assert tshark.required is True
        assert tshark.entry == "tshark.exe"
        # radare2 是可选工具
        r2 = next(r for r in result if r.name == "radare2")
        assert r2.required is False

    def test_list_installed_some_missing(self, manifest_file: Path, project_root: Path) -> None:
        """部分工具 entry 不存在时 installed 为 False。"""
        updater = ToolUpdater(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        # 只创建 tshark 的 entry
        tshark_path = project_root / "tools" / "tshark" / "tshark.exe"
        tshark_path.parent.mkdir(parents=True, exist_ok=True)
        tshark_path.write_bytes(b"fake")

        result = updater.list_installed()
        assert len(result) == 3
        tshark = next(r for r in result if r.name == "tshark")
        yara = next(r for r in result if r.name == "yara")
        assert tshark.installed is True
        assert yara.installed is False


class TestToolUpdaterCheckUpdates:
    """ToolUpdater.check_updates 测试。"""

    def test_check_updates_finds_available(self, manifest_file: Path, project_root: Path) -> None:
        """version != latest_known 的工具应被列出。"""
        updater = ToolUpdater(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        updates = updater.check_updates()
        # yara: 4.5.4 -> 4.5.6 有更新
        # tshark: 4.6.7 == 4.6.7 无更新
        # radare2: 6.1.8 == 6.1.8 无更新
        assert len(updates) == 1
        assert updates[0].name == "yara"
        assert updates[0].current == "4.5.4"
        assert updates[0].latest == "4.5.6"
        assert updates[0].required is True

    def test_check_updates_no_updates_available(self, tmp_path: Path, project_root: Path) -> None:
        """所有工具 version == latest_known 时返回空列表。"""
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text(
            """
schema_version: "1.0"
tools:
  - name: tshark
    version: "4.6.7"
    latest_known: "4.6.7"
    install_path: "tools/tshark/"
    entry: "tshark.exe"
    required: true
""".strip(),
            encoding="utf-8",
        )
        updater = ToolUpdater(
            manifest_path=manifest,
            project_root=project_root,
        )
        updates = updater.check_updates()
        assert updates == []

    def test_check_updates_missing_latest_known_defaults_to_version(
        self, tmp_path: Path, project_root: Path
    ) -> None:
        """latest_known 字段缺失时默认等于 version，不报更新。"""
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text(
            """
schema_version: "1.0"
tools:
  - name: tshark
    version: "4.6.7"
    install_path: "tools/tshark/"
    entry: "tshark.exe"
    required: true
""".strip(),
            encoding="utf-8",
        )
        updater = ToolUpdater(
            manifest_path=manifest,
            project_root=project_root,
        )
        updates = updater.check_updates()
        assert updates == []


class TestToolUpdaterRealImplementation:
    """已实现方法的真实功能测试（不依赖网络）。"""

    def test_fetch_latest_versions_builtin(self, manifest_file: Path, project_root: Path) -> None:
        """fetch_latest_versions 使用 builtin 策略应返回 manifest 中的 latest_known。"""
        updater = ToolUpdater(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        result = updater.fetch_latest_versions(strategy=["builtin"])
        assert isinstance(result, dict)
        assert "tshark" in result
        assert result["tshark"] == "4.6.7"

    def test_fetch_latest_versions_default_strategy(
        self, manifest_file: Path, project_root: Path
    ) -> None:
        """fetch_latest_versions 默认策略应等价于 builtin。"""
        updater = ToolUpdater(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        result = updater.fetch_latest_versions()
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_update_unknown_tool(self, manifest_file: Path, project_root: Path) -> None:
        """update 未知工具应返回失败的 UpdateResult。"""
        updater = ToolUpdater(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        result = updater.update("nonexistent_tool")
        assert isinstance(result, UpdateResult)
        assert result.success is False
        assert "nonexistent_tool" in result.message

    def test_update_all_returns_report(
        self, manifest_file: Path, project_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """update_all 应返回 UpdateAllReport，且只对"有新版本"的工具发起更新。

        修复(2026-09-12)：本 fixture 中 yara 的 version(4.5.4) != latest_known(4.5.6)，
        原用例会真的走到 `update()` → 从 https://example.com/yara.zip **真联网下载**，
        在真机上表现为"偶发长时间阻塞"（流水线『无 --cov 复跑 ~85% 卡住』的元凶，
        实测卡在该用例上 >120s 不返回）。现对 update 打桩：只断言遍历范围与报告结构，
        单测**永不触网**。
        """
        updater = ToolUpdater(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        called: list[str] = []

        def _fake_update(name: str, *args: object, **kwargs: object) -> UpdateResult:
            called.append(name)
            return UpdateResult(name=name, success=True, message="stub: 单测不联网")

        monkeypatch.setattr(updater, "update", _fake_update)

        report = updater.update_all()
        assert isinstance(report, UpdateAllReport)
        assert called == ["yara"]  # manifest 中仅 yara 有可用更新
        assert len(report.results) == 1
        assert report.results[0].name == "yara"

    def test_rollback_no_backup(self, manifest_file: Path, project_root: Path) -> None:
        """rollback 无备份目录时应返回失败。"""
        updater = ToolUpdater(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        result = updater.rollback("tshark")
        assert isinstance(result, UpdateResult)
        assert result.success is False
        assert "备份目录不存在" in result.message

    def test_extract_github_tag(self) -> None:
        """_extract_github_tag 应正确解析 GitHub URL。"""
        url = "https://github.com/VirusTotal/yara/releases/download/v4.5.6/yara.zip"
        result = ToolUpdater._extract_github_tag(url)
        assert result == "VirusTotal/yara"

    def test_extract_github_tag_non_github(self) -> None:
        """_extract_github_tag 非 GitHub URL 应返回 None。"""
        url = "https://www.wireshark.org/download/win64/all-versions/Wireshark-win64-4.6.7.zip"
        result = ToolUpdater._extract_github_tag(url)
        assert result is None

    def test_compute_sha256(self, tmp_path: Path) -> None:
        """_compute_sha256 应正确计算文件哈希。"""
        import hashlib

        test_file = tmp_path / "test.bin"
        content = b"hello world"
        test_file.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        result = ToolUpdater._compute_sha256(test_file)
        assert result == expected


class TestToolUpdaterWithRealManifest:
    """使用项目实际 manifest.yaml 的集成测试。"""

    def test_real_manifest_loads_successfully(self) -> None:
        """项目实际的 tools/manifest.yaml 应能正常加载。"""
        project_root = Path(__file__).resolve().parent.parent.parent.parent
        manifest_path = project_root / "tools" / "manifest.yaml"
        if not manifest_path.exists():
            pytest.skip("项目 manifest.yaml 不存在（非项目根运行）")

        updater = ToolUpdater(
            manifest_path=manifest_path,
            project_root=project_root,
        )
        data = updater._load_manifest()
        assert isinstance(data, dict)
        assert "tools" in data
        # 项目 manifest 登记了 6 个工具
        assert len(data["tools"]) == 6

    def test_real_manifest_list_installed(self) -> None:
        """项目实际的 manifest 应能列出 6 个工具。"""
        project_root = Path(__file__).resolve().parent.parent.parent.parent
        manifest_path = project_root / "tools" / "manifest.yaml"
        if not manifest_path.exists():
            pytest.skip("项目 manifest.yaml 不存在（非项目根运行）")

        updater = ToolUpdater(
            manifest_path=manifest_path,
            project_root=project_root,
        )
        result = updater.list_installed()
        assert len(result) == 6
        # 验证工具名集合
        names = {r.name for r in result}
        assert names == {"tshark", "yara", "die", "adb", "radare2", "ghidra"}

    def test_real_manifest_check_updates_empty(self) -> None:
        """项目实际 manifest 中所有工具 version == latest_known，无可用更新。"""
        project_root = Path(__file__).resolve().parent.parent.parent.parent
        manifest_path = project_root / "tools" / "manifest.yaml"
        if not manifest_path.exists():
            pytest.skip("项目 manifest.yaml 不存在（非项目根运行）")

        updater = ToolUpdater(
            manifest_path=manifest_path,
            project_root=project_root,
        )
        updates = updater.check_updates()
        # 项目 manifest 中所有 version == latest_known
        assert updates == []
