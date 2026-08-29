"""测试模块：winreverse.tools.runner

测试外部工具命令行调用封装。
覆盖：
- ToolRunResult 数据模型（success 属性）
- ToolNotFoundError 异常
- ToolRunner 的 manifest 加载、get_entry_path、run、run_text
- run 方法的成功/失败/超时场景（mock subprocess.run）
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from winreverse.tools.runner import (
    ToolNotFoundError,
    ToolRunner,
    ToolRunResult,
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

update:
  default_source: "original"
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


@pytest.fixture
def runner_with_entry(manifest_file: Path, project_root: Path) -> tuple[ToolRunner, Path]:
    """创建带真实 entry 文件的 runner（tshark.exe 已创建）。"""
    entry_path = project_root / "tools" / "tshark" / "tshark.exe"
    entry_path.parent.mkdir(parents=True, exist_ok=True)
    entry_path.write_bytes(b"fake exe content")
    runner = ToolRunner(
        manifest_path=manifest_file,
        project_root=project_root,
    )
    return runner, entry_path


# =============================================================================
# 数据模型测试
# =============================================================================


class TestToolRunResult:
    """ToolRunResult 数据类测试。"""

    def test_success_when_returncode_zero(self) -> None:
        """returncode=0 且未超时时 success 为 True。"""
        result = ToolRunResult(
            tool_name="tshark",
            command=["tshark.exe"],
            returncode=0,
            stdout="output",
            stderr="",
            duration_ms=100,
            timed_out=False,
        )
        assert result.success is True

    def test_failure_when_returncode_nonzero(self) -> None:
        """returncode!=0 时 success 为 False。"""
        result = ToolRunResult(
            tool_name="tshark",
            command=["tshark.exe"],
            returncode=1,
            stdout="",
            stderr="error",
            duration_ms=100,
            timed_out=False,
        )
        assert result.success is False

    def test_failure_when_timed_out(self) -> None:
        """超时时 success 为 False（即使 returncode=0）。"""
        result = ToolRunResult(
            tool_name="tshark",
            command=["tshark.exe"],
            returncode=0,
            stdout="",
            stderr="",
            duration_ms=5000,
            timed_out=True,
        )
        assert result.success is False


class TestToolNotFoundError:
    """ToolNotFoundError 异常测试。"""

    def test_is_file_not_found_error(self) -> None:
        """ToolNotFoundError 应是 FileNotFoundError 的子类。"""
        assert issubclass(ToolNotFoundError, FileNotFoundError)

    def test_can_be_raised(self) -> None:
        """可以被 raise 并捕获为 FileNotFoundError。"""
        with pytest.raises(FileNotFoundError):
            raise ToolNotFoundError("test")


# =============================================================================
# ToolRunner 初始化测试
# =============================================================================


class TestToolRunnerInit:
    """ToolRunner 初始化测试。"""

    def test_init_basic(self, manifest_file: Path, project_root: Path) -> None:
        """初始化应正确存储参数。"""
        runner = ToolRunner(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        assert runner.manifest_path == manifest_file
        assert runner.project_root == project_root
        assert runner.default_timeout == 300
        assert runner.default_encoding is None

    def test_init_with_custom_params(self, manifest_file: Path, project_root: Path) -> None:
        """自定义参数应正确存储。"""
        runner = ToolRunner(
            manifest_path=manifest_file,
            project_root=project_root,
            default_timeout=600,
            default_encoding="utf-8",
        )
        assert runner.default_timeout == 600
        assert runner.default_encoding == "utf-8"


# =============================================================================
# manifest 加载测试
# =============================================================================


class TestToolRunnerLoadManifest:
    """ToolRunner._load_manifest 测试。"""

    def test_load_manifest_success(self, manifest_file: Path, project_root: Path) -> None:
        """正常加载 manifest。"""
        runner = ToolRunner(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        data = runner._load_manifest()
        assert isinstance(data, dict)
        assert "tools" in data
        assert len(data["tools"]) == 2

    def test_load_manifest_file_not_found(self, tmp_path: Path) -> None:
        """manifest 不存在时应抛 FileNotFoundError。"""
        runner = ToolRunner(
            manifest_path=tmp_path / "nonexistent.yaml",
            project_root=tmp_path,
        )
        with pytest.raises(FileNotFoundError, match="不存在"):
            runner._load_manifest()

    def test_load_manifest_invalid_top_level(self, tmp_path: Path, project_root: Path) -> None:
        """manifest 顶层非字典时应抛 ValueError。"""
        bad_manifest = tmp_path / "bad.yaml"
        bad_manifest.write_text("- list\n- not\n- dict\n", encoding="utf-8")
        runner = ToolRunner(
            manifest_path=bad_manifest,
            project_root=project_root,
        )
        with pytest.raises(ValueError, match="顶层应为字典"):
            runner._load_manifest()

    def test_load_manifest_caching(self, manifest_file: Path, project_root: Path) -> None:
        """manifest 加载应缓存。"""
        runner = ToolRunner(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        data1 = runner._load_manifest()
        data2 = runner._load_manifest()
        assert data1 is data2


# =============================================================================
# _get_tool_entry 测试
# =============================================================================


class TestToolRunnerGetToolEntry:
    """ToolRunner._get_tool_entry 测试。"""

    def test_get_tool_entry_success(self, manifest_file: Path, project_root: Path) -> None:
        """获取已登记工具的配置。"""
        runner = ToolRunner(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        entry = runner._get_tool_entry("tshark")
        assert entry["name"] == "tshark"
        assert entry["entry"] == "tshark.exe"

    def test_get_tool_entry_not_found(self, manifest_file: Path, project_root: Path) -> None:
        """获取未登记工具时应抛 KeyError。"""
        runner = ToolRunner(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        with pytest.raises(KeyError, match="未在 manifest 中登记"):
            runner._get_tool_entry("nonexistent")


# =============================================================================
# get_entry_path 测试
# =============================================================================


class TestToolRunnerGetEntryPath:
    """ToolRunner.get_entry_path 测试。"""

    def test_get_entry_path_success(self, runner_with_entry: tuple[ToolRunner, Path]) -> None:
        """entry 存在时返回完整路径。"""
        runner, expected_path = runner_with_entry
        result = runner.get_entry_path("tshark")
        assert result == expected_path
        assert result.exists()

    def test_get_entry_path_not_found(self, manifest_file: Path, project_root: Path) -> None:
        """entry 不存在时应抛 ToolNotFoundError。"""
        runner = ToolRunner(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        with pytest.raises(ToolNotFoundError, match="工具 entry 不存在"):
            runner.get_entry_path("tshark")

    def test_get_entry_path_tool_not_in_manifest(
        self, manifest_file: Path, project_root: Path
    ) -> None:
        """工具未登记时应抛 KeyError。"""
        runner = ToolRunner(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        with pytest.raises(KeyError, match="未在 manifest 中登记"):
            runner.get_entry_path("nonexistent")


# =============================================================================
# run 方法测试（mock subprocess.run）
# =============================================================================


class TestToolRunnerRun:
    """ToolRunner.run 测试。"""

    def test_run_success(self, runner_with_entry: tuple[ToolRunner, Path]) -> None:
        """成功执行命令。"""
        runner, _ = runner_with_entry

        # mock subprocess.run 返回成功结果
        mock_completed = MagicMock()
        mock_completed.returncode = 0
        mock_completed.stdout = "command output"
        mock_completed.stderr = ""

        with patch("winreverse.tools.runner.subprocess.run") as mock_run:
            mock_run.return_value = mock_completed
            result = runner.run("tshark", ["-r", "test.pcap"])

        assert result.tool_name == "tshark"
        assert result.returncode == 0
        assert result.stdout == "command output"
        assert result.stderr == ""
        assert result.success is True
        assert result.timed_out is False
        assert result.duration_ms >= 0
        # 验证 subprocess.run 被调用
        mock_run.assert_called_once()
        # 验证命令包含 entry 路径
        call_args = mock_run.call_args
        command = call_args[0][0]  # 第一个位置参数
        assert command[0].endswith("tshark.exe")
        assert "-r" in command
        assert "test.pcap" in command

    def test_run_failure_returncode(self, runner_with_entry: tuple[ToolRunner, Path]) -> None:
        """命令返回非 0 退出码时仍返回结果（check=False）。"""
        runner, _ = runner_with_entry

        mock_completed = MagicMock()
        mock_completed.returncode = 1
        mock_completed.stdout = ""
        mock_completed.stderr = "error occurred"

        with patch("winreverse.tools.runner.subprocess.run") as mock_run:
            mock_run.return_value = mock_completed
            result = runner.run("tshark", ["--invalid"])

        assert result.returncode == 1
        assert result.success is False
        assert result.timed_out is False
        assert "error occurred" in result.stderr

    def test_run_timeout(self, runner_with_entry: tuple[ToolRunner, Path]) -> None:
        """命令超时时返回带 timed_out=True 的结果。"""
        runner, _ = runner_with_entry

        # mock subprocess.run 抛出 TimeoutExpired
        timeout_exc = subprocess.TimeoutExpired(
            cmd=["tshark.exe"],
            timeout=300,
            output=b"partial stdout",
            stderr=b"partial stderr",
        )
        with patch("winreverse.tools.runner.subprocess.run") as mock_run:
            mock_run.side_effect = timeout_exc
            result = runner.run("tshark", ["-r", "big.pcap"])

        assert result.timed_out is True
        assert result.returncode == -1
        assert result.success is False

    def test_run_with_check_raises_called_process_error(
        self, runner_with_entry: tuple[ToolRunner, Path]
    ) -> None:
        """check=True 时返回码非 0 抛 CalledProcessError。"""
        runner, _ = runner_with_entry

        called_exc = subprocess.CalledProcessError(
            returncode=2,
            cmd=["tshark.exe"],
            output="partial",
            stderr="failed",
        )
        with patch("winreverse.tools.runner.subprocess.run") as mock_run:
            mock_run.side_effect = called_exc
            with pytest.raises(subprocess.CalledProcessError):
                runner.run("tshark", ["--bad"], check=True)

    def test_run_entry_not_found(self, manifest_file: Path, project_root: Path) -> None:
        """entry 不存在时抛 ToolNotFoundError。"""
        runner = ToolRunner(
            manifest_path=manifest_file,
            project_root=project_root,
        )
        with pytest.raises(ToolNotFoundError, match="工具 entry 不存在"):
            runner.run("tshark", [])

    def test_run_passes_env_and_timeout(self, runner_with_entry: tuple[ToolRunner, Path]) -> None:
        """run 应传递 env 和 timeout 参数到 subprocess.run。"""
        runner, _ = runner_with_entry

        mock_completed = MagicMock()
        mock_completed.returncode = 0
        mock_completed.stdout = ""
        mock_completed.stderr = ""

        with patch("winreverse.tools.runner.subprocess.run") as mock_run:
            mock_run.return_value = mock_completed
            runner.run(
                "tshark",
                ["-v"],
                timeout=120,
                env={"CUSTOM_VAR": "value"},
            )

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["timeout"] == 120
        assert "CUSTOM_VAR" in call_kwargs["env"]
        assert call_kwargs["env"]["CUSTOM_VAR"] == "value"


# =============================================================================
# run_text 便捷方法测试
# =============================================================================


class TestToolRunnerRunText:
    """ToolRunner.run_text 测试。"""

    def test_run_text_success(self, runner_with_entry: tuple[ToolRunner, Path]) -> None:
        """成功时返回 strip 后的 stdout。"""
        runner, _ = runner_with_entry

        mock_completed = MagicMock()
        mock_completed.returncode = 0
        mock_completed.stdout = "  output with spaces  \n"
        mock_completed.stderr = ""

        with patch("winreverse.tools.runner.subprocess.run") as mock_run:
            mock_run.return_value = mock_completed
            result = runner.run_text("tshark", ["-v"])

        assert result == "output with spaces"

    def test_run_text_failure_raises_runtime_error(
        self, runner_with_entry: tuple[ToolRunner, Path]
    ) -> None:
        """失败时抛 RuntimeError。"""
        runner, _ = runner_with_entry

        mock_completed = MagicMock()
        mock_completed.returncode = 1
        mock_completed.stdout = ""
        mock_completed.stderr = "command not found"

        with patch("winreverse.tools.runner.subprocess.run") as mock_run:
            mock_run.return_value = mock_completed
            with pytest.raises(RuntimeError, match="执行失败"):
                runner.run_text("tshark", ["--bad"])

    def test_run_text_timeout_raises_runtime_error(
        self, runner_with_entry: tuple[ToolRunner, Path]
    ) -> None:
        """超时时抛 RuntimeError。"""
        runner, _ = runner_with_entry

        timeout_exc = subprocess.TimeoutExpired(cmd=["tshark.exe"], timeout=300)
        with patch("winreverse.tools.runner.subprocess.run") as mock_run:
            mock_run.side_effect = timeout_exc
            with pytest.raises(RuntimeError, match="执行失败"):
                runner.run_text("tshark", ["-r", "big.pcap"])
