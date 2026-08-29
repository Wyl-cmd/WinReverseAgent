"""winreverse.tools.version_checker — 统一版本校验层。

M2 阶段实现：WheelChecker（Python wheel 完整性校验）
M3 阶段扩展：ToolChecker（外部工具 exe 完整性校验）+ VersionChecker（统一入口）

校验内容：
1. wheel 文件存在性 + SHA256 完整性（+ 可选 import 可用性）
2. 外部工具 entry 文件存在性 + SHA256 完整性（sha256 为空时仅校验存在性）

校验时机：
- doctor 启动时（强制校验，失败则报错）
- 设置页面「工具管理」→「Python 依赖」/「外部工具」子页（按需触发）

参考：实施方案 §5.7.4
"""

from __future__ import annotations

import hashlib
import importlib
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import yaml
from loguru import logger as _logger

# =============================================================================
# 数据模型
# =============================================================================


@dataclass
class WheelCheckResult:
    """单个 wheel 的校验结果。

    Attributes:
        name: 包名（如 'pymem'）
        version: 期望版本（如 '1.14.0'）
        wheel_file: wheel 文件名
        status: 校验状态
            - 'ok': 全部通过
            - 'missing': 文件不存在
            - 'sha256_mismatch': SHA256 不匹配
            - 'not_importable': import 失败
        message: 状态说明（人可读）
        expected_sha256: 期望的 SHA256
        actual_sha256: 实际计算的 SHA256（missing 时为 None）
        required: 是否为必选依赖
    """

    name: str
    version: str
    wheel_file: str
    status: str
    message: str
    expected_sha256: str
    actual_sha256: str | None = None
    required: bool = True


@dataclass
class WheelCheckReport:
    """wheel 校验报告。"""

    results: list[WheelCheckResult] = field(default_factory=list)

    @property
    def overall(self) -> str:
        """总体状态：必选项有 error 即 error；否则 ok。"""
        has_error = any(r.status != "ok" and r.required for r in self.results)
        return "error" if has_error else "ok"

    @property
    def passed(self) -> bool:
        """是否通过（无必选项错误）。"""
        return not any(r.status != "ok" and r.required for r in self.results)

    @property
    def missing_wheels(self) -> list[WheelCheckResult]:
        """缺失的 wheel 列表。"""
        return [r for r in self.results if r.status == "missing"]

    @property
    def mismatched_wheels(self) -> list[WheelCheckResult]:
        """SHA256 不匹配的 wheel 列表。"""
        return [r for r in self.results if r.status == "sha256_mismatch"]


# =============================================================================
# WheelChecker — wheel 完整性校验器
# =============================================================================


class WheelChecker:
    """Python wheel 完整性校验器。

    读取 vendor/wheels_manifest.yaml，逐项校验 vendor/wheels/ 下的 wheel 文件：
    1. 文件存在性
    2. SHA256 完整性
    3. （可选）import 可用性

    用法：
        checker = WheelChecker(
            wheels_manifest=Path("vendor/wheels_manifest.yaml"),
            wheels_dir=Path("vendor/wheels"),
        )
        report = checker.check_all()
        if not report.passed:
            print("wheel 校验失败")
    """

    def __init__(
        self,
        wheels_manifest: Path,
        wheels_dir: Path,
        check_importable: bool = False,
    ) -> None:
        """初始化 wheel 校验器。

        Args:
            wheels_manifest: wheels_manifest.yaml 路径
            wheels_dir: vendor/wheels/ 目录路径
            check_importable: 是否同时校验 import 可用性（默认 False，
                因为 import 校验较慢且可能因 venv 状态不同产生噪音）
        """
        self.wheels_manifest = wheels_manifest
        self.wheels_dir = wheels_dir
        self.check_importable = check_importable
        self._manifest_data: dict[str, Any] | None = None

    def _load_manifest(self) -> dict[str, Any]:
        """加载 wheels_manifest.yaml。

        Returns:
            manifest 字典

        Raises:
            FileNotFoundError: manifest 文件不存在
            yaml.YAMLError: manifest 格式错误
        """
        if self._manifest_data is not None:
            return self._manifest_data
        if not self.wheels_manifest.exists():
            raise FileNotFoundError(f"wheels_manifest.yaml 不存在: {self.wheels_manifest}")
        with self.wheels_manifest.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise ValueError(f"wheels_manifest.yaml 顶层应为字典，实际为 {type(data).__name__}")
        self._manifest_data = data
        return data

    def verify_sha256(self, file_path: Path, expected: str) -> tuple[bool, str]:
        """计算文件 SHA256 并与期望值比对。

        Args:
            file_path: 待校验文件路径
            expected: 期望的 SHA256（小写十六进制字符串）

        Returns:
            (是否匹配, 实际 SHA256) 元组
        """
        if not file_path.exists():
            return False, ""
        sha256 = hashlib.sha256()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        actual = sha256.hexdigest().lower()
        return actual == expected.lower(), actual

    def _check_importable(self, import_name: str) -> bool:
        """检查模块是否可 import。

        Args:
            import_name: 模块名（如 'pymem' / 'yara' / 'die'）

        Returns:
            True 表示可 import
        """
        try:
            importlib.import_module(import_name)
            return True
        except ImportError as e:
            _logger.warning(f"import {import_name} 失败: {e}")
            return False

    def check_wheel(self, name: str) -> WheelCheckResult:
        """校验单个 wheel。

        Args:
            name: 包名（manifest 中的 name 字段）

        Returns:
            WheelCheckResult 校验结果

        Raises:
            KeyError: 包名未在 manifest 中登记
        """
        manifest = self._load_manifest()
        wheels = manifest.get("wheels", [])
        entry = next((w for w in wheels if w.get("name") == name), None)
        if entry is None:
            raise KeyError(f"wheel 未在 manifest 中登记: {name}")

        wheel_file = entry["wheel_file"]
        expected_sha = entry["sha256"]
        version = entry["version"]
        required = entry.get("required", True)
        import_name = entry.get("import_name", name)

        wheel_path = self.wheels_dir / wheel_file

        # 1. 文件存在性
        if not wheel_path.exists():
            return WheelCheckResult(
                name=name,
                version=version,
                wheel_file=wheel_file,
                status="missing",
                message=f"wheel 文件不存在: {wheel_path}",
                expected_sha256=expected_sha,
                actual_sha256=None,
                required=required,
            )

        # 2. SHA256 校验
        matched, actual_sha = self.verify_sha256(wheel_path, expected_sha)
        if not matched:
            return WheelCheckResult(
                name=name,
                version=version,
                wheel_file=wheel_file,
                status="sha256_mismatch",
                message=f"SHA256 不匹配：期望 {expected_sha[:16]}...，实际 {actual_sha[:16]}...",
                expected_sha256=expected_sha,
                actual_sha256=actual_sha,
                required=required,
            )

        # 3. （可选）import 校验
        if self.check_importable and not self._check_importable(import_name):
            return WheelCheckResult(
                name=name,
                version=version,
                wheel_file=wheel_file,
                status="not_importable",
                message=f"import {import_name} 失败（可能未安装到 venv）",
                expected_sha256=expected_sha,
                actual_sha256=actual_sha,
                required=required,
            )

        return WheelCheckResult(
            name=name,
            version=version,
            wheel_file=wheel_file,
            status="ok",
            message=f"{name}=={version} 校验通过",
            expected_sha256=expected_sha,
            actual_sha256=actual_sha,
            required=required,
        )

    def check_all(self) -> WheelCheckReport:
        """校验 manifest 中登记的全部 wheel。

        Returns:
            WheelCheckReport 报告
        """
        manifest = self._load_manifest()
        wheels = manifest.get("wheels", [])
        report = WheelCheckReport()
        for entry in wheels:
            name = entry["name"]
            try:
                result = self.check_wheel(name)
            except KeyError as e:
                # 不应发生（name 来自 manifest 自身），防御性处理
                _logger.error(f"check_wheel 内部错误: {e}")
                continue
            report.results.append(result)
            _logger.info(f"[{result.status}] {result.name}=={result.version}: {result.message}")
        return report


# =============================================================================
# WheelUpdater — wheel 在线更新器
# =============================================================================


class WheelUpdater:
    """wheel 在线更新器。

    已实现完整功能：
    1. 查询 PyPI 获取最新版本（fetch_latest_versions）
    2. 通过 pip install --upgrade 更新包（update / update_all）
    3. 自动同步 wheels_manifest.yaml 中的版本信息

    注：wheel 文件本身的下载与 SHA256 重新计算由 pip 自动完成，
    本更新器仅负责调用 pip 并同步 manifest 版本字段。
    """

    def __init__(
        self,
        wheels_manifest: Path,
        wheels_dir: Path,
        online_index: str = "https://pypi.org/pypi/<name>/json",
        timeout_seconds: int = 10,
    ) -> None:
        """初始化 wheel 更新器。

        Args:
            wheels_manifest: wheels_manifest.yaml 路径
            wheels_dir: vendor/wheels/ 目录路径
            online_index: PyPI JSON API 模板
            timeout_seconds: 网络请求超时
        """
        self.wheels_manifest = wheels_manifest
        self.wheels_dir = wheels_dir
        self.online_index = online_index
        self.timeout_seconds = timeout_seconds

    def fetch_latest_versions(self) -> dict[str, str]:
        """查询所有 wheel 的最新版本。

        调用 PyPI JSON API 在线查询每个包的最新版本。

        Returns:
            {包名: 最新版本号} 字典
        """
        wheels = self._load_wheels_manifest()
        result: dict[str, str] = {}

        for wheel in wheels:
            name = wheel["name"]
            latest = self._fetch_pypi_latest(name)
            if latest:
                result[name] = latest
                _logger.info(f"[PYPI] {name} 最新版本: {latest}")
            else:
                # 查询失败，使用 manifest 中的当前版本作为回退
                result[name] = wheel.get("version", "")

        return result

    def update(self, name: str) -> bool:
        """更新单个 wheel 到最新版本。

        通过 `pip install --upgrade <name>` 更新包。
        更新成功后自动同步 wheels_manifest.yaml 中的版本信息。

        Args:
            name: 包名（如 'pymem'、'pefile'）

        Returns:
            True 表示更新成功
        """
        try:
            _logger.info(f"[PIP] 正在更新 {name}...")
            # 使用当前 Python 解释器的 pip 模块
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--upgrade", name],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode != 0:
                _logger.error(f"[PIP] {name} 更新失败: {result.stderr}")
                return False

            _logger.info(f"[PIP] {name} 更新成功")

            # 查询安装后的版本并更新 manifest
            installed_version = self._get_installed_version(name)
            if installed_version:
                self._update_wheel_version(name, installed_version)

            return True

        except (subprocess.SubprocessError, OSError) as e:
            _logger.error(f"[PIP] {name} 更新异常: {e}")
            return False

    def update_all(self) -> dict[str, bool]:
        """更新全部 wheel 到最新版本。

        Returns:
            {包名: 是否更新成功} 字典
        """
        wheels = self._load_wheels_manifest()
        results: dict[str, bool] = {}

        for wheel in wheels:
            name = wheel["name"]
            results[name] = self.update(name)

        success = sum(1 for v in results.values() if v)
        total = len(results)
        _logger.info(f"[PIP-ALL] 批量更新完成: {success}/{total} 成功")

        return results

    def _load_wheels_manifest(self) -> list[dict[str, Any]]:
        """加载 wheels_manifest.yaml 中的 wheels 列表。

        Returns:
            wheel 配置字典列表
        """
        if not self.wheels_manifest.exists():
            return []
        with self.wheels_manifest.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            return []
        wheels = data.get("wheels", [])
        return wheels if isinstance(wheels, list) else []

    def _fetch_pypi_latest(self, name: str) -> str | None:
        """调用 PyPI JSON API 查询包的最新版本。

        Args:
            name: 包名

        Returns:
            最新版本号字符串，失败返回 None
        """
        url = self.online_index.replace("<name>", name)
        try:
            req = Request(url, headers={"Accept": "application/json"})
            with urlopen(req, timeout=self.timeout_seconds) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                version = data.get("info", {}).get("version", "")
                return version if version else None
        except (HTTPError, URLError, OSError, json.JSONDecodeError) as e:
            _logger.warning(f"[PYPI] 查询 {name} 失败: {e}")
            return None

    @staticmethod
    def _get_installed_version(name: str) -> str | None:
        """获取已安装包的版本号。

        Args:
            name: 包名

        Returns:
            版本号字符串，失败返回 None
        """
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "show", name],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                return None
            # 解析 pip show 输出中的 Version 行
            for line in result.stdout.splitlines():
                if line.startswith("Version:"):
                    return line.split(":", 1)[1].strip()
        except (subprocess.SubprocessError, OSError):
            pass
        return None

    def _update_wheel_version(self, name: str, version: str) -> None:
        """更新 wheels_manifest.yaml 中指定包的版本字段。

        Args:
            name: 包名
            version: 新版本号
        """
        if not self.wheels_manifest.exists():
            return
        with self.wheels_manifest.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            return
        wheels = data.get("wheels", [])
        if not isinstance(wheels, list):
            return
        for wheel in wheels:
            if wheel.get("name") == name:
                wheel["version"] = version
                break
        with self.wheels_manifest.open("w", encoding="utf-8") as f:
            yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        _logger.info(f"[MANIFEST] {name} 版本已更新到 {version}")


# =============================================================================
# ToolChecker — 外部工具完整性校验器（M3 阶段实现）
# =============================================================================


@dataclass
class ToolCheckResult:
    """单个外部工具的校验结果。

    Attributes:
        name: 工具名（如 'tshark'）
        version: 期望版本（如 '4.6.7'）
        entry: 主可执行文件相对路径（如 'tshark.exe'）
        install_path: 安装目录（相对项目根，如 'tools/tshark/'）
        status: 校验状态
            - 'ok': 全部通过
            - 'missing': entry 文件不存在
            - 'sha256_mismatch': SHA256 不匹配
            - 'sha256_empty': manifest 中 sha256 为空（仅 warn，不阻塞）
        message: 状态说明（人可读）
        expected_sha256: 期望的 SHA256（可能为空字符串）
        actual_sha256: 实际计算的 SHA256（missing 时为 None）
        required: 是否为必选工具
    """

    name: str
    version: str
    entry: str
    install_path: str
    status: str
    message: str
    expected_sha256: str
    actual_sha256: str | None = None
    required: bool = True


@dataclass
class ToolCheckReport:
    """外部工具校验报告。"""

    results: list[ToolCheckResult] = field(default_factory=list)

    @property
    def overall(self) -> str:
        """总体状态：必选项有 error 即 error；否则有 warn 即 warn；否则 ok。"""
        has_error = any(
            r.status in ("missing", "sha256_mismatch") and r.required for r in self.results
        )
        if has_error:
            return "error"
        has_warn = any(
            r.status == "sha256_empty"
            or (r.status in ("missing", "sha256_mismatch") and not r.required)
            for r in self.results
        )
        return "warn" if has_warn else "ok"

    @property
    def passed(self) -> bool:
        """是否通过（无必选项 error）。"""
        return not any(
            r.status in ("missing", "sha256_mismatch") and r.required for r in self.results
        )

    @property
    def missing_tools(self) -> list[ToolCheckResult]:
        """缺失的工具列表。"""
        return [r for r in self.results if r.status == "missing"]

    @property
    def mismatched_tools(self) -> list[ToolCheckResult]:
        """SHA256 不匹配的工具列表。"""
        return [r for r in self.results if r.status == "sha256_mismatch"]

    @property
    def empty_sha256_tools(self) -> list[ToolCheckResult]:
        """sha256 未填写的工具列表（仅 warn）。"""
        return [r for r in self.results if r.status == "sha256_empty"]


class ToolChecker:
    """外部工具完整性校验器。

    读取 tools/manifest.yaml，逐项校验 tools/<name>/ 下的 entry 文件：
    1. entry 文件存在性
    2. SHA256 完整性（manifest 中 sha256 为空时仅 warn）

    用法：
        checker = ToolChecker(
            manifest_path=Path("tools/manifest.yaml"),
            project_root=Path("."),
        )
        report = checker.check_all()
        if not report.passed:
            print("外部工具校验失败")
    """

    def __init__(self, manifest_path: Path, project_root: Path) -> None:
        """初始化工具校验器。

        Args:
            manifest_path: tools/manifest.yaml 路径
            project_root: 项目根目录（用于解析 install_path 相对路径）
        """
        self.manifest_path = manifest_path
        self.project_root = project_root
        self._manifest_data: dict[str, Any] | None = None

    def _load_manifest(self) -> dict[str, Any]:
        """加载 manifest.yaml。

        Returns:
            manifest 字典

        Raises:
            FileNotFoundError: manifest 文件不存在
            yaml.YAMLError: manifest 格式错误
        """
        if self._manifest_data is not None:
            return self._manifest_data
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"manifest.yaml 不存在: {self.manifest_path}")
        with self.manifest_path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise ValueError(f"manifest.yaml 顶层应为字典，实际为 {type(data).__name__}")
        self._manifest_data = data
        return data

    def check_tool(self, name: str) -> ToolCheckResult:
        """校验单个工具。

        Args:
            name: 工具名（manifest 中的 name 字段）

        Returns:
            ToolCheckResult 校验结果

        Raises:
            KeyError: 工具名未在 manifest 中登记
        """
        manifest = self._load_manifest()
        tools = manifest.get("tools", [])
        entry = next((t for t in tools if t.get("name") == name), None)
        if entry is None:
            raise KeyError(f"工具未在 manifest 中登记: {name}")

        tool_name = entry["name"]
        version = entry["version"]
        exe = entry["entry"]
        install_path = entry["install_path"]
        expected_sha = entry.get("sha256", "") or ""
        required = entry.get("required", True)

        # entry 完整路径：project_root / install_path / entry
        # install_path 形如 "tools/tshark/"，末尾可能带 /，用 Path 拼接自动处理
        entry_path = self.project_root / install_path / exe

        # 1. 文件存在性
        if not entry_path.exists():
            return ToolCheckResult(
                name=tool_name,
                version=version,
                entry=exe,
                install_path=install_path,
                status="missing",
                message=f"工具 entry 不存在: {entry_path}",
                expected_sha256=expected_sha,
                actual_sha256=None,
                required=required,
            )

        # 2. SHA256 校验
        # manifest 中 sha256 为空时，仅 warn（不阻塞 doctor）
        if not expected_sha:
            actual_sha = self._compute_sha256(entry_path)
            return ToolCheckResult(
                name=tool_name,
                version=version,
                entry=exe,
                install_path=install_path,
                status="sha256_empty",
                message=f"manifest 中 sha256 未填写，仅校验存在性通过: {entry_path}",
                expected_sha256=expected_sha,
                actual_sha256=actual_sha,
                required=required,
            )

        actual_sha = self._compute_sha256(entry_path)
        if actual_sha.lower() != expected_sha.lower():
            return ToolCheckResult(
                name=tool_name,
                version=version,
                entry=exe,
                install_path=install_path,
                status="sha256_mismatch",
                message=f"SHA256 不匹配：期望 {expected_sha[:16]}...，实际 {actual_sha[:16]}...",
                expected_sha256=expected_sha,
                actual_sha256=actual_sha,
                required=required,
            )

        return ToolCheckResult(
            name=tool_name,
            version=version,
            entry=exe,
            install_path=install_path,
            status="ok",
            message=f"{tool_name}=={version} 校验通过",
            expected_sha256=expected_sha,
            actual_sha256=actual_sha,
            required=required,
        )

    def _compute_sha256(self, file_path: Path) -> str:
        """计算文件 SHA256。

        Args:
            file_path: 文件路径

        Returns:
            小写十六进制 SHA256 字符串
        """
        sha256 = hashlib.sha256()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest().lower()

    def check_all(self) -> ToolCheckReport:
        """校验 manifest 中登记的全部工具。

        Returns:
            ToolCheckReport 报告
        """
        manifest = self._load_manifest()
        tools = manifest.get("tools", [])
        report = ToolCheckReport()
        for entry in tools:
            name = entry["name"]
            try:
                result = self.check_tool(name)
            except KeyError as e:
                _logger.error(f"check_tool 内部错误: {e}")
                continue
            report.results.append(result)
            _logger.info(f"[{result.status}] {result.name}=={result.version}: {result.message}")
        return report


# =============================================================================
# VersionChecker — 统一版本校验入口（M3 阶段实现）
# =============================================================================


@dataclass
class VersionCheckReport:
    """统一版本校验报告（wheel + 工具）。"""

    wheel_report: WheelCheckReport = field(default_factory=WheelCheckReport)
    tool_report: ToolCheckReport = field(default_factory=ToolCheckReport)

    @property
    def overall(self) -> str:
        """总体状态：取 wheel 与 tool 中较严重者。"""
        wheel_overall = self.wheel_report.overall
        tool_overall = self.tool_report.overall
        # error > warn > ok
        severity = {"ok": 0, "warn": 1, "error": 2}
        if severity.get(wheel_overall, 0) >= severity.get(tool_overall, 0):
            return wheel_overall
        return tool_overall

    @property
    def passed(self) -> bool:
        """是否通过（wheel 与 tool 都无必选项 error）。"""
        return self.wheel_report.passed and self.tool_report.passed


class VersionChecker:
    """统一版本校验器（wheel + 外部工具）。

    组合 WheelChecker 与 ToolChecker，提供一站式校验入口。
    doctor.py 启动时调用 check_all() 即可完成全部完整性校验。

    用法：
        checker = VersionChecker(
            wheels_manifest=Path("vendor/wheels_manifest.yaml"),
            wheels_dir=Path("vendor/wheels"),
            tools_manifest=Path("tools/manifest.yaml"),
            project_root=Path("."),
        )
        report = checker.check_all()
        if not report.passed:
            print("版本校验失败")
    """

    def __init__(
        self,
        wheels_manifest: Path,
        wheels_dir: Path,
        tools_manifest: Path,
        project_root: Path,
        check_importable: bool = False,
    ) -> None:
        """初始化统一版本校验器。

        Args:
            wheels_manifest: vendor/wheels_manifest.yaml 路径
            wheels_dir: vendor/wheels/ 目录路径
            tools_manifest: tools/manifest.yaml 路径
            project_root: 项目根目录（用于解析工具 install_path 相对路径）
            check_importable: 是否同时校验 wheel 的 import 可用性（默认 False）
        """
        self.wheel_checker = WheelChecker(
            wheels_manifest=wheels_manifest,
            wheels_dir=wheels_dir,
            check_importable=check_importable,
        )
        self.tool_checker = ToolChecker(
            manifest_path=tools_manifest,
            project_root=project_root,
        )

    def check_all(self) -> VersionCheckReport:
        """执行全量校验（wheel + 工具）。

        Returns:
            VersionCheckReport 综合报告
        """
        wheel_report = self.wheel_checker.check_all()
        tool_report = self.tool_checker.check_all()
        return VersionCheckReport(wheel_report=wheel_report, tool_report=tool_report)

    def check_wheels(self) -> WheelCheckReport:
        """仅校验 wheel。"""
        return self.wheel_checker.check_all()

    def check_tools(self) -> ToolCheckReport:
        """仅校验外部工具。"""
        return self.tool_checker.check_all()
