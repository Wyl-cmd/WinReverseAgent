"""winreverse.tools.updater — 外部工具更新器。

职责：
1. 列出 manifest 中登记的工具及其安装状态（list_installed）
2. 检查可用更新（check_updates，对比 version 与 latest_known）
3. 下载 + 校验 + 替换 + 回滚（update / rollback / update_all）
4. 在线查询最新版本（fetch_latest_versions，支持 builtin/online 策略）

设计原则：
- 纯本地方法（list_installed / check_updates）无网络依赖
- 下载方法使用 Python 标准库 urllib，不引入额外依赖
- 与 version_checker.py 共享 manifest 加载逻辑，保持代码风格一致

参考：实施方案 §5.4、§5.8.3
"""

from __future__ import annotations

import hashlib
import http.client
import json
import shutil
import tempfile
import zipfile
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
class InstalledToolInfo:
    """单个工具的安装状态信息。

    Attributes:
        name: 工具名（如 'tshark'）
        version: manifest 中登记的当前版本
        installed: entry 文件是否存在（True=已安装）
        required: 是否为必选工具
        entry: 主可执行文件相对路径（如 'tshark.exe'）
        install_path: 安装目录（相对项目根，如 'tools/tshark/'）
    """

    name: str
    version: str
    installed: bool
    required: bool
    entry: str
    install_path: str


@dataclass
class UpdateInfo:
    """单个工具的可用更新信息。

    Attributes:
        name: 工具名
        current: 当前版本（manifest 中的 version 字段）
        latest: 最新已知版本（manifest 中的 latest_known 字段）
        required: 是否为必选工具
    """

    name: str
    current: str
    latest: str
    required: bool


@dataclass
class UpdateResult:
    """单个工具更新操作的结果。

    Attributes:
        name: 工具名
        success: 是否成功
        message: 状态说明（人可读）
    """

    name: str
    success: bool
    message: str


@dataclass
class UpdateAllReport:
    """批量更新报告。

    Attributes:
        results: 各工具的更新结果列表
    """

    results: list[UpdateResult] = field(default_factory=list)

    @property
    def success_count(self) -> int:
        """成功更新的工具数。"""
        return sum(1 for r in self.results if r.success)

    @property
    def failure_count(self) -> int:
        """更新失败的工具数。"""
        return sum(1 for r in self.results if not r.success)


# =============================================================================
# ToolUpdater — 外部工具更新器
# =============================================================================


class ToolUpdater:
    """外部工具更新器。

    读取 tools/manifest.yaml，提供工具安装状态查询、更新检查、
    下载/替换/回滚等功能。

    已实现功能：
    - list_installed: 列出工具及其安装状态（纯本地，无网络）
    - check_updates: 对比 version 与 latest_known，列出可用更新（纯本地）
    - fetch_latest_versions: 按策略组合查询最新版本（builtin/online）
    - update: 下载 → SHA256 校验 → 备份 → 解压 → 更新 manifest
    - update_all: 一键更新所有有新版本的工具
    - rollback: 用 .bak 目录回滚到旧版本

    用法：
        updater = ToolUpdater(
            manifest_path=Path("tools/manifest.yaml"),
            project_root=Path("."),
        )
        for tool in updater.list_installed():
            print(f"[{tool.name}] v{tool.version} installed={tool.installed}")
        for upd in updater.check_updates():
            print(f"{upd.name}: {upd.current} -> {upd.latest}")
    """

    def __init__(self, manifest_path: Path, project_root: Path) -> None:
        """初始化工具更新器。

        Args:
            manifest_path: tools/manifest.yaml 路径
            project_root: 项目根目录（用于解析 install_path 相对路径，
                判断 entry 文件是否存在）
        """
        self.manifest_path = manifest_path
        self.project_root = project_root
        self._manifest_data: dict[str, Any] | None = None

    # ------------------------- manifest 加载 -------------------------

    def _load_manifest(self) -> dict[str, Any]:
        """加载 manifest.yaml（带缓存）。

        Returns:
            manifest 字典

        Raises:
            FileNotFoundError: manifest 文件不存在
            yaml.YAMLError: manifest 格式错误
            ValueError: manifest 顶层结构非字典
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

    def _get_tool_entry(self, name: str) -> dict[str, Any]:
        """从 manifest 中获取指定工具的配置项。

        Args:
            name: 工具名

        Returns:
            工具配置字典

        Raises:
            KeyError: 工具名未在 manifest 中登记
        """
        manifest = self._load_manifest()
        tools = manifest.get("tools", [])
        entry = next((t for t in tools if isinstance(t, dict) and t.get("name") == name), None)
        if entry is None:
            raise KeyError(f"工具未在 manifest 中登记: {name}")
        if not isinstance(entry, dict):
            raise ValueError(
                f"manifest.yaml 中 {name} 配置项应为字典，实际为 {type(entry).__name__}"
            )
        return entry

    def _get_update_config(self) -> dict[str, Any]:
        """获取 manifest 中 update 段的配置。

        Returns:
            update 配置字典（default_source/custom_mirror/timeout_seconds 等）；
            若未配置或类型异常则返回空字典
        """
        manifest = self._load_manifest()
        cfg = manifest.get("update", {})
        if not isinstance(cfg, dict):
            return {}
        return cfg

    # ------------------------- 纯本地方法（M3 实现） -------------------------

    def list_installed(self) -> list[InstalledToolInfo]:
        """列出所有已登记工具及其安装状态。

        通过检查 entry 文件是否存在判断 installed 状态，
        不涉及任何网络请求。

        Returns:
            InstalledToolInfo 列表（按 manifest 中的登记顺序）
        """
        manifest = self._load_manifest()
        tools = manifest.get("tools", [])
        result: list[InstalledToolInfo] = []
        for tool in tools:
            name = tool["name"]
            version = tool["version"]
            entry = tool["entry"]
            install_path = tool["install_path"]
            required = tool.get("required", True)

            # entry 完整路径：project_root / install_path / entry
            entry_path = self.project_root / install_path / entry
            installed = entry_path.exists()

            info = InstalledToolInfo(
                name=name,
                version=version,
                installed=installed,
                required=required,
                entry=entry,
                install_path=install_path,
            )
            result.append(info)
            status = "OK" if installed else ("MISSING" if required else "OPTIONAL-MISSING")
            _logger.info(f"[{status}] {name} v{version} (entry={entry})")
        return result

    def check_updates(self) -> list[UpdateInfo]:
        """检查可用更新（对比 manifest 中 latest_known 与 version）。

        纯本地操作，不联网。仅返回 version != latest_known 的工具。

        Returns:
            UpdateInfo 列表（仅有可用更新的工具，按 manifest 登记顺序）
        """
        manifest = self._load_manifest()
        tools = manifest.get("tools", [])
        updates: list[UpdateInfo] = []
        for tool in tools:
            name = tool["name"]
            current = tool["version"]
            latest = tool.get("latest_known", current)
            required = tool.get("required", True)

            if current != latest:
                info = UpdateInfo(
                    name=name,
                    current=current,
                    latest=latest,
                    required=required,
                )
                updates.append(info)
                _logger.info(f"[UPDATE-AVAIL] {name}: {current} -> {latest}")
        return updates

    # ------------------------- 在线/下载方法 -------------------------

    def fetch_latest_versions(self, strategy: list[str] | None = None) -> dict[str, str]:
        """按策略组合获取所有工具的最新版本号。

        策略（可组合）：
        - "builtin": 使用 manifest 中的 latest_known 字段（纯本地，无网络）
        - "online": 调用 GitHub Releases API 在线查询（需要网络）

        Args:
            strategy: 策略列表，默认 ["builtin"]

        Returns:
            {工具名: 最新版本号} 字典
        """
        strategies = strategy if strategy is not None else ["builtin"]
        result: dict[str, str] = {}
        manifest = self._load_manifest()
        tools = manifest.get("tools", [])

        # builtin 策略：从 manifest 读取 latest_known
        if "builtin" in strategies:
            for tool in tools:
                name = tool["name"]
                latest = tool.get("latest_known", tool.get("version", ""))
                if latest:
                    result[name] = latest

        # online 策略：调用 GitHub Releases API
        if "online" in strategies:
            for tool in tools:
                name = tool["name"]
                url = tool.get("download_url", "")
                github_tag = self._extract_github_tag(url)
                if github_tag is None:
                    # 非 GitHub 源，保留 builtin 结果
                    continue
                online_version = self._fetch_github_latest(github_tag)
                if online_version:
                    result[name] = online_version
                    _logger.info(f"[ONLINE] {name} 最新版本: {online_version}")

        return result

    @staticmethod
    def _extract_github_tag(url: str) -> str | None:
        """从 GitHub 下载 URL 中提取 owner/repo。

        Args:
            url: download_url 字符串

        Returns:
            "owner/repo" 字符串，非 GitHub 源返回 None
        """
        if "github.com" not in url:
            return None
        parts = url.split("/")
        try:
            idx = parts.index("github.com")
            if idx + 2 < len(parts):
                return f"{parts[idx + 1]}/{parts[idx + 2]}"
        except ValueError:
            pass
        return None

    @staticmethod
    def _fetch_github_latest(repo: str) -> str | None:
        """调用 GitHub Releases API 获取最新版本号。

        Args:
            repo: "owner/repo" 格式的仓库标识

        Returns:
            最新版本号字符串（如 "4.6.7"），失败返回 None
        """
        api_url = f"https://api.github.com/repos/{repo}/releases/latest"
        try:
            req = Request(api_url, headers={"Accept": "application/vnd.github+json"})
            with urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                tag = data.get("tag_name", "")
                # tag_name 通常是 "v4.6.7" 或 "4.6.7"，去掉前缀 v
                if tag.startswith("v"):
                    tag = tag[1:]
                return tag if tag else None
        except (HTTPError, URLError, OSError, json.JSONDecodeError) as e:
            _logger.warning(f"GitHub API 查询失败 {repo}: {e}")
            return None

    def update(self, tool_name: str, force: bool = False) -> UpdateResult:
        """更新指定工具到最新版本。

        完整流程：
        1. 下载 zip 到临时目录
        2. SHA256 校验下载包（对照 package_sha256，失败则删除并重试）
        3. 备份旧版本到 <name>.bak/
        4. 解压新版本到 install_path
        5. 回填 manifest：package_sha256 = 下载包哈希，sha256 = entry exe 哈希

        字段语义（与 ToolChecker 对齐）：
        - sha256: 解压后 entry 可执行文件的哈希（ToolChecker 校验对象）
        - package_sha256: 下载 zip 包的哈希（更新器下载校验对象）

        Args:
            tool_name: 工具名
            force: True 表示强制重新下载当前版本（不升级，仅重装）

        Returns:
            UpdateResult 更新结果
        """
        try:
            tool_entry = self._get_tool_entry(tool_name)
        except KeyError as e:
            return UpdateResult(name=tool_name, success=False, message=str(e))

        download_url = tool_entry.get("download_url", "")
        expected_package_sha = str(tool_entry.get("package_sha256", "") or "")
        install_path = tool_entry.get("install_path", f"tools/{tool_name}/")
        latest_version = tool_entry.get("latest_known", tool_entry.get("version", ""))
        download_format = str(tool_entry.get("download_format", "zip")).lower()

        if not download_url:
            return UpdateResult(
                name=tool_name,
                success=False,
                message=f"manifest 中 {tool_name} 无 download_url",
            )

        update_cfg = self._get_update_config()
        retry_times = int(update_cfg.get("retry_times", 3))
        timeout = int(update_cfg.get("timeout_seconds", 600))

        _logger.info(f"[UPDATE] 开始更新 {tool_name} -> v{latest_version}")

        # 1. 下载（带重试）。非 zip 格式（如 paf.exe 自解压包）下载后
        #    只做校验并提示手动安装，因为标准库无法解压 7z SFX / NSIS 载荷
        if download_format != "zip":
            return self._update_non_zip(
                tool_name=tool_name,
                download_url=download_url,
                download_format=download_format,
                expected_package_sha=expected_package_sha,
                retry_times=retry_times,
                timeout=timeout,
            )

        zip_path = self._download_with_retry(download_url, tool_name, retry_times, timeout)
        if zip_path is None:
            return UpdateResult(
                name=tool_name,
                success=False,
                message=f"下载失败（重试 {retry_times} 次后仍失败）",
            )

        # 2. SHA256 校验或计算（校验对象为下载的 zip 包）
        actual_sha256 = self._compute_sha256(zip_path)
        if expected_package_sha:
            if actual_sha256 != expected_package_sha:
                zip_path.unlink(missing_ok=True)
                return UpdateResult(
                    name=tool_name,
                    success=False,
                    message=f"SHA256 校验失败: 期望 {expected_package_sha[:16]}... 实际 {actual_sha256[:16]}...",
                )
            _logger.info(f"[SHA256] {tool_name} 校验通过")
        else:
            _logger.info(
                f"[SHA256] {tool_name} 无预设 package_sha256，计算并回填: {actual_sha256[:16]}..."
            )

        # 3. 备份旧版本到 .bak/（备份失败时尚未触碰 install_dir，安全中止）
        install_dir = self.project_root / install_path
        bak_dir = self.project_root / f"{install_path.rstrip('/')}.bak"
        if install_dir.exists():
            try:
                if bak_dir.exists():
                    shutil.rmtree(bak_dir)
                shutil.move(str(install_dir), str(bak_dir))
                _logger.info(f"[BACKUP] 旧版本已备份到 {bak_dir}")
            except OSError as e:
                zip_path.unlink(missing_ok=True)
                return UpdateResult(
                    name=tool_name,
                    success=False,
                    message=f"备份旧版本失败: {e}",
                )

        # 4. 解压新版本到 install_path
        try:
            install_dir.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(str(install_dir))
            _logger.info(f"[EXTRACT] 已解压到 {install_dir}")
        except (zipfile.BadZipFile, OSError) as e:
            # 解压失败，回滚备份（先移除新建的安装目录，
            # 否则 shutil.move 会把备份嵌套进该目录而非替换它）
            if install_dir.exists():
                shutil.rmtree(install_dir)
            if bak_dir.exists():
                shutil.move(str(bak_dir), str(install_dir))
            zip_path.unlink(missing_ok=True)
            return UpdateResult(
                name=tool_name,
                success=False,
                message=f"解压失败: {e}",
            )

        # 5. 回填 manifest：package_sha256 = 下载包哈希，sha256 = entry exe 哈希。
        #    新版本已解压就位，回填失败不回滚安装，但须按契约返回 UpdateResult
        #    而非裸异常，并清理临时 zip
        try:
            self._update_manifest_field(tool_name, "version", latest_version)
            self._update_manifest_field(tool_name, "package_sha256", actual_sha256)
            entry_sha = self._compute_entry_sha256(tool_name)
            self._update_manifest_field(tool_name, "sha256", entry_sha)
            self._save_manifest()
        except (OSError, yaml.YAMLError) as e:
            zip_path.unlink(missing_ok=True)
            return UpdateResult(
                name=tool_name,
                success=False,
                message=f"清单回填失败（新版本文件已解压到 {install_dir}）: {e}",
            )

        # 清理临时文件
        zip_path.unlink(missing_ok=True)

        _logger.info(f"[DONE] {tool_name} 更新完成 v{latest_version}")
        return UpdateResult(
            name=tool_name,
            success=True,
            message=f"已更新到 v{latest_version} (entry SHA256: {entry_sha[:16]}...)",
        )

    def _compute_entry_sha256(self, tool_name: str) -> str:
        """计算工具 entry 可执行文件的 SHA256。

        Returns:
            64 字符十六进制哈希；entry 不存在或读取失败时返回空字符串
        """
        try:
            tool_entry = self._get_tool_entry(tool_name)
        except (KeyError, ValueError):
            return ""
        entry_rel = str(tool_entry.get("entry", ""))
        install_path = str(tool_entry.get("install_path", f"tools/{tool_name}/"))
        if not entry_rel:
            return ""
        entry_path = self.project_root / install_path / entry_rel
        if not entry_path.is_file():
            return ""
        try:
            return self._compute_sha256(entry_path)
        except OSError:
            return ""

    def _update_non_zip(
        self,
        *,
        tool_name: str,
        download_url: str,
        download_format: str,
        expected_package_sha: str,
        retry_times: int,
        timeout: int,
    ) -> UpdateResult:
        """处理非 zip 格式的工具更新（下载 + 校验，不自动解压）。

        官方仅提供自解压安装包（paf.exe / NSIS 安装器）的工具无法用标准库
        zipfile 解压，此处下载到 downloads/ 目录并完成 SHA256 校验后，
        返回携带手动安装指引的结果。

        Args:
            tool_name: 工具名
            download_url: 下载 URL
            download_format: 下载格式（如 'paf_exe' / 'exe'）
            expected_package_sha: manifest 中的期望下载包 SHA256（package_sha256）
            retry_times: 最大重试次数
            timeout: 超时秒数

        Returns:
            UpdateResult（success=False，但文件已就绪，message 含路径与指引）
        """
        dest_dir = self.project_root / "downloads"
        file_path = self._download_with_retry(
            download_url,
            tool_name,
            retry_times,
            timeout,
            dest_dir=dest_dir,
        )
        if file_path is None:
            return UpdateResult(
                name=tool_name,
                success=False,
                message=f"下载失败（重试 {retry_times} 次后仍失败）",
            )

        actual_sha256 = self._compute_sha256(file_path)
        if expected_package_sha:
            if actual_sha256 != expected_package_sha:
                file_path.unlink(missing_ok=True)
                return UpdateResult(
                    name=tool_name,
                    success=False,
                    message=(
                        f"SHA256 校验失败: 期望 {expected_package_sha[:16]}... "
                        f"实际 {actual_sha256[:16]}..."
                    ),
                )
            _logger.info(f"[SHA256] {tool_name} 校验通过")
        else:
            self._update_manifest_field(tool_name, "package_sha256", actual_sha256)
            self._save_manifest()
            _logger.info(f"[SHA256] {tool_name} 无预设 package_sha256，计算并回填")

        message = (
            f"{tool_name} 官方仅提供 {download_format} 格式（无 zip 便携包），"
            f"不支持自动解压。安装包已下载并校验: {file_path}，"
            f"请手动运行安装（目标目录 tools/{tool_name}/），"
            f"完成后用 'winreverse tools verify {tool_name}' 校验。"
        )
        _logger.warning(f"[MANUAL] {message}")
        return UpdateResult(name=tool_name, success=False, message=message)

    def _download_with_retry(
        self,
        url: str,
        tool_name: str,
        retry_times: int,
        timeout: int,
        dest_dir: Path | None = None,
    ) -> Path | None:
        """下载文件（带重试）。

        Args:
            url: 下载 URL
            tool_name: 工具名（用于命名临时文件）
            retry_times: 最大重试次数
            timeout: 超时秒数
            dest_dir: 目标目录（None 表示系统临时目录 + .zip 后缀；
                指定时直接以 URL 文件名落盘，用于非 zip 格式）

        Returns:
            下载的文件路径，失败返回 None
        """
        for attempt in range(1, retry_times + 1):
            try:
                _logger.info(f"[DOWNLOAD] {tool_name} 第 {attempt}/{retry_times} 次尝试: {url}")
                if dest_dir is None:
                    tmp_dir = Path(tempfile.gettempdir())
                    zip_path = tmp_dir / f"winreverse_{tool_name}.zip"
                else:
                    tmp_dir = dest_dir
                    tmp_dir.mkdir(parents=True, exist_ok=True)
                    url_filename = url.rstrip("/").rsplit("/", 1)[-1]
                    zip_path = tmp_dir / url_filename

                req = Request(url, headers={"User-Agent": "WinReverseAgent/1.0"})
                with (
                    urlopen(req, timeout=timeout) as resp,
                    zip_path.open("wb") as f,
                ):
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        f.write(chunk)

                _logger.info(f"[DOWNLOAD] {tool_name} 下载完成: {zip_path}")
                return zip_path
            except (HTTPError, URLError, OSError, http.client.HTTPException) as e:
                # IncompleteRead 等 HTTP 协议级错误（截断下载）正是重试的目标场景
                _logger.warning(f"[DOWNLOAD] {tool_name} 第 {attempt} 次失败: {e}")
                if attempt < retry_times:
                    continue
                return None
        return None

    @staticmethod
    def _compute_sha256(file_path: Path) -> str:
        """计算文件的 SHA256 哈希值。

        Args:
            file_path: 文件路径

        Returns:
            64 字符的十六进制 SHA256 字符串
        """
        sha256 = hashlib.sha256()
        with file_path.open("rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()

    def _update_manifest_field(self, tool_name: str, field_name: str, value: str) -> None:
        """更新 manifest 中指定工具的指定字段值。

        Args:
            tool_name: 工具名
            field_name: 字段名（如 'version' / 'sha256'）
            value: 新值
        """
        manifest = self._load_manifest()
        tools = manifest.get("tools", [])
        for tool in tools:
            if tool.get("name") == tool_name:
                tool[field_name] = value
                break

    def _save_manifest(self) -> None:
        """将当前 manifest 数据写回 manifest.yaml 文件。"""
        manifest = self._load_manifest()
        with self.manifest_path.open("w", encoding="utf-8") as f:
            yaml.dump(manifest, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        _logger.info(f"[MANIFEST] 已更新 {self.manifest_path}")

    def update_all(self) -> UpdateAllReport:
        """一键更新所有有新版本的工具。

        遍历 check_updates() 返回的工具列表，逐个调用 update()。

        Returns:
            UpdateAllReport 批量更新报告
        """
        updates = self.check_updates()
        report = UpdateAllReport()

        if not updates:
            _logger.info("[UPDATE-ALL] 无可用更新")
            return report

        _logger.info(f"[UPDATE-ALL] 共 {len(updates)} 个工具需要更新")
        for upd in updates:
            _logger.info(f"[UPDATE-ALL] 正在更新 {upd.name}: {upd.current} -> {upd.latest}")
            result = self.update(upd.name)
            report.results.append(result)

        _logger.info(f"[UPDATE-ALL] 完成: 成功 {report.success_count}，失败 {report.failure_count}")
        return report

    def rollback(self, tool_name: str) -> UpdateResult:
        """回滚到备份的旧版本。

        流程：
        1. 检查 <install_path>.bak/ 目录是否存在
        2. 将当前版本移到 .bak.new/，将 .bak/ 移到 install_path
        3. 将 .bak.new/ 重命名为 .bak/（保留当前版本作为新备份）
        4. 更新 manifest.yaml 中的 version 字段

        Args:
            tool_name: 工具名

        Returns:
            UpdateResult 回滚结果
        """
        try:
            tool_entry = self._get_tool_entry(tool_name)
        except KeyError as e:
            return UpdateResult(name=tool_name, success=False, message=str(e))

        install_path = tool_entry.get("install_path", f"tools/{tool_name}/")
        install_dir = self.project_root / install_path
        bak_dir = self.project_root / f"{install_path.rstrip('/')}.bak"
        bak_new_dir = self.project_root / f"{install_path.rstrip('/')}.bak.new"

        # 1. 检查 .bak/ 目录是否存在
        if not bak_dir.exists():
            return UpdateResult(
                name=tool_name,
                success=False,
                message=f"备份目录不存在: {bak_dir}（无法回滚）",
            )

        # 2. 交换当前版本和备份版本
        try:
            # 将当前版本移到 .bak.new/
            if install_dir.exists():
                if bak_new_dir.exists():
                    shutil.rmtree(bak_new_dir)
                shutil.move(str(install_dir), str(bak_new_dir))

            # 将 .bak/ 移到 install_path
            shutil.move(str(bak_dir), str(install_dir))

            # 将 .bak.new/ 重命名为 .bak/（保留当前版本作为新备份）
            if bak_new_dir.exists():
                shutil.move(str(bak_new_dir), str(bak_dir))

            _logger.info(f"[ROLLBACK] {tool_name} 已回滚到备份版本")
        except OSError as e:
            # 恢复失败，尝试修复目录状态
            if bak_new_dir.exists() and not install_dir.exists():
                shutil.move(str(bak_new_dir), str(install_dir))
            return UpdateResult(
                name=tool_name,
                success=False,
                message=f"回滚失败: {e}",
            )

        # 3. 更新 manifest 中的 version 字段（从备份的 manifest 读取旧版本）
        # 注意：备份目录中可能没有 manifest，我们只能标记为"已回滚"
        # 精确的版本号需要用户手动检查或通过 ToolChecker 重新校验
        current_version = tool_entry.get("version", "")
        _logger.info(f"[ROLLBACK] {tool_name} 已回滚（回滚前版本 v{current_version}）")

        return UpdateResult(
            name=tool_name,
            success=True,
            message=f"已回滚到备份版本（回滚前 v{current_version}）",
        )
