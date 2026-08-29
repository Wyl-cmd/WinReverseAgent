"""winreverse.forensics.android.adb — adb 桥接层（取证采集与设备操作）。

封装 adb 子进程调用，面向木马分析与取证场景：
- 只读采集：设备属性（getprop）、包/进程列表、文件拉取、logcat、截图
- 可写操作（木马分析需要）：推送文件、安装/卸载 APK、通用 shell 命令
  （部署采样代理、拉取私有目录、触发行为等）
- 无线调试（Android 11+ 网络远程调试）：connect / pair / tcpip 模式

adb 二进制解析顺序：显式 adb_path → 项目 tools/adb/adb.exe → PATH。
所有命令带超时；可写操作不影响只读采集 API。

许可证边界：adb 属 Google platform-tools（官方 zip 由 tools/updater 下载），
本模块不携带任何 adb 二进制。
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# 单条 adb 命令默认超时（秒）
_DEFAULT_TIMEOUT = 30
# adb pull/push 大文件超时
_TRANSFER_TIMEOUT = 600
# 无线配对码格式（Android 11+：6 位数字）
_PAIR_CODE_PATTERN = re.compile(r"^\d{6}$")


class AdbError(RuntimeError):
    """adb 调用失败的统一异常（二进制缺失 / 设备离线 / 命令失败）。"""


@dataclass
class DeviceInfo:
    """设备属性快照。

    Attributes:
        serial: 设备序列号
        state: 设备状态（device / offline / unauthorized）
        model: 型号
        brand: 品牌
        android_version: Android 版本
        build_id: 构建号
        security_patch: 安全补丁级别
        api_level: SDK API 级别
        extra: 其他 getprop 属性（ro. 前缀关键项）
    """

    serial: str
    state: str
    model: str = ""
    brand: str = ""
    android_version: str = ""
    build_id: str = ""
    security_patch: str = ""
    api_level: str = ""
    extra: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, str | None]:
        """转为 JSON 兼容字典。"""
        return {
            "serial": self.serial,
            "state": self.state,
            "model": self.model,
            "brand": self.brand,
            "android_version": self.android_version,
            "build_id": self.build_id,
            "security_patch": self.security_patch,
            "api_level": self.api_level,
        }


class AdbClient:
    """adb 子进程客户端（只读取证操作）。

    用法：
        adb = AdbClient()                # 自动解析 adb 路径
        devices = adb.list_devices()
        info = adb.get_device_info(devices[0].serial)
    """

    def __init__(self, adb_path: str | Path | None = None) -> None:
        """初始化 adb 客户端。

        Args:
            adb_path: adb 可执行文件路径（None 时按
                tools/adb/adb.exe → PATH 顺序解析）

        Raises:
            AdbError: 找不到可用的 adb 二进制
        """
        self._adb_path = self._resolve_adb(adb_path)

    @staticmethod
    def _resolve_adb(adb_path: str | Path | None) -> Path:
        """按 显式路径 → tools/adb/adb.exe → PATH 顺序解析 adb。"""
        candidates: list[Path] = []
        if adb_path is not None:
            candidates.append(Path(adb_path))
        # 项目内 tools/adb/（platform-tools zip 解压布局）
        candidates.append(Path.cwd() / "tools" / "adb" / "platform-tools" / "adb.exe")
        candidates.append(Path.cwd() / "tools" / "adb" / "adb.exe")
        for candidate in candidates:
            if candidate.is_file():
                return candidate
        which = shutil.which("adb")
        if which:
            return Path(which)
        raise AdbError(
            "找不到 adb。请通过 'winreverse tools update adb' 下载 platform-tools，"
            "或安装 Android SDK platform-tools 后加入 PATH"
        )

    @property
    def adb_path(self) -> Path:
        """adb 二进制路径。"""
        return self._adb_path

    def _run(self, args: list[str], *, timeout: int = _DEFAULT_TIMEOUT) -> str:
        """执行 adb 命令并返回 stdout。

        Raises:
            AdbError: 命令失败或超时
        """
        cmd = [str(self._adb_path), *args]
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as e:
            raise AdbError(f"adb 二进制不可用: {self._adb_path}") from e
        except subprocess.TimeoutExpired as e:
            raise AdbError(f"adb 命令超时: {' '.join(args)}") from e
        if completed.returncode != 0:
            stderr = completed.stderr.strip()
            raise AdbError(f"adb 命令失败: {' '.join(args)}: {stderr}")
        return completed.stdout

    def _run_for_device(
        self, serial: str, args: list[str], *, timeout: int = _DEFAULT_TIMEOUT
    ) -> str:
        """对指定设备执行 adb 命令。"""
        return self._run(["-s", serial, *args], timeout=timeout)

    # ------------------------- 设备与信息采集 -------------------------

    def list_devices(self) -> list[DeviceInfo]:
        """列出当前连接的设备及其状态。"""
        output = self._run(["devices", "-l"])
        devices: list[DeviceInfo] = []
        for line in output.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            serial, state = parts[0], parts[1]
            model = ""
            for part in parts[2:]:
                if part.startswith("model:"):
                    model = part.removeprefix("model:")
                    break
            devices.append(DeviceInfo(serial=serial, state=state, model=model))
        return devices

    def get_device_info(self, serial: str) -> DeviceInfo:
        """采集设备属性快照（getprop，只读）。

        Raises:
            AdbError: 设备离线或未授权
        """
        output = self._run_for_device(serial, ["shell", "getprop"])
        props: dict[str, str] = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("[") and "]: [" in line:
                key, _, value = line.partition("]: [")
                props[key.removeprefix("[")] = value.rstrip("]")

        extra_keys = [
            "ro.build.fingerprint",
            "ro.build.date.utc",
            "ro.boot.serialno",
            "ro.product.cpu.abi",
        ]
        return DeviceInfo(
            serial=serial,
            state="device",
            model=props.get("ro.product.model", ""),
            brand=props.get("ro.product.brand", ""),
            android_version=props.get("ro.build.version.release", ""),
            build_id=props.get("ro.build.display.id", ""),
            security_patch=props.get("ro.build.version.security_patch", ""),
            api_level=props.get("ro.build.version.sdk", ""),
            extra={k: props[k] for k in extra_keys if k in props},
        )

    def list_packages(self, serial: str, *, third_party_only: bool = True) -> list[str]:
        """列出已安装包名（默认仅第三方应用，取证关注面）。"""
        args = ["shell", "pm", "list", "packages"]
        if third_party_only:
            args.append("-3")
        output = self._run_for_device(serial, args)
        packages = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                packages.append(line.removeprefix("package:"))
        return sorted(packages)

    def list_processes(self, serial: str) -> list[dict[str, str]]:
        """列出进程快照（ps -A，只读）。"""
        output = self._run_for_device(serial, ["shell", "ps", "-A"])
        processes: list[dict[str, str]] = []
        lines = output.splitlines()
        # 首行为表头：USER PID PPID VSZ RSS WCHAN ADDR S NAME
        header = lines[0].split() if lines else []
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            row = dict(zip(header, parts, strict=False))
            processes.append(
                {
                    "user": row.get("USER", ""),
                    "pid": row.get("PID", ""),
                    "name": row.get("NAME", parts[-1]),
                }
            )
        return processes

    def get_kernel_release(self, serial: str) -> str:
        """查询设备内核版本（uname -r，LiME 模块匹配用）。

        Returns:
            内核版本字符串；查询失败返回空字符串
        """
        try:
            output = self._run_for_device(serial, ["shell", "uname", "-r"])
        except AdbError:
            return ""
        return output.strip().splitlines()[0].strip() if output.strip() else ""

    def pull_file(self, serial: str, remote_path: str, local_path: str | Path) -> Path:
        """拉取设备文件到本地（取证归档用，只读）。

        Returns:
            本地文件/目录路径

        Raises:
            AdbError: 拉取失败（权限不足 / 路径不存在）
        """
        local = Path(local_path)
        local.parent.mkdir(parents=True, exist_ok=True)
        self._run_for_device(serial, ["pull", remote_path, str(local)], timeout=_TRANSFER_TIMEOUT)
        if not local.exists():
            raise AdbError(f"adb pull 未产出本地文件: {remote_path} → {local}")
        return local

    # ------------------------- 可写操作（木马分析） -------------------------

    def shell_command(self, serial: str, command: str, *, timeout: int = _DEFAULT_TIMEOUT) -> str:
        """在设备上执行任意 shell 命令并返回输出。

        木马分析用途：部署/触发采样代理、查看私有目录、top/logcat 等。

        Args:
            serial: 设备序列号
            command: 完整 shell 命令串（如 'su -c ls /data/data'）
            timeout: 超时秒数

        Raises:
            AdbError: 命令失败
        """
        return self._run_for_device(serial, ["shell", command], timeout=timeout)

    def push_file(self, serial: str, local_path: str | Path, remote_path: str) -> str:
        """推送本地文件到设备（如部署采样代理/测试载荷）。

        Returns:
            设备侧目标路径

        Raises:
            AdbError: 推送失败
        """
        local = Path(local_path)
        if not local.is_file():
            raise AdbError(f"本地文件不存在: {local}")
        self._run_for_device(serial, ["push", str(local), remote_path], timeout=_TRANSFER_TIMEOUT)
        return remote_path

    def install_apk(self, serial: str, apk_path: str | Path, *, replace: bool = True) -> str:
        """安装 APK 到设备（部署监控代理/测试样本）。

        Args:
            serial: 设备序列号
            apk_path: 本地 APK 路径
            replace: 已存在时是否覆盖安装（adb install -r）

        Returns:
            adb install 输出

        Raises:
            AdbError: 安装失败
        """
        apk = Path(apk_path)
        if not apk.is_file():
            raise AdbError(f"APK 不存在: {apk}")
        args = ["install"]
        if replace:
            args.append("-r")
        args.append(str(apk))
        return self._run_for_device(serial, args, timeout=_TRANSFER_TIMEOUT)

    def uninstall(self, serial: str, package: str) -> str:
        """从设备卸载指定包（分析后清理采样代理/样本）。"""
        return self._run_for_device(serial, ["uninstall", package])

    def logcat(self, serial: str, *, lines: int = 200, filter_tag: str = "") -> str:
        """抓取设备日志缓冲（行为分析线索，只读）。

        Args:
            serial: 设备序列号
            lines: 最近条数
            filter_tag: 可选标签过滤（传给 logcat -s）

        Returns:
            日志文本
        """
        command = f"logcat -d -t {lines}"
        if filter_tag:
            command += f" -s {filter_tag}"
        return self._run_for_device(serial, ["shell", command], timeout=60)

    def screenshot(self, serial: str, local_path: str | Path) -> Path:
        """截取设备当前屏幕（行为记录取证）。

        使用 exec-out 原始字节输出（screencap -p 的 PNG 经文本解码会被
        破坏，因此不走 _run 的文本模式）。

        Args:
            serial: 设备序列号
            local_path: 本地 PNG 保存路径

        Returns:
            本地 PNG 路径

        Raises:
            AdbError: 截图失败
        """
        local = Path(local_path)
        local.parent.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            [str(self._adb_path), "-s", serial, "exec-out", "screencap", "-p"],
            capture_output=True,
            timeout=60,
            check=False,
        )
        if completed.returncode != 0 or not completed.stdout:
            stderr = completed.stderr.decode("utf-8", "replace")
            raise AdbError(f"截图失败: {stderr[:200]}")
        local.write_bytes(completed.stdout)
        return local

    # ------------------------- 无线调试（Android 11+ 网络远程调试） -------------------------

    def connect(self, host_port: str) -> str:
        """通过网络连接设备（adb connect ip:port）。

        适用 Android 11+ 的无线调试，或同一局域网内已开启
        tcpip 模式的设备，实现无 USB 的远程调试。

        Args:
            host_port: 'ip:port'（无线调试页显示的 IP 与端口）

        Returns:
            adb 输出（含 connected / failed 信息）
        """
        return self._run(["connect", host_port], timeout=30)

    def pair(self, host_port: str, pairing_code: str) -> str:
        """无线调试首次配对（Android 11+，adb pair）。

        在设备「开发者选项 → 无线调试 → 使用配对码配对设备」页面
        获取 ip:port 与 6 位配对码后调用；配对成功后再 connect 常规端口。

        Args:
            host_port: 配对页显示的 'ip:pairing_port'
            pairing_code: 6 位数字配对码

        Returns:
            adb 输出

        Raises:
            AdbError: 配对码格式非法
        """
        if not _PAIR_CODE_PATTERN.match(pairing_code):
            raise AdbError(f"配对码应为 6 位数字，实际: {pairing_code!r}")
        if host_port.count(":") != 1:
            raise AdbError(f"配对地址应为 'ip:配对端口'，实际: {host_port!r}")
        return self._run(["pair", host_port, pairing_code], timeout=30)

    def tcpip_mode(self, serial: str, port: int = 5555) -> str:
        """将 USB 连接的设备切换为 TCP/IP 监听模式（adb tcpip <port>）。

        切换后可拔掉 USB，用 connect('ip:port') 走网络远程调试。
        """
        return self._run_for_device(serial, ["tcpip", str(port)])

    def usb_mode(self, serial: str) -> str:
        """切回 USB 模式（adb usb）。"""
        return self._run_for_device(serial, ["usb"])

    def disconnect(self, host_port: str | None = None) -> str:
        """断开网络连接的设备（全部或指定 ip:port）。"""
        args = ["disconnect"] + ([host_port] if host_port else [])
        return self._run(args)
