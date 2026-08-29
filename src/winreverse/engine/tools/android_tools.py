"""winreverse.engine.tools.android_tools — Android 取证工具。

将 forensics.android 的采集与分析能力封装为 ToolInterface 实现。

工具清单：
- android.devices: 列出已连接设备
- android.info: 采集设备属性快照
- android.packages: 采集第三方应用清单
- android.pull: 拉取设备文件
- android.lime_guide: 生成 LiME 内存采集引导（GPL 隔离）
- android.analyze_image: Volatility 3 白名单插件分析内存镜像

依赖边界（均不随项目分发）：
- adb：tools/adb/ 或 PATH（winreverse tools update adb 可下载官方 platform-tools）
- volatility3：用户显式安装（VSL 许可），android.analyze_image 失败时给出指引

参考：实施方案 §10（木马行为分析）、forensics/android/ 各模块 docstring
"""

from __future__ import annotations

from typing import Any

from winreverse.engine.tools._base import BaseTool
from winreverse.forensics.android.adb import AdbClient
from winreverse.forensics.android.lime import build_lime_guide
from winreverse.forensics.android.volatility import VolatilityBridge


class AndroidDevicesTool(BaseTool):
    """android.devices — 列出已连接设备。"""

    name = "android.devices"
    description = "列出 adb 已连接的 Android 设备及状态（需 platform-tools/adb）"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        adb_path = input_data.get("adb_path")
        adb = AdbClient(adb_path) if adb_path else AdbClient()
        devices = adb.list_devices()
        return {
            "adb_path": str(adb.adb_path),
            "count": len(devices),
            "devices": [d.to_dict() for d in devices],
        }


class AndroidInfoTool(BaseTool):
    """android.info — 采集设备属性快照。"""

    name = "android.info"
    description = "采集指定设备的 getprop 属性快照（型号/Android 版本/补丁级别等，只读）"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        serial = str(self._require(input_data, "serial"))
        adb_path = input_data.get("adb_path")
        adb = AdbClient(adb_path) if adb_path else AdbClient()
        info = adb.get_device_info(serial)
        return info.to_dict()


class AndroidPackagesTool(BaseTool):
    """android.packages — 采集第三方应用清单。"""

    name = "android.packages"
    description = "列出设备已安装的第三方应用包名（取证关注面，只读）"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        serial = str(self._require(input_data, "serial"))
        adb_path = input_data.get("adb_path")
        adb = AdbClient(adb_path) if adb_path else AdbClient()
        packages = adb.list_packages(serial, third_party_only=True)
        return {"serial": serial, "count": len(packages), "packages": packages}


class AndroidPullTool(BaseTool):
    """android.pull — 拉取设备文件。"""

    name = "android.pull"
    description = "从设备拉取文件到本地（只读取证归档，如 /data/... 需对应权限）"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        serial = str(self._require(input_data, "serial"))
        remote_path = str(self._require(input_data, "remote_path"))
        local_path = str(self._require(input_data, "local_path"))
        adb_path = input_data.get("adb_path")
        adb = AdbClient(adb_path) if adb_path else AdbClient()
        result_path = adb.pull_file(serial, remote_path, local_path)
        return {"serial": serial, "remote_path": remote_path, "local_path": str(result_path)}


class AndroidLimeGuideTool(BaseTool):
    """android.lime_guide — 生成 LiME 内存采集引导。"""

    name = "android.lime_guide"
    description = (
        "生成 LiME（GPL-2.0）内核内存采集的命令清单与前置条件说明；"
        "本工具只做引导，不分发、不执行 LiME 二进制"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        serial = str(self._require(input_data, "serial"))
        guide = build_lime_guide(
            serial,
            kernel_release=str(input_data.get("kernel_release", "")),
            local_module_path=str(input_data.get("local_module_path", "lime.ko")),
            dump_path=str(input_data.get("dump_path", "/data/local/tmp/ram.lime")),
        )
        return guide.to_dict()


class AndroidAnalyzeImageTool(BaseTool):
    """android.analyze_image — Volatility 3 白名单插件分析内存镜像。"""

    name = "android.analyze_image"
    description = (
        "用 Volatility 3（VSL 许可，需用户自行安装）分析内存镜像"
        "（Linux LiME raw 或 Windows minidump），仅允许白名单插件"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        image_path = str(self._require(input_data, "image_path"))
        plugin = str(self._require(input_data, "plugin"))
        vol_path = input_data.get("vol_path")
        bridge = VolatilityBridge(vol_path) if vol_path else VolatilityBridge()
        analysis = bridge.analyze(image_path, plugin, extra_args=input_data.get("extra_args"))
        return analysis.to_dict()


class AndroidShellTool(BaseTool):
    """android.shell — 设备 shell 命令（可写，木马分析用）。"""

    name = "android.shell"
    description = (
        "在设备上执行任意 shell 命令（可写）：部署/触发采样代理、查看私有目录、"
        "top/logcat 等；需要设备授权，root 操作需自行加 su -c"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        serial = str(self._require(input_data, "serial"))
        command = str(self._require(input_data, "command"))
        adb_path = input_data.get("adb_path")
        adb = AdbClient(adb_path) if adb_path else AdbClient()
        output = adb.shell_command(serial, command)
        return {"serial": serial, "command": command, "output": output[:8000]}


class AndroidPushTool(BaseTool):
    """android.push — 推送文件到设备（可写）。"""

    name = "android.push"
    description = "推送本地文件到设备（部署采样代理/测试载荷到 /data/local/tmp 等）"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        serial = str(self._require(input_data, "serial"))
        local_path = str(self._require(input_data, "local_path"))
        remote_path = str(self._require(input_data, "remote_path"))
        adb_path = input_data.get("adb_path")
        adb = AdbClient(adb_path) if adb_path else AdbClient()
        result = adb.push_file(serial, local_path, remote_path)
        return {"serial": serial, "remote_path": result}


class AndroidInstallTool(BaseTool):
    """android.install — 安装 APK（可写，部署监控代理/样本）。"""

    name = "android.install"
    description = "安装本地 APK 到设备（覆盖安装用 replace=true），分析后可用 android.shell 卸载"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        serial = str(self._require(input_data, "serial"))
        apk_path = str(self._require(input_data, "apk_path"))
        adb_path = input_data.get("adb_path")
        adb = AdbClient(adb_path) if adb_path else AdbClient()
        output = adb.install_apk(serial, apk_path, replace=bool(input_data.get("replace", True)))
        return {"serial": serial, "apk": apk_path, "output": output[:2000]}


class AndroidLogcatTool(BaseTool):
    """android.logcat — 抓取设备日志（行为线索）。"""

    name = "android.logcat"
    description = "抓取设备 logcat 日志缓冲最近 N 条（行为分析线索，只读）"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        serial = str(self._require(input_data, "serial"))
        adb_path = input_data.get("adb_path")
        adb = AdbClient(adb_path) if adb_path else AdbClient()
        text = adb.logcat(
            serial,
            lines=int(input_data.get("lines", 200)),
            filter_tag=str(input_data.get("filter_tag", "")),
        )
        return {"serial": serial, "log": text[:12000]}


class AndroidScreenshotTool(BaseTool):
    """android.screenshot — 设备截屏（行为记录）。"""

    name = "android.screenshot"
    description = "截取设备当前屏幕保存为本地 PNG（行为记录取证）"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        serial = str(self._require(input_data, "serial"))
        local_path = str(self._require(input_data, "local_path"))
        adb_path = input_data.get("adb_path")
        adb = AdbClient(adb_path) if adb_path else AdbClient()
        result = adb.screenshot(serial, local_path)
        return {"serial": serial, "png": str(result)}


class AndroidConnectTool(BaseTool):
    """android.connect — 网络远程调试连接（Android 11+ 无线调试）。"""

    name = "android.connect"
    description = (
        "adb connect 网络连接设备（ip:端口），支持 Android 11+ 无线调试，"
        "不再依赖 USB；首次配对用 android.pair"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        host_port = str(self._require(input_data, "host_port"))
        adb_path = input_data.get("adb_path")
        adb = AdbClient(adb_path) if adb_path else AdbClient()
        output = adb.connect(host_port)
        return {"host_port": host_port, "output": output}


class AndroidPairTool(BaseTool):
    """android.pair — 无线调试首次配对（Android 11+）。"""

    name = "android.pair"
    description = (
        "adb pair 无线调试配对：在设备「开发者选项 → 无线调试 → 配对码配对」"
        "页获取 ip:配对端口 与 6 位码后调用；配对后用 android.connect 连常规端口"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        host_port = str(self._require(input_data, "host_port"))
        pairing_code = str(self._require(input_data, "pairing_code"))
        adb_path = input_data.get("adb_path")
        adb = AdbClient(adb_path) if adb_path else AdbClient()
        output = adb.pair(host_port, pairing_code)
        return {"host_port": host_port, "output": output}


ANDROID_TOOLS: list[BaseTool] = [
    AndroidDevicesTool(),
    AndroidInfoTool(),
    AndroidPackagesTool(),
    AndroidPullTool(),
    AndroidLimeGuideTool(),
    AndroidAnalyzeImageTool(),
    AndroidShellTool(),
    AndroidPushTool(),
    AndroidInstallTool(),
    AndroidLogcatTool(),
    AndroidScreenshotTool(),
    AndroidConnectTool(),
    AndroidPairTool(),
]
