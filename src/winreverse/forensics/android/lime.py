"""winreverse.forensics.android.lime — LiME 内存采集引导（GPL 隔离）。

许可证边界：LiME（Linux Memory Extractor）为 GPL-2.0 内核模块，
其二进制/源码不随本项目分发。本模块只做"引导"：
1. 说明前置条件（root 设备、与设备内核版本匹配的自编译 lime.ko）
2. 生成设备侧采集命令清单（insmod → dd → pull，用户在 adb shell 中执行）
3. 采集完成后的镜像交给 VolatilityBridge（linux.* 插件）分析

这样既保留 LiME 的取证能力，又避免 GPL 二进制随项目分发。
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LimeGuide:
    """LiME 采集引导（命令清单 + 前置说明）。

    Attributes:
        serial: 目标设备序列号
        kernel_release: 目标内核版本（uname -r，需与 lime.ko 编译版本一致）
        module_path: lime.ko 推送到设备后的路径
        dump_path: 设备侧内存镜像输出路径
        steps: 按序执行的命令清单（用户在 adb shell 中执行）
        warnings: 前置条件与注意事项
    """

    serial: str
    kernel_release: str = ""
    module_path: str = "/data/local/tmp/lime.ko"
    dump_path: str = "/data/local/tmp/ram.lime"
    steps: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """转为 JSON 兼容字典。"""
        return {
            "serial": self.serial,
            "kernel_release": self.kernel_release,
            "module_path": self.module_path,
            "dump_path": self.dump_path,
            "steps": self.steps,
            "warnings": self.warnings,
        }


def build_lime_guide(
    serial: str,
    *,
    kernel_release: str = "",
    local_module_path: str = "lime.ko",
    dump_path: str = "/data/local/tmp/ram.lime",
) -> LimeGuide:
    """生成 LiME 内存采集引导。

    Args:
        serial: 目标设备序列号
        kernel_release: 设备内核版本（空则引导中包含查询命令）
        local_module_path: 本地编译好的 lime.ko 路径（需自行从 LiME 源码编译）
        dump_path: 设备侧镜像输出路径

    Returns:
        LimeGuide 命令清单
    """
    module_path = "/data/local/tmp/lime.ko"
    steps = [
        # 1. 推送内核模块（用户自行编译，本项目不分发 GPL 二进制）
        f"adb -s {serial} push {local_module_path} {module_path}",
        # 2. 加载模块采集内存（LiME 的 dd 格式：每页带地址元数据）
        (f"adb -s {serial} shell \"su -c 'insmod {module_path} path={dump_path} format=lime'\""),
        # 3. 卸载模块
        f"adb -s {serial} shell \"su -c 'rmmod lime'\"",
        # 4. 拉取镜像到本地
        f"adb -s {serial} pull {dump_path} ./ram.lime",
    ]
    warnings = [
        "需要 root 权限（insmod 依赖 su）；未 root 设备无法采集内核内存",
        "lime.ko 必须与设备内核版本精确匹配，请从 LiME 源码（GPL-2.0）"
        "针对目标内核自行编译：https://github.com/504ensicslabs/lime",
        "采集过程会将完整物理内存写入设备存储，请确保剩余空间充足",
        "镜像为 format=lime 格式，可直接用 volatility3 的 linux.* 插件分析",
    ]
    kernel_steps: list[str] = []
    if not kernel_release:
        kernel_steps.append(f"adb -s {serial} shell uname -r  # 确认内核版本")
    return LimeGuide(
        serial=serial,
        kernel_release=kernel_release,
        module_path=module_path,
        dump_path=dump_path,
        steps=[*kernel_steps, *steps],
        warnings=warnings,
    )
