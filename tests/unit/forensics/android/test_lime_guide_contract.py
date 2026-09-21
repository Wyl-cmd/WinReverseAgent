"""测试模块：winreverse.forensics.android.lime（LiME 引导命令清单契约）。

覆盖点：to_dict 精确结构、可变默认值实例隔离、步骤精确顺序与固定推送目标、
dump_path 透传、未知内核时探测步骤前置。
"""

from __future__ import annotations

from winreverse.forensics.android.lime import LimeGuide, build_lime_guide


class TestLimeGuideDataclass:
    """LimeGuide 数据类契约。"""

    def test_to_dict_exact_structure(self) -> None:
        """to_dict 恰含六个字段且默认路径固定（下游 JSON 消费方依赖键集）。"""
        guide = LimeGuide(serial="SER1", kernel_release="6.1.0", steps=["a"], warnings=["w"])
        assert guide.to_dict() == {
            "serial": "SER1",
            "kernel_release": "6.1.0",
            "module_path": "/data/local/tmp/lime.ko",
            "dump_path": "/data/local/tmp/ram.lime",
            "steps": ["a"],
            "warnings": ["w"],
        }

    def test_mutable_defaults_not_shared_between_instances(self) -> None:
        """steps/warnings 使用 default_factory：实例间不得共享可变默认值。"""
        g1, g2 = LimeGuide(serial="A"), LimeGuide(serial="B")
        g1.steps.append("contaminate")
        g1.warnings.append("contaminate")
        assert g2.steps == []
        assert g2.warnings == []

    def test_build_returns_fresh_lists_each_call(self) -> None:
        """连续两次 build_lime_guide 的命令清单互不影响（防构造期列表复用）。"""
        first, second = (
            build_lime_guide("S", kernel_release="k"),
            build_lime_guide("S", kernel_release="k"),
        )
        first.steps.append("contaminate")
        assert second.steps[-1] == "adb -s S pull /data/local/tmp/ram.lime ./ram.lime"


class TestBuildLimeGuideSteps:
    """build_lime_guide 命令清单内容契约。"""

    def test_steps_exact_order_and_fixed_push_target(self) -> None:
        """已知内核时恰为 push→insmod→rmmod→pull 四步，推送目标固定为设备侧路径。"""
        guide = build_lime_guide(
            "SER1",
            kernel_release="6.1.0-android13",
            local_module_path="my_lime.ko",
            dump_path="/sdcard/mem.lime",
        )
        assert guide.steps == [
            "adb -s SER1 push my_lime.ko /data/local/tmp/lime.ko",
            "adb -s SER1 shell \"su -c 'insmod /data/local/tmp/lime.ko"
            " path=/sdcard/mem.lime format=lime'\"",
            "adb -s SER1 shell \"su -c 'rmmod lime'\"",
            "adb -s SER1 pull /sdcard/mem.lime ./ram.lime",
        ]

    def test_kernel_probe_first_when_kernel_unknown(self) -> None:
        """未知内核时探测命令置于清单首位（先确认版本再推送模块）。"""
        guide = build_lime_guide("SER1")
        assert guide.kernel_release == ""
        assert guide.steps[0] == "adb -s SER1 shell uname -r  # 确认内核版本"
        assert guide.steps[1] == "adb -s SER1 push lime.ko /data/local/tmp/lime.ko"

    def test_no_probe_step_when_kernel_known(self) -> None:
        """已知内核时清单不含探测命令（与上例互补，防止冗余步骤混入）。"""
        guide = build_lime_guide("SER1", kernel_release="6.1.0")
        assert all("uname" not in s for s in guide.steps)

    def test_serial_embedded_in_every_step(self) -> None:
        """每条命令均面向目标设备序列号（多设备场景防误投）。"""
        for step in build_lime_guide("XYZ", kernel_release="k").steps:
            assert step.startswith("adb -s XYZ ")
