"""winreverse.engine.tools.behavior_tools — 动态行为分析工具。

将 forensics.behavior（进程隔离行为监控）与 sandbox_wsb 封装为
ToolInterface 实现。

工具清单：
- behavior.monitor: 运行样本并采集四维行为（进程/网络/文件/注册表）
- behavior.sandbox_check: Windows Sandbox 可用性检测
- behavior.sandbox_wsb: 生成沙箱引爆配置（.wsb）

即插即用：默认进程隔离后端零配置；Sandbox 为可选增强。
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Any

from winreverse.engine.tools._base import BaseTool
from winreverse.forensics.behavior import ProcessIsolationRunner
from winreverse.forensics.sandbox_wsb import (
    is_sandbox_available,
    write_wsb_config,
)


def _runner(input_data: dict[str, Any]) -> ProcessIsolationRunner:
    """按输入构造 runner（会话根/轮询间隔可配）。"""
    sessions_root = input_data.get("sessions_root")
    poll = float(input_data.get("poll_interval", 0.5))
    if sessions_root:
        return ProcessIsolationRunner(sessions_root=sessions_root, poll_interval=poll)
    return ProcessIsolationRunner(poll_interval=poll)


class BehaviorMonitorTool(BaseTool):
    """behavior.monitor — 运行样本并采集行为报告。"""

    name = "behavior.monitor"
    description = (
        "动态行为分析：在进程隔离环境中运行样本（默认最长 3600 秒），"
        "采集进程树/外联网络/释放文件/注册表持久化四维行为，"
        "输出风险评分与 IOC（即插即用，无需任何环境配置）"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        sample_path = str(self._require(input_data, "sample_path"))
        duration = int(input_data.get("duration", 30))
        runner = _runner(input_data)
        session_id = runner.prepare(sample_path, {})
        try:
            runner.run(session_id, duration=duration)
            return runner.collect(session_id)
        finally:
            # 报告已落盘，清理样本副本与残留进程（销毁失败不影响报告返回）
            with contextlib.suppress(Exception):
                runner.destroy(session_id)


class BehaviorSandboxCheckTool(BaseTool):
    """behavior.sandbox_check — Windows Sandbox 可用性检测。"""

    name = "behavior.sandbox_check"
    description = (
        "检测 Windows Sandbox 是否可用（可选的更强隔离引爆环境）；"
        "不可用时直接用 behavior.monitor 的进程隔离后端即可"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        available = is_sandbox_available()
        return {
            "available": available,
            "note": (
                "Windows Sandbox 已启用，可用 behavior.sandbox_wsb 生成引爆配置"
                if available
                else "未启用；行为分析请直接用 behavior.monitor（零配置）"
            ),
        }


class BehaviorSandboxWsbTool(BaseTool):
    """behavior.sandbox_wsb — 生成沙箱引爆配置。"""

    name = "behavior.sandbox_wsb"
    description = (
        "生成 Windows Sandbox 引爆配置（.wsb，默认关网络/只读映射样本目录），"
        "双击即可在沙箱内运行样本"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        sample_path = str(self._require(input_data, "sample_path"))
        output_path = str(
            input_data.get("output_path") or Path("output/behavior_sessions") / "sample_sandbox.wsb"
        )
        result_path = write_wsb_config(
            sample_path,
            output_path,
            networking=bool(input_data.get("networking", False)),
            mapped_folder=input_data.get("mapped_folder"),
            logon_command=str(input_data.get("logon_command", "")),
        )
        return {"wsb": str(result_path)}


BEHAVIOR_TOOLS: list[BaseTool] = [
    BehaviorMonitorTool(),
    BehaviorSandboxCheckTool(),
    BehaviorSandboxWsbTool(),
]
