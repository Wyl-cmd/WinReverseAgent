"""winreverse.engine.sandbox_runner — 木马杀箱后端契约（预留）。

【预留声明】
本模块仅定义 SandboxRunner Protocol 契约，不实现任何杀箱后端。
M8 阶段启动木马分析能力时，再实现具体后端：
- WindowsSandboxRunner: Windows Sandbox 后端（默认，需 Pro/Enterprise）
- HyperVRunner: Hyper-V 虚拟机后端（隔离最强，体积大）
- ProcessIsolationRunner: 进程隔离 + Job Object 后端（Home 版兜底）

当前阶段（M1-M7）仅保留接口契约，确保架构层为未来扩展预留。
详见实施方案 §10。
"""

from __future__ import annotations

from typing import Any, Protocol


class SandboxRunner(Protocol):
    """杀箱后端契约。

    未来 M8 实现时各后端（Sandbox/Hyper-V/Process）各做一个实现。
    所有实现必须实现此契约，调用方（Skill / LLM 分析器）零改动。
    """

    def prepare(self, sample_path: str, config: dict[str, Any]) -> str:
        """准备杀箱环境。

        Args:
            sample_path: 样本文件路径
            config: 杀箱配置（网络策略/运行时长/监控项等）

        Returns:
            会话 ID（用于后续 run/collect/destroy）
        """
        ...

    def run(self, session_id: str, duration: int) -> dict[str, Any]:
        """运行样本，返回事件流。

        Args:
            session_id: prepare() 返回的会话 ID
            duration: 运行时长（秒）

        Returns:
            事件流字典，包含文件/注册表/进程/网络四维事件
        """
        ...

    def collect(self, session_id: str) -> dict[str, Any]:
        """收集行为事件。

        Args:
            session_id: 会话 ID

        Returns:
            完整行为事件集合，供 LLM 行为分析器使用
        """
        ...

    def destroy(self, session_id: str) -> None:
        """销毁杀箱，清理环境。

        所有样本副本必须在此阶段清理，仅保留原始哈希记录。
        """
        ...


class BehaviorAnalyzer(Protocol):
    """LLM 行为分析器契约（预留）。

    未来 M8 实现时，复用 Soul 引擎 + Prompt 模板实现。
    """

    def analyze(self, events: dict[str, Any]) -> dict[str, Any]:
        """分析行为事件，输出行为摘要/技术能力/风险评分/家族归属/处置建议。

        Args:
            events: SandboxRunner.collect() 返回的事件集合

        Returns:
            分析报告字典，包含：
            - behavior_summary: 行为摘要
            - technical_capabilities: 技术能力列表
            - risk_score: 风险评分（0-100）
            - family_attribution: 家族归属
            - disposal_suggestions: 处置建议
        """
        ...
