"""winreverse.soul — Soul 引擎包入口。

从 winreverse.soul.agent re-export 核心引擎契约（Agent / AgentConfig /
AgentState / Runtime），供上层编排与测试使用。
"""

from __future__ import annotations

from winreverse.soul.agent import Agent, AgentConfig, AgentState, Runtime

__all__ = ["Agent", "AgentConfig", "AgentState", "Runtime"]
