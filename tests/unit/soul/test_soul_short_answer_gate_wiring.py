"""测试模块：短答闸门（P0-4）在 Soul / 应用层的接线。

分两层验证：

1. **Soul 层**：``WinReverseSoul(short_answer_gate=...)`` 必须把开关透传给每次 run
   构建的 ``AgentConfig``（默认 False = 库级静默；True = 启用闸门）。
2. **应用层**：``WinReverseApplication``（CLI skill / REPL 的真实交付路径）必须显式
   打开闸门——否则技能 E2E 的「引子式答复以 rc=0 交付」缺口在真实运行里仍然成立。

背景：2026-09-17 错峰实测 5/23 ≈ 21.7% 技能交付是 146–255 字符开场句（无结论/证据）。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from kosong.types import GenerateResult, Message, MessageRole, Usage
from winreverse.config import AgentConfig as NewAgentConfig
from winreverse.config import AppConfig, LLMConfig
from winreverse.engine.bus import ToolRegistry
from winreverse.soul.agent import _SHORT_ANSWER_PROMPT
from winreverse.soul.soul import WinReverseSoul

INTRO_ANSWER = (
    "好的，我先来分析一下这个样本。接下来我会先读取文件的基本信息，"
    "再进一步查看字符串与导入表，最后结合实际行为给出判断，请稍等。"
)
SUBSTANTIVE_ANSWER = "结论：样本无恶意行为。\n- 证据：导入表仅 kernel32 的读写 API"


class _ScriptedLLM:
    """按脚本顺序返回结果的 LLM 桩；记录每次调用的完整消息历史。"""

    def __init__(self, responses: list[GenerateResult]) -> None:
        self._responses = list(responses)
        self.calls: list[list[Message]] = []

    async def generate(
        self,
        messages: list[Message],
        model: str | None = None,
        tools: list[Any] | None = None,
    ) -> GenerateResult:
        self.calls.append(list(messages))
        if not self._responses:
            return GenerateResult(
                message=Message(role=MessageRole.ASSISTANT, content="脚本耗尽"),
                stop_reason="stop",
                usage=Usage(),
            )
        return self._responses.pop(0)


def _result(content: str, stop_reason: str = "stop") -> GenerateResult:
    return GenerateResult(
        message=Message(role=MessageRole.ASSISTANT, content=content),
        stop_reason=stop_reason,
        usage=Usage(),
    )


def _soul(llm: Any, tmp_path: Path, **kwargs: Any) -> WinReverseSoul:
    return WinReverseSoul(llm=llm, registry=ToolRegistry(), work_dir=tmp_path, **kwargs)


class TestSoulGatePlumbing:
    """Soul 层：short_answer_gate 透传到 AgentConfig 并生效。"""

    async def test_gate_enabled_replaces_intro(self, tmp_path: Path) -> None:
        """Soul(short_answer_gate=True)：引子答 → 续写替换为实质答复。"""
        llm = _ScriptedLLM([_result(INTRO_ANSWER), _result(SUBSTANTIVE_ANSWER)])
        soul = _soul(llm, tmp_path, short_answer_gate=True)

        answer = await soul.run("分析")

        assert answer == SUBSTANTIVE_ANSWER
        assert len(llm.calls) == 2
        assert _SHORT_ANSWER_PROMPT[:12] in str(llm.calls[1][-1].content)

    async def test_gate_default_off_keeps_intro(self, tmp_path: Path) -> None:
        """Soul 默认（未显式打开）：引子答原样返回、仅 1 次调用（库级静默）。"""
        llm = _ScriptedLLM([_result(INTRO_ANSWER)])
        soul = _soul(llm, tmp_path)

        answer = await soul.run("分析")

        assert answer == INTRO_ANSWER
        assert len(llm.calls) == 1
        assert soul.short_answer_gate is False

    async def test_min_answer_chars_is_forwarded(self, tmp_path: Path) -> None:
        """min_answer_chars 透传：阈值调到 5 时短引子同样触发续写。"""
        llm = _ScriptedLLM([_result("完成"), _result(SUBSTANTIVE_ANSWER)])
        soul = _soul(llm, tmp_path, short_answer_gate=True, min_answer_chars=5)

        answer = await soul.run("分析")

        assert answer == SUBSTANTIVE_ANSWER
        assert len(llm.calls) == 2
        assert soul.min_answer_chars == 5


class TestAppWiringEnablesGate:
    """应用层：CLI skill / REPL 交付路径必须打开短答闸门。"""

    def test_application_soul_has_gate_enabled(self, tmp_path: Path) -> None:
        """WinReverseApplication 初始化出的 Soul 必须 short_answer_gate=True。"""
        from winreverse.app import create_agent_from_config

        config = AppConfig(
            llm=LLMConfig(model="unit-model", api_key="unit-key"),
            agent=NewAgentConfig(work_dir=str(tmp_path)),
        )
        agent = create_agent_from_config(config)
        agent._ensure_initialized()

        assert agent._soul.short_answer_gate is True, (
            "应用层必须打开短答闸门，否则「引子式答复 rc=0 交付」缺口在真实交付路径上仍然成立"
        )
        assert agent._soul.min_answer_chars == 300

    def test_skill_executor_uses_gate_enabled_soul(self, tmp_path: Path) -> None:
        """SkillExecutor 经 app 装配的 Soul 运行技能 → 引子答被闸门替换（端到端）。"""
        from winreverse.app import Agent as AppAgent
        from winreverse.skill.loader import Skill, SkillRegistry

        config = AppConfig(
            llm=LLMConfig(model="unit-model", api_key="unit-key"),
            agent=NewAgentConfig(work_dir=str(tmp_path)),
        )
        # 走 Agent(llm=...) 注入接缝：app 装配出的 Soul 用脚本化 LLM（不触网）
        stub = _ScriptedLLM([_result(INTRO_ANSWER), _result(SUBSTANTIVE_ANSWER)])
        agent = AppAgent(app_config=config, llm=stub)
        agent._ensure_initialized()

        registry = SkillRegistry()
        registry.register(
            Skill(
                name="闸门测试技能",
                description="断言交付答复有实质内容",
                prompt_template="任务：分析目标。",
            )
        )
        agent._executor._skill_registry = registry

        result = agent.run_skill_sync("闸门测试技能", {})

        assert result.final_answer == SUBSTANTIVE_ANSWER
        assert len(stub.calls) == 2, "应用层交付路径应触发一次短答续写"

    def test_gate_still_disabled_when_soul_built_directly(self, tmp_path: Path) -> None:
        """直接构造的 Soul（无应用层）默认不开闸门 → 不额外消耗 LLM 调用。"""
        pytest.importorskip("winreverse.soul.soul")

        llm = _ScriptedLLM([_result(INTRO_ANSWER)])
        soul = _soul(llm, tmp_path)
        assert soul.short_answer_gate is False
