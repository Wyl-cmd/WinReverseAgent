"""被测模块: winreverse.skill.executor._execute_flow 单步异常回落（真机 coverage 缺 272/274/280）。

覆盖点: toolset.execute 抛裸异常时记录日志、该步产出 is_error=True 且带
「执行异常」说明的 FlowStepResult，整体流程不中断（272 except / 274
logger.exception / 280 append）。SoulToolsetAdapter 会吞工具异常，
故以抛异常 toolset 替身替换 soul._toolset 直达编排器裸异常分支。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from kosong.types import GenerateResult, Message, MessageRole, Usage
from winreverse.engine.bus import ToolRegistry
from winreverse.skill.executor import SkillExecutor
from winreverse.skill.loader import Skill, SkillParameter, SkillRegistry
from winreverse.soul.soul import WinReverseSoul


class _MockLLM:
    """单轮即完成的 Mock LLM。"""

    async def generate(
        self,
        messages: list[Any],
        model: str | None = None,
        tools: list[Any] | None = None,
    ) -> GenerateResult:
        _ = messages, model, tools
        return GenerateResult(
            message=Message(role=MessageRole.ASSISTANT, content="已完成"),
            stop_reason="stop",
            usage=Usage(),
        )


class _ExplodingToolset:
    """execute 恒抛裸异常的 toolset 替身（绕开 SoulToolsetAdapter 吞异常）。"""

    async def execute(self, action: str, args: dict[str, Any]) -> Any:
        raise RuntimeError("toolset 炸了")


@pytest.mark.asyncio
async def test_flow_step_crash_yields_error_step_and_continues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """预置流单步 toolset 裸异常 → 该步 is_error=True 且带异常说明，整体流程不中断。"""
    skill_registry = SkillRegistry()
    skill_registry.register(
        Skill(
            name="崩流技能",
            description="预置流单步异常",
            parameters=[SkillParameter(name="target", required=True)],
            prompt_template="处理 {{target}}",
            execution_flow=[{"action": "pe.parse", "args": {"file_path": "{{target}}"}}],
        )
    )
    soul = WinReverseSoul(llm=_MockLLM(), registry=ToolRegistry(), work_dir=tmp_path)
    monkeypatch.setattr(soul, "_toolset", _ExplodingToolset())
    executor = SkillExecutor(skill_registry=skill_registry, soul=soul)

    result = await executor.run("崩流技能", {"target": "dump.bin"})

    assert len(result.flow_results) == 1
    step = result.flow_results[0]
    assert step.action == "pe.parse"
    assert step.arguments == {"file_path": "dump.bin"}
    assert step.is_error is True
    assert "执行异常: RuntimeError" in step.output
    assert "toolset 炸了" in step.output
    # 单步失败不中断：Soul 主流程照常产出最终回复
    assert result.final_answer == "已完成"
