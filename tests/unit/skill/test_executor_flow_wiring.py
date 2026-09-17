"""测试模块：SkillExecutor 预置流的"上游输出接线"（P0-2 配套修复）。

背景：trojan_memory_triage 这类技能的预置流是"先把 attach/dump 的输出喂给下一步"
（``memory.attach → {{pid}}``、``memory.dump → {{output_dir}}``）。修复前
``_render_args`` 对未声明占位符不做解析，``{{pid}}`` 会原样传成字符串 ``"{{pid}}"``，
下游工具必然报错。现在上游输出里的 ``pid`` / ``output_dir`` / ``dump_dir`` / ``pcap``
等键会自动接线给后续步骤。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kosong.types import GenerateResult, Message, MessageRole, Usage
from winreverse.engine.bus import ToolRegistry
from winreverse.skill.executor import SkillExecutor
from winreverse.skill.loader import Skill, SkillParameter, SkillRegistry
from winreverse.soul.soul import WinReverseSoul


class _ScriptedLLM:
    def __init__(self) -> None:
        self.calls = 0

    async def generate(self, messages: Any, model: Any = None, tools: Any = None) -> GenerateResult:
        self.calls += 1
        return GenerateResult(
            message=Message(role=MessageRole.ASSISTANT, content="结论：已接线"),
            stop_reason="stop",
            usage=Usage(),
        )


class _AttachTool:
    name = "memory.attach"
    description = "附加进程（桩）"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        assert input_data.get("process_name")
        return {"status": "success", "pid": 4242, "process_name": input_data["process_name"]}


class _DumpTool:
    name = "memory.dump"
    description = "转储（桩）"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {
            "status": "success",
            "pid": input_data["pid"],
            "output_dir": f"output/memory_dumps/{input_data['pid']}",
            "manifest_path": f"output/memory_dumps/{input_data['pid']}/manifest.json",
        }


class _RecordingTool:
    """记录收到的参数，供断言接线结果。"""

    def __init__(self, name: str) -> None:
        self.name = name
        self.description = "记录参数（桩）"
        self.seen: list[dict[str, Any]] = []

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        self.seen.append(dict(input_data))
        return {"status": "success", "seen": input_data}


def _make_executor(
    *tools: Any, skill: Skill, work_dir: Path
) -> tuple[SkillExecutor, dict[str, Any]]:
    """装配真实 Soul + 桩工具 + 桩技能的执行器。"""
    registry = ToolRegistry()
    recorded: dict[str, Any] = {}
    for tool in tools:
        registry.register(tool)
        recorded[tool.name] = tool
    soul = WinReverseSoul(llm=_ScriptedLLM(), registry=registry, work_dir=work_dir)
    skill_registry = SkillRegistry()
    skill_registry.register(skill)
    executor = SkillExecutor(skill_registry=skill_registry, soul=soul)
    return executor, recorded


@pytest.mark.asyncio
async def test_upstream_output_keys_are_wired_into_later_steps(tmp_path: Path) -> None:
    """memory.attach 的 pid → 后续 {{pid}}；memory.dump 的 output_dir → {{output_dir}}。"""
    analyzer = _RecordingTool("memory.analyze")
    skill = Skill(
        name="接线测试",
        description="d",
        target="t",
        parameters=[SkillParameter(name="process_name", required=True, default="svchost.exe")],
        prompt_template="分析 {{process_name}}",
        execution_flow=[
            {"action": "memory.attach", "args": {"process_name": "{{process_name}}"}},
            {"action": "memory.dump", "args": {"pid": "{{pid}}"}},
            {"action": "memory.analyze", "args": {"dump_dir": "{{output_dir}}"}},
        ],
    )
    executor, _ = _make_executor(
        _AttachTool(), _DumpTool(), analyzer, skill=skill, work_dir=tmp_path
    )

    result = await executor.run("接线测试", {"process_name": "svchost.exe"})

    assert [step.action for step in result.flow_results] == [
        "memory.attach",
        "memory.dump",
        "memory.analyze",
    ]
    assert all(not step.is_error for step in result.flow_results)

    dumped = result.flow_results[1].arguments
    assert dumped["pid"] == 4242, "{{pid}} 必须来自 attach 输出（而不是字面量）"

    analyzed = analyzer.seen[0]
    assert analyzed["dump_dir"] == "output/memory_dumps/4242", "{{output_dir}} 必须来自 dump 输出"
    assert "{{" not in json.dumps(analyzed, ensure_ascii=False)


@pytest.mark.asyncio
async def test_unknown_placeholder_stays_literal_and_does_not_crash(tmp_path: Path) -> None:
    """没有上游产出时占位符保持字面量（工具侧报错可读，流程不炸）。"""
    recorder = _RecordingTool("memory.analyze")
    skill = Skill(
        name="无源接线",
        description="d",
        target="t",
        parameters=[],
        prompt_template="p",
        execution_flow=[{"action": "memory.analyze", "args": {"dump_dir": "{{dump_dir}}"}}],
    )
    executor, _ = _make_executor(recorder, skill=skill, work_dir=tmp_path)

    result = await executor.run("无源接线", {})

    assert recorder.seen[0]["dump_dir"] == "{{dump_dir}}"
    assert result.flow_results[0].action == "memory.analyze"


def test_wire_helper_ignores_non_json_and_non_scalar() -> None:
    """接线辅助函数：非 JSON / 非标量 / 已存在非空值的键都不覆盖。"""
    variables: dict[str, Any] = {"pid": 7, "output_dir": ""}
    SkillExecutor._wire_flow_outputs(variables, "not-json")
    assert variables == {"pid": 7, "output_dir": ""}

    SkillExecutor._wire_flow_outputs(
        variables,
        json.dumps({"pid": 9, "output_dir": "out/9", "dump_dir": ["x"]}),
    )
    assert variables["pid"] == 7, "已有非空值不得被覆盖"
    assert variables["output_dir"] == "out/9"
    assert "dump_dir" not in variables, "非标量不接线"


def test_wire_helper_ignores_non_object_json() -> None:
    """JSON 合法但不是对象（数组/标量）→ 静默跳过（单步失败不影响流程）。"""
    variables: dict[str, Any] = {"keep": "v"}

    SkillExecutor._wire_flow_outputs(variables, json.dumps(["pid", "pcap"]))
    SkillExecutor._wire_flow_outputs(variables, json.dumps("pcap"))

    assert variables == {"keep": "v"}


async def test_executor_flow_does_not_mutate_caller_variables(tmp_path: Path) -> None:
    """接线只改执行器内部副本：调用方传入的 parameters 字典不被污染。"""
    recorder = _RecordingTool("memory.analyze")
    skill = Skill(
        name="副本测试",
        description="d",
        target="t",
        parameters=[SkillParameter(name="process_name", required=True, default="svchost.exe")],
        prompt_template="p",
        execution_flow=[
            {"action": "memory.attach", "args": {"process_name": "{{process_name}}"}},
            {"action": "memory.dump", "args": {"pid": "{{pid}}"}},
            {"action": "memory.analyze", "args": {"dump_dir": "{{output_dir}}"}},
        ],
    )
    executor, _ = _make_executor(
        _AttachTool(), _DumpTool(), recorder, skill=skill, work_dir=tmp_path
    )
    user_params: dict[str, Any] = {}

    await executor.run("副本测试", dict(user_params, process_name="svchost.exe"))

    assert user_params == {}, "调用方参数字典不得被接线/默认值污染"
