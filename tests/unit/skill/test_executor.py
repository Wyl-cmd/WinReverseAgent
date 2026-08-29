"""测试模块：winreverse.skill.executor

覆盖 SkillExecutor 的核心功能：
- run() 主流程（含/不含 execution_flow）
- 参数校验、模板渲染、预置流执行
- 工具调用异常处理、prompt 组装
- _infer_type / _render_args / _build_render_vars / _build_prompt_with_flow

使用 mock LLM 与 mock 工具避免真实调用。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from kosong.types import GenerateResult, Message, MessageRole, Usage
from winreverse.engine.bus import ToolRegistry
from winreverse.skill.executor import (
    FlowStepResult,
    SkillExecutionError,
    SkillExecutor,
    SkillRunResult,
)
from winreverse.skill.loader import Skill, SkillNotFoundError, SkillParameter, SkillRegistry
from winreverse.soul.soul import WinReverseSoul

# =============================================================================
# Mock LLM 实现
# =============================================================================


class _MockLLM:
    """Mock LLM 生成器，按预设脚本返回结果。"""

    def __init__(self, responses: list[GenerateResult] | None = None) -> None:
        self._responses = list(responses) if responses else []
        self._call_count = 0
        self.last_messages: list[Message] | None = None

    async def generate(
        self,
        messages: list[Message],
        model: str | None = None,
        tools: list[Any] | None = None,
    ) -> GenerateResult:
        _ = model, tools
        self.last_messages = list(messages)
        if self._call_count >= len(self._responses):
            return GenerateResult(
                message=Message(role=MessageRole.ASSISTANT, content="已完成"),
                stop_reason="stop",
                usage=Usage(),
            )
        response = self._responses[self._call_count]
        self._call_count += 1
        return response


def _make_result(content: str = "", stop_reason: str = "stop") -> GenerateResult:
    """构造 GenerateResult。"""
    return GenerateResult(
        message=Message(role=MessageRole.ASSISTANT, content=content),
        stop_reason=stop_reason,
        usage=Usage(),
    )


# =============================================================================
# 测试用工具
# =============================================================================


class _EchoTool:
    """回显工具。"""

    name = "echo"
    description = "回显输入"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {"status": "success", "echoed": input_data.get("msg", "")}


class _ParseTool:
    """PE 解析工具。"""

    name = "pe.parse"
    description = "解析 PE 文件"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {
            "status": "success",
            "file": input_data.get("file_path", ""),
            "bits": 64,
            "imphash": "abc123",
        }


class _ErrorTool:
    """总是返回错误的工具。"""

    name = "error.tool"
    description = "总是失败"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {"status": "error", "error_message": "designed to fail"}


class _RaisingTool:
    """总是抛异常的工具。"""

    name = "raising.tool"
    description = "抛异常"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("boom")


# =============================================================================
# 辅助函数：构造 Skill / Soul / Executor
# =============================================================================


def _make_skill(
    name: str = "测试技能",
    description: str = "测试用 Skill",
    *,
    parameters: list[SkillParameter] | None = None,
    prompt_template: str = "任务: 测试",
    execution_flow: list[dict[str, Any]] | None = None,
) -> Skill:
    """构造 Skill 实例。"""
    return Skill(
        name=name,
        description=description,
        parameters=parameters or [],
        prompt_template=prompt_template,
        execution_flow=execution_flow or [],
    )


def _make_executor(
    skill_registry: SkillRegistry,
    registry: ToolRegistry,
    llm: _MockLLM,
    tmp_path: Path,
) -> tuple[SkillExecutor, WinReverseSoul]:
    """构造 SkillExecutor 与 Soul 实例。"""
    soul = WinReverseSoul(llm=llm, registry=registry, work_dir=tmp_path)
    executor = SkillExecutor(skill_registry=skill_registry, soul=soul)
    return executor, soul


# =============================================================================
# SkillExecutor 初始化测试
# =============================================================================


class TestSkillExecutorInit:
    """SkillExecutor 初始化测试。"""

    def test_init_properties(self, tmp_path: Path) -> None:
        """初始化后属性可访问。"""
        skill_registry = SkillRegistry()
        soul = WinReverseSoul(
            llm=_MockLLM(),
            registry=ToolRegistry(),
            work_dir=tmp_path,
        )
        executor = SkillExecutor(skill_registry=skill_registry, soul=soul)

        assert executor.skill_registry is skill_registry
        assert executor.soul is soul


# =============================================================================
# run() 主流程测试
# =============================================================================


class TestSkillExecutorRun:
    """SkillExecutor.run() 测试。"""

    @pytest.mark.asyncio
    async def test_run_simple_skill_no_flow(self, tmp_path: Path) -> None:
        """无 execution_flow 的 Skill 直接走 Soul.run。"""
        skill_registry = SkillRegistry()
        skill_registry.register(
            _make_skill(
                name="简单技能",
                prompt_template="任务: 测试 {{target}}",
                parameters=[SkillParameter(name="target", required=True)],
            )
        )
        mock_llm = _MockLLM([_make_result(content="完成")])
        registry = ToolRegistry()
        executor, _ = _make_executor(skill_registry, registry, mock_llm, tmp_path)

        result = await executor.run("简单技能", {"target": "abc"})

        assert isinstance(result, SkillRunResult)
        assert result.skill_name == "简单技能"
        assert result.final_answer == "完成"
        assert result.flow_results == []
        assert "任务: 测试 abc" in result.rendered_prompt

    @pytest.mark.asyncio
    async def test_run_with_execution_flow(self, tmp_path: Path) -> None:
        """带 execution_flow 的 Skill 预执行工具调用。"""
        skill_registry = SkillRegistry()
        skill_registry.register(
            _make_skill(
                name="PE 分析",
                prompt_template="分析 {{file_path}}",
                parameters=[SkillParameter(name="file_path", required=True)],
                execution_flow=[
                    {
                        "action": "pe.parse",
                        "args": {"file_path": "{{file_path}}"},
                    }
                ],
            )
        )
        registry = ToolRegistry()
        registry.register(_ParseTool())
        mock_llm = _MockLLM([_make_result(content="分析完成")])
        executor, _ = _make_executor(skill_registry, registry, mock_llm, tmp_path)

        result = await executor.run("PE 分析", {"file_path": "test.exe"})

        assert result.final_answer == "分析完成"
        assert len(result.flow_results) == 1
        assert result.flow_results[0].action == "pe.parse"
        assert result.flow_results[0].arguments == {"file_path": "test.exe"}
        assert result.flow_results[0].is_error is False
        # 预置流结果应注入 prompt
        assert "预置执行流结果" in result.rendered_prompt
        assert "pe.parse" in result.rendered_prompt
        assert "imphash" in result.rendered_prompt

    @pytest.mark.asyncio
    async def test_run_skill_not_found(self, tmp_path: Path) -> None:
        """未注册的 Skill 抛出 SkillNotFoundError。"""
        skill_registry = SkillRegistry()
        mock_llm = _MockLLM()
        executor, _ = _make_executor(skill_registry, ToolRegistry(), mock_llm, tmp_path)

        with pytest.raises(SkillNotFoundError):
            await executor.run("不存在的技能", {})

    @pytest.mark.asyncio
    async def test_run_missing_required_param(self, tmp_path: Path) -> None:
        """缺少必填参数抛出 SkillExecutionError。"""
        skill_registry = SkillRegistry()
        skill_registry.register(
            _make_skill(
                name="需要参数",
                parameters=[SkillParameter(name="file_path", required=True)],
            )
        )
        mock_llm = _MockLLM()
        executor, _ = _make_executor(skill_registry, ToolRegistry(), mock_llm, tmp_path)

        with pytest.raises(SkillExecutionError, match="参数校验失败"):
            await executor.run("需要参数", {})

    @pytest.mark.asyncio
    async def test_run_with_default_param(self, tmp_path: Path) -> None:
        """使用默认值填充参数。"""
        skill_registry = SkillRegistry()
        skill_registry.register(
            _make_skill(
                name="默认值测试",
                prompt_template="deep={{deep}}",
                parameters=[
                    SkillParameter(name="file_path", required=True),
                    SkillParameter(name="deep", default=False, type="bool"),
                ],
            )
        )
        mock_llm = _MockLLM([_make_result(content="ok")])
        executor, _ = _make_executor(skill_registry, ToolRegistry(), mock_llm, tmp_path)

        result = await executor.run("默认值测试", {"file_path": "a.exe"})

        # 默认值 False 渲染为 "False"
        assert "deep=False" in result.rendered_prompt

    @pytest.mark.asyncio
    async def test_run_with_extra_params(self, tmp_path: Path) -> None:
        """用户传入的额外参数（不在 Skill 定义中）也参与渲染。"""
        skill_registry = SkillRegistry()
        skill_registry.register(
            _make_skill(
                name="额外参数",
                prompt_template="file={{file}} extra={{extra}}",
                parameters=[SkillParameter(name="file", required=True)],
            )
        )
        mock_llm = _MockLLM([_make_result(content="ok")])
        executor, _ = _make_executor(skill_registry, ToolRegistry(), mock_llm, tmp_path)

        result = await executor.run(
            "额外参数",
            {"file": "a.exe", "extra": "custom_value"},
        )

        assert "file=a.exe" in result.rendered_prompt
        assert "extra=custom_value" in result.rendered_prompt

    @pytest.mark.asyncio
    async def test_run_flow_tool_error_does_not_abort(self, tmp_path: Path) -> None:
        """预置流中工具返回 error，不中断后续步骤。"""
        skill_registry = SkillRegistry()
        skill_registry.register(
            _make_skill(
                name="带错误流",
                prompt_template="测试",
                execution_flow=[
                    {"action": "error.tool", "args": {}},
                    {"action": "echo", "args": {"msg": "still_works"}},
                ],
            )
        )
        registry = ToolRegistry()
        registry.register(_ErrorTool())
        registry.register(_EchoTool())
        mock_llm = _MockLLM([_make_result(content="ok")])
        executor, _ = _make_executor(skill_registry, registry, mock_llm, tmp_path)

        result = await executor.run("带错误流", {})

        assert len(result.flow_results) == 2
        assert result.flow_results[0].is_error is True
        assert result.flow_results[1].is_error is False
        assert "still_works" in result.flow_results[1].output

    @pytest.mark.asyncio
    async def test_run_flow_tool_exception_does_not_abort(self, tmp_path: Path) -> None:
        """预置流中工具抛异常，不中断后续步骤。

        SoulToolsetAdapter.execute 内部会捕获异常并返回 is_error=True 的结果，
        SkillExecutor 应识别此错误结果但继续执行后续步骤。
        """
        skill_registry = SkillRegistry()
        skill_registry.register(
            _make_skill(
                name="带异常流",
                prompt_template="测试",
                execution_flow=[
                    {"action": "raising.tool", "args": {}},
                    {"action": "echo", "args": {"msg": "after_exception"}},
                ],
            )
        )
        registry = ToolRegistry()
        registry.register(_RaisingTool())
        registry.register(_EchoTool())
        mock_llm = _MockLLM([_make_result(content="ok")])
        executor, _ = _make_executor(skill_registry, registry, mock_llm, tmp_path)

        result = await executor.run("带异常流", {})

        assert len(result.flow_results) == 2
        # 第一步异常被 SoulToolsetAdapter 捕获，返回错误结果（不抛出）
        assert result.flow_results[0].is_error is True
        assert "raising.tool" in result.flow_results[0].output
        assert "RuntimeError" in result.flow_results[0].output
        # 第二步仍正常执行
        assert result.flow_results[1].is_error is False
        assert "after_exception" in result.flow_results[1].output

    @pytest.mark.asyncio
    async def test_run_flow_step_missing_action_skipped(self, tmp_path: Path) -> None:
        """execution_flow 中缺少 action 字段的步骤被跳过。"""
        skill_registry = SkillRegistry()
        skill_registry.register(
            _make_skill(
                name="缺 action",
                prompt_template="测试",
                execution_flow=[
                    {"args": {"msg": "no_action"}},
                    {"action": "echo", "args": {"msg": "has_action"}},
                ],
            )
        )
        registry = ToolRegistry()
        registry.register(_EchoTool())
        mock_llm = _MockLLM([_make_result(content="ok")])
        executor, _ = _make_executor(skill_registry, registry, mock_llm, tmp_path)

        result = await executor.run("缺 action", {})

        # 只执行了 1 步（跳过缺 action 的）
        assert len(result.flow_results) == 1
        assert result.flow_results[0].action == "echo"

    @pytest.mark.asyncio
    async def test_run_soul_failure_raises_execution_error(self, tmp_path: Path) -> None:
        """Soul 引擎抛异常时包装为 SkillExecutionError。"""

        class _FailingLLM:
            async def generate(self, **kwargs: Any) -> GenerateResult:
                raise RuntimeError("LLM 调用失败")

        skill_registry = SkillRegistry()
        skill_registry.register(_make_skill(name="失败测试"))
        soul = WinReverseSoul(
            llm=_FailingLLM(),
            registry=ToolRegistry(),
            work_dir=tmp_path,
        )
        executor = SkillExecutor(skill_registry=skill_registry, soul=soul)

        with pytest.raises(SkillExecutionError, match="Soul 引擎执行失败"):
            await executor.run("失败测试", {})

    @pytest.mark.asyncio
    async def test_run_passes_agent_type_to_soul(self, tmp_path: Path) -> None:
        """agent_type 参数传递给 Soul.run。"""
        skill_registry = SkillRegistry()
        skill_registry.register(_make_skill(name="类型测试"))
        mock_llm = _MockLLM([_make_result(content="ok")])
        executor, soul = _make_executor(skill_registry, ToolRegistry(), mock_llm, tmp_path)

        # 监听 soul.run 的调用参数
        captured: dict[str, Any] = {}
        original_run = soul.run

        async def _spy_run(prompt: str, **kwargs: Any) -> str:
            captured["prompt"] = prompt
            captured.update(kwargs)
            return await original_run(prompt, **kwargs)

        soul.run = _spy_run  # type: ignore[method-assign]

        await executor.run("类型测试", {}, agent_type="reverse", model="gpt-4", max_turns=5)

        assert captured.get("agent_type") == "reverse"
        assert captured.get("model") == "gpt-4"
        assert captured.get("max_turns") == 5

    @pytest.mark.asyncio
    async def test_run_loads_skill_from_yaml(self, tmp_path: Path) -> None:
        """从 YAML 文件加载 Skill 并执行。"""
        from winreverse.skill.loader import YamlSkillLoader

        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        skill_file = skills_dir / "test_skill.yaml"
        skill_file.write_text(
            """
name: "YAML 技能"
description: "从 YAML 加载"
target: "测试"
parameters:
  - name: "file_path"
    type: "string"
    required: true
prompt_template: |
  分析文件 {{file_path}}
execution_flow:
  - action: "echo"
    args:
      msg: "{{file_path}}"
""",
            encoding="utf-8",
        )

        loader = YamlSkillLoader()
        skill = loader.load(skill_file)

        skill_registry = SkillRegistry()
        skill_registry.register(skill)

        registry = ToolRegistry()
        registry.register(_EchoTool())
        mock_llm = _MockLLM([_make_result(content="YAML 完成")])
        executor, _ = _make_executor(skill_registry, registry, mock_llm, tmp_path)

        result = await executor.run("YAML 技能", {"file_path": "test.exe"})

        assert result.final_answer == "YAML 完成"
        assert len(result.flow_results) == 1
        assert result.flow_results[0].arguments == {"msg": "test.exe"}


# =============================================================================
# _infer_type 类型推断测试
# =============================================================================


class TestInferType:
    """_infer_type 静态方法测试。"""

    def test_true_string(self) -> None:
        assert SkillExecutor._infer_type("true") is True

    def test_false_string(self) -> None:
        assert SkillExecutor._infer_type("false") is False

    def test_true_uppercase(self) -> None:
        assert SkillExecutor._infer_type("TRUE") is True

    def test_false_mixed_case(self) -> None:
        assert SkillExecutor._infer_type("False") is False

    def test_integer_string(self) -> None:
        assert SkillExecutor._infer_type("42") == 42

    def test_negative_integer_string(self) -> None:
        assert SkillExecutor._infer_type("-10") == -10

    def test_float_string(self) -> None:
        assert SkillExecutor._infer_type("3.14") == 3.14

    def test_plain_string(self) -> None:
        assert SkillExecutor._infer_type("hello") == "hello"

    def test_empty_string(self) -> None:
        assert SkillExecutor._infer_type("") == ""

    def test_file_path_not_converted(self) -> None:
        """文件路径字符串不被转换为数字。"""
        assert SkillExecutor._infer_type("test.exe") == "test.exe"

    def test_numeric_string_with_extension(self) -> None:
        """带扩展名的数字字符串保持为字符串。"""
        assert SkillExecutor._infer_type("123.exe") == "123.exe"


# =============================================================================
# _render_args 参数渲染测试
# =============================================================================


class TestRenderArgs:
    """_render_args 静态方法测试。"""

    def test_replaces_placeholders(self) -> None:
        """替换 {{var}} 占位符。"""
        raw = {"file_path": "{{target}}", "deep": "{{flag}}"}
        variables = {"target": "test.exe", "flag": True}

        rendered = SkillExecutor._render_args(raw, variables)

        assert rendered["file_path"] == "test.exe"
        assert rendered["deep"] is True

    def test_no_placeholders(self) -> None:
        """无占位符时原样返回。"""
        raw = {"key": "value", "num": 42}
        rendered = SkillExecutor._render_args(raw, {})
        assert rendered["key"] == "value"
        assert rendered["num"] == 42

    def test_non_string_values_preserved(self) -> None:
        """非字符串值原样返回。"""
        raw = {"list": [1, 2, 3], "dict": {"a": 1}, "none": None}
        rendered = SkillExecutor._render_args(raw, {})
        assert rendered["list"] == [1, 2, 3]
        assert rendered["dict"] == {"a": 1}
        assert rendered["none"] is None

    def test_partial_placeholder(self) -> None:
        """部分占位符的字符串。"""
        raw = {"path": "C:\\test\\{{name}}.exe"}
        variables = {"name": "sample"}
        rendered = SkillExecutor._render_args(raw, variables)
        assert rendered["path"] == "C:\\test\\sample.exe"

    def test_empty_raw_args(self) -> None:
        """空字典返回空字典。"""
        assert SkillExecutor._render_args({}, {"var": "x"}) == {}


# =============================================================================
# _build_render_vars 默认值合并测试
# =============================================================================


class TestBuildRenderVars:
    """_build_render_vars 静态方法测试。"""

    def test_user_value_overrides_default(self) -> None:
        """用户值优先于默认值。"""
        skill = _make_skill(
            parameters=[
                SkillParameter(name="deep", default=False, type="bool"),
            ]
        )
        variables = SkillExecutor._build_render_vars(skill, {"deep": True})
        assert variables["deep"] is True

    def test_default_used_when_missing(self) -> None:
        """用户未提供时使用默认值。"""
        skill = _make_skill(
            parameters=[
                SkillParameter(name="deep", default=True, type="bool"),
            ]
        )
        variables = SkillExecutor._build_render_vars(skill, {})
        assert variables["deep"] is True

    def test_empty_string_when_no_default_no_required(self) -> None:
        """非必填且无默认值时填空字符串。"""
        skill = _make_skill(
            parameters=[
                SkillParameter(name="optional"),
            ]
        )
        variables = SkillExecutor._build_render_vars(skill, {})
        assert variables["optional"] == ""

    def test_extra_user_params_preserved(self) -> None:
        """用户传入的额外参数被保留。"""
        skill = _make_skill(parameters=[SkillParameter(name="file_path", required=True)])
        variables = SkillExecutor._build_render_vars(
            skill, {"file_path": "a.exe", "extra": "value"}
        )
        assert variables["file_path"] == "a.exe"
        assert variables["extra"] == "value"

    def test_no_parameters_skill(self) -> None:
        """无参数定义的 Skill 仍能处理用户参数。"""
        skill = _make_skill()
        variables = SkillExecutor._build_render_vars(skill, {"key": "value"})
        assert variables == {"key": "value"}


# =============================================================================
# _build_prompt_with_flow 预置流结果注入测试
# =============================================================================


class TestBuildPromptWithFlow:
    """_build_prompt_with_flow 静态方法测试。"""

    def test_empty_flow_returns_base(self) -> None:
        """无预置流结果时原样返回 base_prompt。"""
        prompt = SkillExecutor._build_prompt_with_flow("base", [])
        assert prompt == "base"

    def test_with_successful_results(self) -> None:
        """成功结果注入到 prompt。"""
        results = [
            FlowStepResult(
                action="pe.parse",
                arguments={"file_path": "test.exe"},
                output='{"status": "success", "bits": 64}',
                is_error=False,
            )
        ]
        prompt = SkillExecutor._build_prompt_with_flow("base prompt", results)
        assert "base prompt" in prompt
        assert "预置执行流结果" in prompt
        assert "pe.parse" in prompt
        assert "[OK]" in prompt
        assert "bits" in prompt

    def test_with_error_results(self) -> None:
        """错误结果标注 [ERROR]。"""
        results = [
            FlowStepResult(
                action="error.tool",
                arguments={},
                output="失败原因",
                is_error=True,
            )
        ]
        prompt = SkillExecutor._build_prompt_with_flow("base", results)
        assert "[ERROR]" in prompt
        assert "error.tool" in prompt

    def test_with_multiple_results(self) -> None:
        """多个结果按顺序输出。"""
        results = [
            FlowStepResult(action="step1", arguments={}, output="out1", is_error=False),
            FlowStepResult(action="step2", arguments={}, output="out2", is_error=True),
            FlowStepResult(action="step3", arguments={}, output="out3", is_error=False),
        ]
        prompt = SkillExecutor._build_prompt_with_flow("base", results)
        assert "步骤 1" in prompt
        assert "步骤 2" in prompt
        assert "步骤 3" in prompt
        assert prompt.index("step1") < prompt.index("step2") < prompt.index("step3")


# =============================================================================
# 集成：加载真实 skills/*.yaml 文件测试
# =============================================================================


class TestIntegrationWithRealSkills:
    """集成测试：使用项目内 skills/*.yaml 文件。"""

    @pytest.mark.asyncio
    async def test_load_and_run_pe_analyzer_skill(self, tmp_path: Path) -> None:
        """加载 skills/pe_analyzer.yaml 并执行（mock LLM）。"""
        from winreverse.skill.loader import YamlSkillLoader

        # 定位 skills 目录
        skills_dir = Path(__file__).resolve().parents[3] / "skills"
        if not skills_dir.exists():
            pytest.skip(f"skills 目录不存在: {skills_dir}")

        loader = YamlSkillLoader()
        skill = loader.load(skills_dir / "pe_analyzer.yaml")

        skill_registry = SkillRegistry()
        skill_registry.register(skill)

        registry = ToolRegistry()
        registry.register(_ParseTool())
        mock_llm = _MockLLM([_make_result(content="PE 分析报告完成")])
        executor, _ = _make_executor(skill_registry, registry, mock_llm, tmp_path)

        result = await executor.run(
            skill.name,
            {"file_path": "test.exe", "deep_scan": False},
        )

        assert result.skill_name == skill.name
        assert result.final_answer == "PE 分析报告完成"
        # pe_analyzer.yaml 有 execution_flow，应执行预置步骤
        assert len(result.flow_results) > 0
        assert result.flow_results[0].action == "pe.parse"
