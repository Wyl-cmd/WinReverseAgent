"""端到端集成测试：Skill → SkillExecutor → Soul → Tool 数据流。

验证 M5-5 完整数据流：
1. 从 skills/*.yaml 加载 Skill
2. SkillExecutor 解析参数与 execution_flow
3. SoulToolsetAdapter 调用真实 ToolInterface 工具
4. Soul 引擎执行 agent loop（LLM 调用工具 → 工具返回 → LLM 总结）
5. 返回最终报告

使用 mock LLM 模拟真实 LLM 响应，使用真实 PE 工具与 sample_pe_bytes。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kosong.types import (
    GenerateResult,
    Message,
    MessageRole,
    Tool,
    ToolCall,
    Usage,
)
from winreverse.engine.bus import ToolRegistry
from winreverse.skill.executor import SkillExecutor, SkillRunResult
from winreverse.skill.loader import SkillRegistry, YamlSkillLoader
from winreverse.soul.soul import WinReverseSoul

# =============================================================================
# Mock LLM 实现（支持多轮对话与工具调用循环）
# =============================================================================


class _ScriptedLLM:
    """按脚本响应的 Mock LLM。

    每次调用 generate() 返回预设的下一条响应。
    可检查消息历史以验证工具结果是否正确回传。
    """

    def __init__(self, responses: list[GenerateResult]) -> None:
        self._responses = list(responses)
        self._call_count = 0
        self.call_history: list[dict[str, Any]] = []

    async def generate(
        self,
        messages: list[Message],
        model: str | None = None,
        tools: list[Tool] | None = None,
    ) -> GenerateResult:
        self.call_history.append(
            {
                "messages": list(messages),
                "model": model,
                "tools_count": len(tools) if tools else 0,
            }
        )
        if self._call_count >= len(self._responses):
            return GenerateResult(
                message=Message(role=MessageRole.ASSISTANT, content="已超出预设响应"),
                stop_reason="stop",
                usage=Usage(),
            )
        response = self._responses[self._call_count]
        self._call_count += 1
        return response


def _text_response(content: str, stop_reason: str = "stop") -> GenerateResult:
    """构造纯文本响应。"""
    return GenerateResult(
        message=Message(role=MessageRole.ASSISTANT, content=content),
        stop_reason=stop_reason,
        usage=Usage(),
    )


def _tool_call_response(
    tool_name: str,
    arguments: dict[str, Any],
    call_id: str = "call_1",
    content: str = "",
) -> GenerateResult:
    """构造工具调用响应。"""
    return GenerateResult(
        message=Message(
            role=MessageRole.ASSISTANT,
            content=content,
            tool_calls=[
                ToolCall(
                    id=call_id,
                    function=ToolCall.FunctionBody(
                        name=tool_name,
                        arguments=json.dumps(arguments),
                    ),
                )
            ],
        ),
        stop_reason="tool_use",
        usage=Usage(),
    )


# =============================================================================
# 测试用真实工具（不依赖外部文件或进程）
# =============================================================================


class _StubPEParseTool:
    """pe.parse 工具的桩实现，返回固定的 PE 元信息。"""

    name = "pe.parse"
    description = "解析 PE 文件元信息"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        file_path = input_data.get("file_path", "")
        return {
            "status": "success",
            "file_path": file_path,
            "bits": 64,
            "machine": "AMD64",
            "imphash": "abc123def456",
            "entry_point": 0x1000,
            "num_sections": 4,
            "timestamp": "2024-01-01",
        }


class _StubPEImportsTool:
    """pe.imports 工具的桩实现。"""

    name = "pe.imports"
    description = "列出 PE 导入表"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {
            "status": "success",
            "imports": {
                "kernel32.dll": ["CreateFileW", "WriteFile", "ExitProcess"],
                "user32.dll": ["MessageBoxW"],
            },
            "suspicious_count": 1,
        }


class _StubPEDetectSuspiciousTool:
    """pe.suspicious_imports 工具的桩实现。"""

    name = "pe.suspicious_imports"
    description = "检测可疑 API"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {
            "status": "success",
            "suspicious": [
                {"dll": "kernel32.dll", "function": "WriteFile", "risk": "medium"},
            ],
            "total_suspicious": 1,
        }


class _StubEchoTool:
    """echo 工具桩实现。"""

    name = "echo"
    description = "回显输入"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {"status": "success", "echoed": input_data.get("msg", "")}


# =============================================================================
# 辅助：定位项目根目录的 skills/
# =============================================================================


def _project_root() -> Path:
    """获取项目根目录（WinReverseAgent/）。"""
    return Path(__file__).resolve().parents[2]


def _skills_dir() -> Path:
    """获取 skills/ 目录路径。"""
    return _project_root() / "skills"


# =============================================================================
# 端到端测试场景一：完整 Skill → Soul 数据流
# =============================================================================


class TestSkillSoulE2E:
    """端到端：Skill 加载 → SkillExecutor → Soul → 工具调用 → LLM 总结。"""

    @pytest.mark.asyncio
    async def test_full_pipeline_with_execution_flow(self, tmp_path: Path) -> None:
        """完整流程：加载 PE 分析 Skill → 预置流调用 pe.parse → LLM 生成报告。"""
        # 1. 加载真实 Skill YAML
        skills_dir = _skills_dir()
        if not skills_dir.exists():
            pytest.skip(f"skills 目录不存在: {skills_dir}")

        loader = YamlSkillLoader()
        skill = loader.load(skills_dir / "pe_analyzer.yaml")

        skill_registry = SkillRegistry()
        skill_registry.register(skill)

        # 2. 注册真实工具
        registry = ToolRegistry()
        registry.register(_StubPEParseTool())
        registry.register(_StubPEImportsTool())
        registry.register(_StubPEDetectSuspiciousTool())

        # 3. 配置 mock LLM（响应 LLM 总结报告）
        mock_llm = _ScriptedLLM(
            [
                # 第一轮：LLM 收到 prompt（含预置流结果）后直接生成报告
                _text_response(
                    "PE 文件分析报告：\n"
                    "- 文件: test.exe\n"
                    "- 位数: 64 位\n"
                    "- imphash: abc123def456\n"
                    "- 可疑 API: WriteFile (medium risk)\n"
                    "- 结论: 该文件包含文件写入操作，建议进一步动态分析。"
                )
            ]
        )

        # 4. 组装 Soul 引擎与 SkillExecutor
        soul = WinReverseSoul(llm=mock_llm, registry=registry, work_dir=tmp_path)
        executor = SkillExecutor(skill_registry=skill_registry, soul=soul)

        # 5. 执行 Skill
        result = await executor.run(
            skill.name,
            {"file_path": "test.exe", "deep_scan": False},
        )

        # 6. 验证结果
        assert isinstance(result, SkillRunResult)
        assert result.skill_name == skill.name
        assert "PE 文件分析报告" in result.final_answer
        assert "abc123def456" in result.final_answer

        # 验证预置流执行了 5 步（pe_analyzer.yaml 的 execution_flow）
        assert len(result.flow_results) == 5
        assert result.flow_results[0].action == "pe.parse"
        assert result.flow_results[1].action == "pe.imports"
        assert result.flow_results[2].action == "pe.suspicious_imports"
        assert result.flow_results[3].action == "pe.sections"
        assert result.flow_results[4].action == "die.scan_file"

        # 验证预置流结果注入到 prompt
        assert "预置执行流结果" in result.rendered_prompt
        assert "abc123def456" in result.rendered_prompt

        # 验证 LLM 只被调用一次（预置流结果已包含足够信息）
        assert len(mock_llm.call_history) == 1

    @pytest.mark.asyncio
    async def test_llm_autonomous_tool_call(self, tmp_path: Path) -> None:
        """LLM 主动调用工具（不依赖 execution_flow）。

        场景：Skill 无预置流，LLM 收到 prompt 后自主调用 pe.parse 工具。
        """
        # 1. 构造无 execution_flow 的 Skill
        skill_yaml = """
name: "自主工具调用"
description: "LLM 自主决定调用工具"
target: "PE 文件"
parameters:
  - name: "file_path"
    type: "string"
    required: true
prompt_template: |
  任务：分析 PE 文件 {{file_path}} 的元信息。
  请调用 pe.parse 工具获取详细信息，然后给出分析结论。
"""
        skill_file = tmp_path / "autonomous.yaml"
        skill_file.write_text(skill_yaml, encoding="utf-8")

        loader = YamlSkillLoader()
        skill = loader.load(skill_file)

        skill_registry = SkillRegistry()
        skill_registry.register(skill)

        # 2. 注册工具
        registry = ToolRegistry()
        registry.register(_StubPEParseTool())

        # 3. 配置 LLM 脚本：第一轮调工具，第二轮生成报告
        mock_llm = _ScriptedLLM(
            [
                _tool_call_response("pe.parse", {"file_path": "test.exe"}),
                _text_response(
                    "分析完成：文件 test.exe 为 64 位 PE，imphash 为 abc123def456，入口点 0x1000。"
                ),
            ]
        )

        soul = WinReverseSoul(llm=mock_llm, registry=registry, work_dir=tmp_path)
        executor = SkillExecutor(skill_registry=skill_registry, soul=soul)

        # 4. 执行
        result = await executor.run("自主工具调用", {"file_path": "test.exe"})

        # 5. 验证
        assert "分析完成" in result.final_answer
        assert "abc123def456" in result.final_answer
        # 无 execution_flow，flow_results 为空
        assert result.flow_results == []
        # LLM 被调用两次（一次工具调用，一次总结）
        assert len(mock_llm.call_history) == 2

        # 验证第二轮 LLM 调用时消息历史包含工具结果
        second_call_messages = mock_llm.call_history[1]["messages"]
        tool_messages = [m for m in second_call_messages if m.role == MessageRole.TOOL]
        assert len(tool_messages) == 1
        assert "abc123def456" in str(tool_messages[0].content)

    @pytest.mark.asyncio
    async def test_execution_flow_error_continues_pipeline(self, tmp_path: Path) -> None:
        """预置流某步失败，LLM 仍能基于其他结果生成报告。"""
        # 构造 Skill：预置流含一个不存在的工具
        skill_yaml = """
name: "容错测试"
description: "预置流含错误但 LLM 仍能完成"
target: "测试"
parameters:
  - name: "file_path"
    type: "string"
    required: true
prompt_template: |
  任务：分析 {{file_path}}。
  注意：预置流中部分步骤可能失败，请基于可用结果给出结论。
execution_flow:
  - action: "pe.parse"
    args:
      file_path: "{{file_path}}"
  - action: "nonexistent.tool"
    args: {}
"""
        skill_file = tmp_path / "fault_tolerant.yaml"
        skill_file.write_text(skill_yaml, encoding="utf-8")

        loader = YamlSkillLoader()
        skill = loader.load(skill_file)

        skill_registry = SkillRegistry()
        skill_registry.register(skill)

        registry = ToolRegistry()
        registry.register(_StubPEParseTool())  # 不注册 nonexistent.tool

        mock_llm = _ScriptedLLM(
            [
                _text_response(
                    "基于可用数据的分析：文件 test.exe 为 64 位 PE，"
                    "imphash abc123def456。部分工具调用失败，建议重试。"
                )
            ]
        )

        soul = WinReverseSoul(llm=mock_llm, registry=registry, work_dir=tmp_path)
        executor = SkillExecutor(skill_registry=skill_registry, soul=soul)

        result = await executor.run("容错测试", {"file_path": "test.exe"})

        # 验证：流程未中断，LLM 仍生成报告
        assert len(result.flow_results) == 2
        assert result.flow_results[0].is_error is False
        assert result.flow_results[1].is_error is True
        assert "nonexistent.tool" in result.flow_results[1].output
        assert "基于可用数据" in result.final_answer

    @pytest.mark.asyncio
    async def test_multiple_skills_loaded(self, tmp_path: Path) -> None:
        """同时加载多个 Skill 并按名调用。"""
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()

        # Skill 1: PE 分析
        (skills_dir / "pe.yaml").write_text(
            """
name: "PE 分析"
description: "PE 文件分析"
parameters:
  - name: "file_path"
    required: true
prompt_template: "分析 {{file_path}}"
execution_flow:
  - action: "pe.parse"
    args:
      file_path: "{{file_path}}"
""",
            encoding="utf-8",
        )

        # Skill 2: echo 测试
        (skills_dir / "echo.yaml").write_text(
            """
name: "回显测试"
description: "测试 echo 工具"
prompt_template: "回显消息 {{msg}}"
execution_flow:
  - action: "echo"
    args:
      msg: "{{msg}}"
""",
            encoding="utf-8",
        )

        loader = YamlSkillLoader()
        skill_registry = SkillRegistry()
        for yaml_file in sorted(skills_dir.glob("*.yaml")):
            skill_registry.register(loader.load(yaml_file))

        assert len(skill_registry) == 2

        registry = ToolRegistry()
        registry.register(_StubPEParseTool())
        registry.register(_StubEchoTool())

        # 用同一个 LLM 实例处理两个 Skill（每次响应不同）
        mock_llm = _ScriptedLLM(
            [
                _text_response("PE 分析完成: 64 位"),
                _text_response("回显结果: hello"),
            ]
        )

        soul = WinReverseSoul(llm=mock_llm, registry=registry, work_dir=tmp_path)
        executor = SkillExecutor(skill_registry=skill_registry, soul=soul)

        # 执行第一个 Skill
        result1 = await executor.run("PE 分析", {"file_path": "a.exe"})
        assert "PE 分析完成" in result1.final_answer
        assert len(result1.flow_results) == 1
        assert result1.flow_results[0].action == "pe.parse"

        # 执行第二个 Skill
        result2 = await executor.run("回显测试", {"msg": "hello"})
        assert "回显结果" in result2.final_answer
        assert len(result2.flow_results) == 1
        assert result2.flow_results[0].action == "echo"
        assert "hello" in result2.flow_results[0].output

    @pytest.mark.asyncio
    async def test_skill_with_agent_type_and_tool_whitelist(self, tmp_path: Path) -> None:
        """Skill 调用时指定 agent_type，应用工具白名单。"""
        from winreverse.soul.agent_spec import AgentTypeDefinition, LaborMarket

        # 创建 labor_market，注册 reverse 类型，限定工具白名单
        market = LaborMarket()
        market.register(
            AgentTypeDefinition(
                name="reverse",
                description="逆向分析",
                system_prompt_template="你是 Windows 逆向工程专家。",
                allowed_tools=("pe.parse", "pe.imports"),
            )
        )

        skill_yaml = """
name: "白名单测试"
description: "测试 agent_type 工具白名单"
parameters:
  - name: "file_path"
    required: true
prompt_template: "分析 {{file_path}}"
"""
        skill_file = tmp_path / "whitelist.yaml"
        skill_file.write_text(skill_yaml, encoding="utf-8")

        loader = YamlSkillLoader()
        skill_registry = SkillRegistry()
        skill_registry.register(loader.load(skill_file))

        registry = ToolRegistry()
        registry.register(_StubPEParseTool())
        registry.register(_StubPEImportsTool())
        registry.register(_StubEchoTool())  # 不在白名单内

        mock_llm = _ScriptedLLM([_text_response("白名单测试完成")])

        soul = WinReverseSoul(
            llm=mock_llm,
            registry=registry,
            work_dir=tmp_path,
            labor_market=market,
        )
        executor = SkillExecutor(skill_registry=skill_registry, soul=soul)

        result = await executor.run(
            "白名单测试",
            {"file_path": "test.exe"},
            agent_type="reverse",
        )

        assert "白名单测试完成" in result.final_answer

        # 验证 LLM 收到的 tools 仅含白名单中的 2 个工具
        assert len(mock_llm.call_history) == 1
        # 通过 call_history 间接验证（tools_count 应为 2）
        assert mock_llm.call_history[0]["tools_count"] == 2

    @pytest.mark.asyncio
    async def test_multi_turn_agent_loop(self, tmp_path: Path) -> None:
        """多轮 agent loop：LLM 连续调用多个工具后给出结论。"""
        skill_yaml = """
name: "多轮调用"
description: "LLM 连续调用多个工具"
parameters:
  - name: "file_path"
    required: true
prompt_template: |
  分析 {{file_path}}：
  1. 先调用 pe.parse 获取元信息
  2. 再调用 pe.imports 获取导入表
  3. 最后调用 pe.suspicious_imports 检测可疑 API
  4. 综合所有结果给出报告
"""
        skill_file = tmp_path / "multi_turn.yaml"
        skill_file.write_text(skill_yaml, encoding="utf-8")

        loader = YamlSkillLoader()
        skill_registry = SkillRegistry()
        skill_registry.register(loader.load(skill_file))

        registry = ToolRegistry()
        registry.register(_StubPEParseTool())
        registry.register(_StubPEImportsTool())
        registry.register(_StubPEDetectSuspiciousTool())

        # LLM 脚本：连续调用 3 个工具，最后总结
        mock_llm = _ScriptedLLM(
            [
                _tool_call_response("pe.parse", {"file_path": "test.exe"}, call_id="c1"),
                _tool_call_response("pe.imports", {"file_path": "test.exe"}, call_id="c2"),
                _tool_call_response(
                    "pe.suspicious_imports",
                    {"file_path": "test.exe"},
                    call_id="c3",
                ),
                _text_response(
                    "多轮分析完成：64 位 PE，导入 WriteFile 等可疑 API，建议进一步分析。"
                ),
            ]
        )

        soul = WinReverseSoul(llm=mock_llm, registry=registry, work_dir=tmp_path)
        executor = SkillExecutor(skill_registry=skill_registry, soul=soul)

        result = await executor.run("多轮调用", {"file_path": "test.exe"})

        assert "多轮分析完成" in result.final_answer
        # LLM 被调用 4 次（3 次工具 + 1 次总结）
        assert len(mock_llm.call_history) == 4
        # 无 execution_flow
        assert result.flow_results == []

    @pytest.mark.asyncio
    async def test_real_pe_skill_with_stub_tools(self, tmp_path: Path) -> None:
        """使用真实 skills/pe_analyzer.yaml + 桩工具的完整端到端测试。"""
        skills_dir = _skills_dir()
        if not skills_dir.exists():
            pytest.skip(f"skills 目录不存在: {skills_dir}")

        loader = YamlSkillLoader()
        skill = loader.load(skills_dir / "pe_analyzer.yaml")

        skill_registry = SkillRegistry()
        skill_registry.register(skill)

        # 注册 pe_analyzer.yaml execution_flow 涉及的所有工具
        registry = ToolRegistry()
        registry.register(_StubPEParseTool())
        registry.register(_StubPEImportsTool())
        registry.register(_StubPEDetectSuspiciousTool())

        # pe.sections 和 die.scan_file 用桩实现
        class _StubPESectionsTool:
            name = "pe.sections"
            description = "列出节区"

            def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
                return {
                    "status": "success",
                    "sections": [
                        {"name": ".text", "vsize": 0x1000, "rsize": 0x200},
                        {"name": ".data", "vsize": 0x200, "rsize": 0x200},
                    ],
                }

        class _StubDIETool:
            name = "die.scan_file"
            description = "DIE 扫描"

            def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
                return {
                    "status": "success",
                    "detects": [
                        {"type": "compiler", "name": "MSVC", "version": "19.0"},
                    ],
                }

        registry.register(_StubPESectionsTool())
        registry.register(_StubDIETool())

        mock_llm = _ScriptedLLM(
            [
                _text_response(
                    "## PE 文件综合分析报告\n\n"
                    "### 文件元信息\n"
                    "- 路径: test.exe\n"
                    "- 位数: 64 位 (AMD64)\n"
                    "- imphash: abc123def456\n"
                    "- 入口点: 0x1000\n\n"
                    "### 导入表摘要\n"
                    "- kernel32.dll: CreateFileW, WriteFile, ExitProcess\n"
                    "- user32.dll: MessageBoxW\n\n"
                    "### 可疑 API\n"
                    "- WriteFile (中风险)\n\n"
                    "### 节区\n"
                    "- .text (虚拟 0x1000)\n"
                    "- .data (虚拟 0x200)\n\n"
                    "### 编译器识别\n"
                    "- MSVC 19.0\n\n"
                    "### 结论\n"
                    "该文件使用 MSVC 编译，包含文件写入 API，"
                    "建议结合动态分析进一步确认行为。"
                )
            ]
        )

        soul = WinReverseSoul(llm=mock_llm, registry=registry, work_dir=tmp_path)
        executor = SkillExecutor(skill_registry=skill_registry, soul=soul)

        result = await executor.run(
            skill.name,
            {"file_path": "test.exe", "deep_scan": True},
        )

        # 验证最终报告包含所有预置流结果的关键信息
        assert "PE 文件综合分析报告" in result.final_answer
        assert "abc123def456" in result.final_answer
        assert "WriteFile" in result.final_answer
        assert "MSVC" in result.final_answer

        # 验证所有 5 个预置步骤都成功执行
        assert len(result.flow_results) == 5
        for fr in result.flow_results:
            assert fr.is_error is False, f"{fr.action} 应成功"

        # 验证 deep_scan 参数被正确传递到 die.scan_file
        die_call = result.flow_results[4]
        assert die_call.action == "die.scan_file"
        assert die_call.arguments.get("deep") is True
