"""测试模块：winreverse.soul.orchestration

覆盖 ToolOrchestrator 的工具分区、并发执行、串行执行、错误处理。
"""

from __future__ import annotations

from typing import Any

import pytest

from winreverse.engine.bus import ToolInterface, ToolRegistry
from winreverse.soul.orchestration import (
    PartitionedResult,
    ToolCall,
    ToolOrchestrator,
)
from winreverse.soul.toolset import SoulToolsetAdapter

# =============================================================================
# 测试用工具
# =============================================================================


class _ReadOnlyTool:
    """只读工具（pe.parse 风格）。"""

    name = "pe.parse"
    description = "解析 PE 文件"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {"status": "success", "result": f"parsed {input_data.get('file', '')}"}


class _WriteTool:
    """写入工具（memory.write 风格）。"""

    name = "memory.write"
    description = "写入内存"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {"status": "success", "written": input_data.get("value", "")}


class _ErrorTool:
    """总是返回错误的工具。"""

    name = "pe.parse"
    description = "失败工具"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {"status": "error", "error_message": "orchestration test error"}


def _build_adapter(*tools: ToolInterface) -> SoulToolsetAdapter:
    """构造包含指定工具的 SoulToolsetAdapter。"""
    registry = ToolRegistry()
    for tool in tools:
        registry.register(tool)
    return SoulToolsetAdapter(registry)


# =============================================================================
# ToolCall 数据类测试
# =============================================================================


class TestToolCall:
    """ToolCall 数据类测试。"""

    def test_create_with_required_fields(self) -> None:
        """创建 ToolCall 实例（仅必填字段）。"""
        call = ToolCall(name="pe.parse", arguments={"file": "test.exe"})
        assert call.name == "pe.parse"
        assert call.arguments == {"file": "test.exe"}
        assert call.call_id == ""

    def test_create_with_call_id(self) -> None:
        """创建带 call_id 的 ToolCall。"""
        call = ToolCall(name="pe.parse", arguments={}, call_id="call-123")
        assert call.call_id == "call-123"


# =============================================================================
# PartitionedResult 数据类测试
# =============================================================================


class TestPartitionedResult:
    """PartitionedResult 数据类测试。"""

    def test_default_empty(self) -> None:
        """默认实例所有列表为空。"""
        result = PartitionedResult()
        assert result.safe_results == []
        assert result.unsafe_results == []
        assert result.errors == []

    def test_with_results(self) -> None:
        """带结果的实例。"""
        result = PartitionedResult(
            safe_results=[("call1", "output1")],
            unsafe_results=[("call2", "output2")],
            errors=[("call3", "error1")],
        )
        assert len(result.safe_results) == 1
        assert len(result.unsafe_results) == 1
        assert len(result.errors) == 1


# =============================================================================
# is_concurrency_safe 静态方法测试
# =============================================================================


class TestIsConcurrencySafe:
    """is_concurrency_safe 静态方法测试。"""

    def test_read_only_tool_is_safe(self) -> None:
        """只读工具并发安全。"""
        assert ToolOrchestrator.is_concurrency_safe("pe.parse") is True
        assert ToolOrchestrator.is_concurrency_safe("pe.imports") is True
        assert ToolOrchestrator.is_concurrency_safe("yara.scan_file") is True
        assert ToolOrchestrator.is_concurrency_safe("die.scan_memory") is True
        assert ToolOrchestrator.is_concurrency_safe("disasm") is True

    def test_write_tool_is_unsafe(self) -> None:
        """写入工具不并发安全。"""
        assert ToolOrchestrator.is_concurrency_safe("memory.attach") is False
        assert ToolOrchestrator.is_concurrency_safe("memory.read") is False
        assert ToolOrchestrator.is_concurrency_safe("memory.write") is False

    def test_unknown_tool_is_unsafe(self) -> None:
        """未知工具默认不并发安全。"""
        assert ToolOrchestrator.is_concurrency_safe("unknown.tool") is False

    def test_with_input_args(self) -> None:
        """传入 input_args 参数不影响结果。"""
        assert ToolOrchestrator.is_concurrency_safe("pe.parse", {"file": "test"}) is True
        assert ToolOrchestrator.is_concurrency_safe("memory.write", {"value": 1}) is False


# =============================================================================
# ToolOrchestrator 初始化测试
# =============================================================================


class TestToolOrchestratorInit:
    """ToolOrchestrator 初始化测试。"""

    def test_init_default_concurrency(self) -> None:
        """默认并发数为 5。"""
        adapter = _build_adapter(_ReadOnlyTool())
        orchestrator = ToolOrchestrator(adapter)
        assert orchestrator._max_concurrent_safe == 5

    def test_init_custom_concurrency(self) -> None:
        """自定义并发数。"""
        adapter = _build_adapter(_ReadOnlyTool())
        orchestrator = ToolOrchestrator(adapter, max_concurrent_safe=10)
        assert orchestrator._max_concurrent_safe == 10


# =============================================================================
# partition_calls 测试
# =============================================================================


class TestPartitionCalls:
    """partition_calls 分区测试。"""

    def test_partition_all_safe(self) -> None:
        """全部为只读工具。"""
        adapter = _build_adapter(_ReadOnlyTool())
        orchestrator = ToolOrchestrator(adapter)

        calls = [
            ToolCall(name="pe.parse", arguments={}),
            ToolCall(name="pe.parse", arguments={}),
        ]
        safe, unsafe = orchestrator.partition_calls(calls)

        assert len(safe) == 2
        assert len(unsafe) == 0

    def test_partition_all_unsafe(self) -> None:
        """全部为写入工具。"""
        adapter = _build_adapter(_WriteTool())
        orchestrator = ToolOrchestrator(adapter)

        calls = [
            ToolCall(name="memory.write", arguments={}),
            ToolCall(name="memory.write", arguments={}),
        ]
        safe, unsafe = orchestrator.partition_calls(calls)

        assert len(safe) == 0
        assert len(unsafe) == 2

    def test_partition_mixed(self) -> None:
        """混合工具分区。"""
        adapter = _build_adapter(_ReadOnlyTool(), _WriteTool())
        orchestrator = ToolOrchestrator(adapter)

        calls = [
            ToolCall(name="pe.parse", arguments={}),
            ToolCall(name="memory.write", arguments={}),
            ToolCall(name="pe.parse", arguments={}),
        ]
        safe, unsafe = orchestrator.partition_calls(calls)

        assert len(safe) == 2
        assert len(unsafe) == 1

    def test_partition_empty_list(self) -> None:
        """空列表分区。"""
        adapter = _build_adapter()
        orchestrator = ToolOrchestrator(adapter)

        safe, unsafe = orchestrator.partition_calls([])
        assert safe == []
        assert unsafe == []

    def test_custom_safety_rule(self) -> None:
        """自定义安全规则覆盖默认。"""
        adapter = _build_adapter(_ReadOnlyTool())
        orchestrator = ToolOrchestrator(adapter)
        orchestrator.register_safety_rule("pe.parse", lambda args: False)

        calls = [ToolCall(name="pe.parse", arguments={})]
        safe, unsafe = orchestrator.partition_calls(calls)

        assert len(safe) == 0
        assert len(unsafe) == 1


# =============================================================================
# run_tools_partitioned 异步测试
# =============================================================================


class TestRunToolsPartitioned:
    """run_tools_partitioned 异步执行测试。"""

    @pytest.mark.asyncio
    async def test_empty_calls(self) -> None:
        """空调用列表返回空结果。"""
        adapter = _build_adapter()
        orchestrator = ToolOrchestrator(adapter)

        result = await orchestrator.run_tools_partitioned([])

        assert result.safe_results == []
        assert result.unsafe_results == []
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_safe_calls_parallel(self) -> None:
        """只读工具并行执行。"""
        adapter = _build_adapter(_ReadOnlyTool())
        orchestrator = ToolOrchestrator(adapter)

        calls = [
            ToolCall(name="pe.parse", arguments={"file": "a.exe"}, call_id="call1"),
            ToolCall(name="pe.parse", arguments={"file": "b.exe"}, call_id="call2"),
        ]
        result = await orchestrator.run_tools_partitioned(calls)

        assert len(result.safe_results) == 2
        assert len(result.unsafe_results) == 0
        assert len(result.errors) == 0

        # 验证结果关联
        call_ids = {cid for cid, _ in result.safe_results}
        assert call_ids == {"call1", "call2"}

    @pytest.mark.asyncio
    async def test_unsafe_calls_serial(self) -> None:
        """写入工具串行执行。"""
        adapter = _build_adapter(_WriteTool())
        orchestrator = ToolOrchestrator(adapter)

        calls = [
            ToolCall(name="memory.write", arguments={"value": "a"}, call_id="call1"),
            ToolCall(name="memory.write", arguments={"value": "b"}, call_id="call2"),
        ]
        result = await orchestrator.run_tools_partitioned(calls)

        assert len(result.unsafe_results) == 2
        assert len(result.safe_results) == 0
        assert len(result.errors) == 0

    @pytest.mark.asyncio
    async def test_mixed_calls(self) -> None:
        """混合调用：只读并行 + 写入串行。"""
        adapter = _build_adapter(_ReadOnlyTool(), _WriteTool())
        orchestrator = ToolOrchestrator(adapter)

        calls = [
            ToolCall(name="pe.parse", arguments={}, call_id="safe1"),
            ToolCall(name="memory.write", arguments={}, call_id="unsafe1"),
            ToolCall(name="pe.parse", arguments={}, call_id="safe2"),
        ]
        result = await orchestrator.run_tools_partitioned(calls)

        assert len(result.safe_results) == 2
        assert len(result.unsafe_results) == 1

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        """工具返回错误时归入 errors。"""
        adapter = _build_adapter(_ErrorTool())
        orchestrator = ToolOrchestrator(adapter)

        calls = [ToolCall(name="pe.parse", arguments={}, call_id="err1")]
        result = await orchestrator.run_tools_partitioned(calls)

        assert len(result.errors) == 1
        assert len(result.safe_results) == 0

    @pytest.mark.asyncio
    async def test_unknown_tool_error(self) -> None:
        """未知工具调用归入 errors。"""
        adapter = _build_adapter()
        orchestrator = ToolOrchestrator(adapter)

        calls = [ToolCall(name="unknown.tool", arguments={}, call_id="unknown1")]
        result = await orchestrator.run_tools_partitioned(calls)

        # 未知工具默认 unsafe，串行执行时也归入 errors
        assert len(result.errors) == 1
        assert "not found" in result.errors[0][1] or "execution failed" in result.errors[0][1]

    @pytest.mark.asyncio
    async def test_call_id_defaults_to_name(self) -> None:
        """无 call_id 时用工具名作为标识。"""
        adapter = _build_adapter(_ReadOnlyTool())
        orchestrator = ToolOrchestrator(adapter)

        calls = [ToolCall(name="pe.parse", arguments={})]
        result = await orchestrator.run_tools_partitioned(calls)

        assert len(result.safe_results) == 1
        assert result.safe_results[0][0] == "pe.parse"
