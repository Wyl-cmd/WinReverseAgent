"""被测模块: winreverse.soul.orchestration（ToolOrchestrator 错误路径）。

覆盖点: 只读工具 execute 抛 Exception（_run_safe except 分支，用抛异常的
toolset 桩直达）、抛 BaseException（gather return_exceptions=True 收集 →
"unknown" 归档）、写入工具 execute 抛 Exception 的串行 errors 归档与
call_id 缺失回退工具名；另锁真实 SoulToolsetAdapter 包装异常的集成行为。
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from winreverse.engine.bus import ToolInterface, ToolRegistry
from winreverse.soul.orchestration import PartitionedResult, ToolCall, ToolOrchestrator
from winreverse.soul.toolset import SoulToolsetAdapter


class _ExplodingReadOnlyTool:
    """execute 直接抛 Exception 的只读工具（真实适配器会包装为 is_error）。"""

    name = "pe.parse"
    description = "抛异常只读工具"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("safe boom")


class _CancelledReadOnlyTool:
    """execute 抛 BaseException（非 Exception）的只读工具。

    _run_safe 只捕获 Exception，CancelledError 会穿透到
    asyncio.gather(return_exceptions=True) 的结果收集分支。
    """

    name = "disasm"
    description = "抛取消只读工具"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        raise asyncio.CancelledError()


class _ExplodingWriteTool:
    """execute 直接抛 Exception 的写入工具。"""

    name = "memory.write"
    description = "抛异常写入工具"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        raise OSError("unsafe boom")


class _OkReadOnlyTool:
    """正常只读工具，用于混合批次中验证成功结果不受异常影响。"""

    name = "pe.meta"
    description = "正常只读工具"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {"status": "success", "result": "meta-ok"}


class _RaisingToolset:
    """execute 直接抛异常的 toolset 桩（直达编排器自身的 except 分支）。"""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    async def execute(self, name: str, arguments: dict[str, Any]) -> Any:
        raise self._exc


def _adapter(*tools: ToolInterface) -> SoulToolsetAdapter:
    """构造包含指定工具的 SoulToolsetAdapter（与既有 orchestration 测试一致）。"""
    registry = ToolRegistry()
    for tool in tools:
        registry.register(tool)
    return SoulToolsetAdapter(registry)


# =============================================================================
# 只读（safe）分区错误路径
# =============================================================================


class TestSafeErrorPaths:
    """只读工具异常 → 归档进 errors 而非中断整批。"""

    @pytest.mark.asyncio
    async def test_toolset_exception_recorded_as_error(self) -> None:
        """toolset.execute 抛 Exception：结果为 (call_id, str(exc)) 归档。"""
        orchestrator = ToolOrchestrator(_RaisingToolset(RuntimeError("safe boom")))
        result = await orchestrator.run_tools_partitioned(
            [ToolCall(name="pe.parse", arguments={"file_path": "a.exe"}, call_id="c1")]
        )
        assert result.safe_results == []
        assert result.unsafe_results == []
        assert result.errors == [("c1", "safe boom")]

    @pytest.mark.asyncio
    async def test_toolset_base_exception_recorded_as_unknown(self) -> None:
        """toolset.execute 抛 BaseException：gather 收集后按 ("unknown", ...) 归档。"""
        orchestrator = ToolOrchestrator(_RaisingToolset(asyncio.CancelledError()))
        result = await orchestrator.run_tools_partitioned(
            [ToolCall(name="disasm", arguments={"address": "0x401000"}, call_id="c2")]
        )
        assert len(result.errors) == 1
        call_id, message = result.errors[0]
        assert call_id == "unknown"
        assert isinstance(message, str)

    @pytest.mark.asyncio
    async def test_adapter_wraps_tool_exception_as_error_result(self) -> None:
        """集成行为：真实适配器把工具异常包装为 is_error 结果进 errors。"""
        orchestrator = ToolOrchestrator(_adapter(_ExplodingReadOnlyTool()))
        result = await orchestrator.run_tools_partitioned(
            [ToolCall(name="pe.parse", arguments={}, call_id="c1")]
        )
        assert result.safe_results == []
        assert len(result.errors) == 1
        call_id, message = result.errors[0]
        assert call_id == "c1"
        assert "safe boom" in message
        assert "execution failed" in message

    @pytest.mark.asyncio
    async def test_mixed_batch_one_safe_failure_does_not_affect_others(self) -> None:
        """混合批次：一个只读工具失败不吞掉其他只读工具的成功结果。"""
        orchestrator = ToolOrchestrator(_adapter(_ExplodingReadOnlyTool(), _OkReadOnlyTool()))
        result = await orchestrator.run_tools_partitioned(
            [
                ToolCall(name="pe.parse", arguments={}, call_id="bad"),
                ToolCall(name="pe.meta", arguments={}, call_id="good"),
            ]
        )
        assert [call_id for call_id, _ in result.safe_results] == ["good"]
        assert json.loads(result.safe_results[0][1])["result"] == "meta-ok"
        assert len(result.errors) == 1
        assert result.errors[0][0] == "bad"


# =============================================================================
# 写入（unsafe）分区错误路径
# =============================================================================


class TestUnsafeErrorPaths:
    """写入工具异常 → 串行执行中归档进 errors。"""

    @pytest.mark.asyncio
    async def test_toolset_exception_recorded_with_call_id(self) -> None:
        """toolset.execute 抛 Exception：(call_id, str(exc)) 归档。"""
        orchestrator = ToolOrchestrator(_RaisingToolset(OSError("unsafe boom")))
        result = await orchestrator.run_tools_partitioned(
            [ToolCall(name="memory.write", arguments={"value": 1}, call_id="w1")]
        )
        assert result.unsafe_results == []
        assert result.errors == [("w1", "unsafe boom")]

    @pytest.mark.asyncio
    async def test_toolset_exception_falls_back_to_tool_name(self) -> None:
        """call_id 为空串时归档键回退为工具名（call.call_id or call.name）。"""
        orchestrator = ToolOrchestrator(_RaisingToolset(OSError("unsafe boom")))
        result = await orchestrator.run_tools_partitioned(
            [ToolCall(name="memory.write", arguments={"value": 1})]
        )
        assert result.errors == [("memory.write", "unsafe boom")]

    @pytest.mark.asyncio
    async def test_adapter_wraps_write_tool_exception(self) -> None:
        """集成行为：写入工具异常经真实适配器包装后归档进 errors。"""
        orchestrator = ToolOrchestrator(_adapter(_ExplodingWriteTool()))
        result = await orchestrator.run_tools_partitioned(
            [ToolCall(name="memory.write", arguments={}, call_id="w1")]
        )
        assert result.unsafe_results == []
        assert len(result.errors) == 1
        assert result.errors[0][0] == "w1"
        assert "unsafe boom" in result.errors[0][1]

    @pytest.mark.asyncio
    async def test_empty_calls_returns_empty_result(self) -> None:
        """空调用列表直接返回空 PartitionedResult（短路分支）。"""
        orchestrator = ToolOrchestrator(_RaisingToolset(RuntimeError()))
        result = await orchestrator.run_tools_partitioned([])
        assert isinstance(result, PartitionedResult)
        assert result == PartitionedResult()
