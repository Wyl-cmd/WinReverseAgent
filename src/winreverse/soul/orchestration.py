"""winreverse.soul.orchestration — 工具调用编排。

从 KXNS soul/orchestration.py 裁剪迁移，主要改动：
- 移除 `from kxns.soul.toolset import ToolDefinition, Toolset` 依赖
- ToolOrchestrator 改用 SoulToolsetAdapter（WinReverseAgent 适配器）
- 工具分类（只读/写入）调整为 WinReverseAgent 工具命名规范

功能：
- ToolCall: 工具调用请求数据类
- PartitionedResult: 分区执行结果（safe/unsafe/errors）
- ToolOrchestrator: 工具并发编排器，只读工具并行执行，写入工具串行执行

参考：实施方案 §8.2.6
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from winreverse.soul.toolset import SoulToolsetAdapter

logger = logging.getLogger(__name__)


# WinReverseAgent 只读工具集（可并行执行，无副作用）
_READ_ONLY_TOOLS: set[str] = {
    # PE 分析（仅读取文件元信息）
    "pe.parse",
    "pe.imports",
    "pe.exports",
    "pe.sections",
    "pe.suspicious_imports",
    "pe.meta",
    # 反汇编（仅读取代码）
    "disasm",
    # YARA 扫描（仅匹配，不修改）
    "yara.scan_file",
    "yara.scan_memory",
    # DIE 扫描（仅识别，不修改）
    "die.scan_file",
    "die.scan_memory",
    # memory.read 仅读取，但实际依赖 attach 会话，仍归入 unsafe
}

# WinReverseAgent 写入工具集（必须串行执行，有副作用）
_WRITE_TOOLS: set[str] = {
    "memory.attach",  # 附加进程（有状态变更）
    "memory.read",  # 依赖 attach 会话
    "memory.write",  # 写入进程内存（有副作用）
}


@dataclass(slots=True)
class ToolCall:
    """工具调用请求。

    Attributes:
        name: 工具名
        arguments: 输入参数
        call_id: 调用 ID（用于结果关联，可选）
    """

    name: str
    arguments: dict[str, Any]
    call_id: str = ""


@dataclass
class PartitionedResult:
    """分区执行结果。

    Attributes:
        safe_results: 只读工具的执行结果列表 [(call_id, output), ...]
        unsafe_results: 写入工具的执行结果列表 [(call_id, output), ...]
        errors: 错误列表 [(call_id, error_message), ...]
    """

    safe_results: list[tuple[str, str]] = field(default_factory=list)
    unsafe_results: list[tuple[str, str]] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)


class ToolOrchestrator:
    """工具调用编排器。

    根据工具是否并发安全（只读 vs 写入）分区执行：
    - 只读工具：使用 Semaphore 并行执行（默认 max_concurrent_safe=5）
    - 写入工具：串行执行，避免竞态条件

    用法：
        adapter = SoulToolsetAdapter(registry)
        orchestrator = ToolOrchestrator(adapter)
        result = await orchestrator.run_tools_partitioned([
            ToolCall(name="pe.parse", arguments={"file_path": "test.exe"}),
            ToolCall(name="pe.imports", arguments={"file_path": "test.exe"}),
        ])
    """

    def __init__(
        self,
        toolset: SoulToolsetAdapter,
        max_concurrent_safe: int = 5,
    ) -> None:
        """初始化编排器。

        Args:
            toolset: Soul 工具集适配器
            max_concurrent_safe: 只读工具最大并发数
        """
        self._toolset = toolset
        self._max_concurrent_safe = max_concurrent_safe
        self._custom_safe_rules: dict[str, Callable[[dict[str, Any]], bool]] = {}

    @staticmethod
    def is_concurrency_safe(tool_name: str, input_args: dict[str, Any] | None = None) -> bool:
        """判断工具是否并发安全（只读无副作用）。

        Args:
            tool_name: 工具名
            input_args: 输入参数（当前未使用，预留扩展）

        Returns:
            True 表示可并行执行，False 表示必须串行
        """
        _ = input_args  # 预留：未来可根据参数动态判断
        if tool_name in _READ_ONLY_TOOLS:
            return True
        if tool_name in _WRITE_TOOLS:
            return False
        # 未知工具默认不并发（保守策略）
        return False

    def register_safety_rule(
        self,
        tool_name: str,
        rule: Callable[[dict[str, Any]], bool],
    ) -> None:
        """注册自定义安全规则。

        Args:
            tool_name: 工具名
            rule: 判定函数，接收 input_args 返回 bool
        """
        self._custom_safe_rules[tool_name] = rule

    def _check_safety(self, tool_name: str, input_args: dict[str, Any]) -> bool:
        """检查工具是否安全（优先使用自定义规则）。"""
        if tool_name in self._custom_safe_rules:
            return self._custom_safe_rules[tool_name](input_args)
        return self.is_concurrency_safe(tool_name, input_args)

    def partition_calls(
        self,
        calls: list[ToolCall],
    ) -> tuple[list[ToolCall], list[ToolCall]]:
        """将工具调用分区为（safe, unsafe）两组。"""
        safe: list[ToolCall] = []
        unsafe: list[ToolCall] = []
        for call in calls:
            if self._check_safety(call.name, call.arguments):
                safe.append(call)
            else:
                unsafe.append(call)
        return safe, unsafe

    async def run_tools_partitioned(
        self,
        calls: list[ToolCall],
    ) -> PartitionedResult:
        """分区执行工具调用。

        Args:
            calls: 工具调用列表

        Returns:
            PartitionedResult 包含 safe_results / unsafe_results / errors
        """
        result = PartitionedResult()
        if not calls:
            return result

        safe_calls, unsafe_calls = self.partition_calls(calls)

        # 并行执行只读工具
        if safe_calls:
            semaphore = asyncio.Semaphore(self._max_concurrent_safe)

            async def _run_safe(call: ToolCall) -> tuple[str, str, bool]:
                async with semaphore:
                    try:
                        tool_result = await self._toolset.execute(
                            call.name,
                            call.arguments,
                        )
                        return (call.call_id or call.name, tool_result.output, tool_result.is_error)
                    except Exception as exc:
                        return (call.call_id or call.name, str(exc), True)

            safe_coros = [_run_safe(c) for c in safe_calls]
            safe_outputs = await asyncio.gather(*safe_coros, return_exceptions=True)

            for item in safe_outputs:
                if isinstance(item, BaseException):
                    result.errors.append(("unknown", str(item)))
                else:
                    call_id, output, is_error = item
                    if is_error:
                        result.errors.append((call_id, output))
                    else:
                        result.safe_results.append((call_id, output))

        # 串行执行写入工具
        for call in unsafe_calls:
            try:
                tool_result = await self._toolset.execute(call.name, call.arguments)
                if tool_result.is_error:
                    result.errors.append((call.call_id or call.name, tool_result.output))
                else:
                    result.unsafe_results.append((call.call_id or call.name, tool_result.output))
            except Exception as exc:
                result.errors.append((call.call_id or call.name, str(exc)))

        return result
