"""测试模块：winreverse.soul.soul 尾部路径。

覆盖：未知压缩策略回退 layered 并告警、last_agent 未运行时为 None、
build_system_prompt 附加 agent_type 过滤上下文、start 后 run 不重复启动。
全部使用 mock LLM，Linux 可跑，无平台依赖。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from kosong.types import GenerateResult, Message, MessageRole, Usage
from winreverse.engine.bus import ToolRegistry
from winreverse.soul.compaction import CompactionStrategy
from winreverse.soul.soul import WinReverseSoul


class _MockLLM:
    """Mock LLM 生成器（与 test_soul 同约定）。"""

    def __init__(self, responses: list[GenerateResult] | None = None) -> None:
        self._responses = list(responses) if responses else []

    async def generate(
        self,
        messages: list[Message],
        model: str | None = None,
        tools: list[Any] | None = None,
    ) -> GenerateResult:
        _ = messages, model, tools
        if self._responses:
            return self._responses.pop(0)
        return GenerateResult(
            message=Message(role=MessageRole.ASSISTANT, content="已完成"),
            stop_reason="stop",
            usage=Usage(),
        )


def _make_result(content: str = "ok") -> GenerateResult:
    """构造单轮回复。"""
    return GenerateResult(
        message=Message(role=MessageRole.ASSISTANT, content=content),
        stop_reason="stop",
        usage=Usage(),
    )


def _soul(tmp_path: Path, **kwargs: Any) -> WinReverseSoul:
    """构造最小 Soul 实例。"""
    return WinReverseSoul(llm=_MockLLM(), registry=ToolRegistry(), work_dir=tmp_path, **kwargs)


class TestTailPaths:
    """soul.py 既有用例未触达的分支。"""

    def test_unknown_compaction_strategy_falls_back_to_layered(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """未知压缩策略：回退 LAYERED 并记录 warning。"""
        with caplog.at_level(logging.WARNING, logger="winreverse.soul.soul"):
            soul = _soul(tmp_path, compaction_strategy="no_such_strategy")

        assert soul._compactor._strategy is CompactionStrategy.LAYERED
        assert "未知压缩策略" in caplog.text
        assert "no_such_strategy" in caplog.text

    def test_last_agent_none_before_run(self, tmp_path: Path) -> None:
        """未运行任何 agent 时 last_agent 返回 None 而非 AttributeError。"""
        soul = _soul(tmp_path)
        assert soul.last_agent is None

    def test_build_system_prompt_appends_agent_type_context(self, tmp_path: Path) -> None:
        """上下文命中 agent_type 关键词时追加到系统提示词末尾。"""
        winreverse_dir = tmp_path / ".winreverse"
        winreverse_dir.mkdir()
        (winreverse_dir / "KXNS.md").write_text(
            "# reverse notes\nbinary disassemble workflow", encoding="utf-8"
        )
        soul = _soul(tmp_path)
        soul.start()

        prompt = soul.build_system_prompt("基础提示", agent_type="reverse")

        assert "基础提示" in prompt
        assert "--- agent_type=reverse context ---" in prompt
        assert "binary disassemble workflow" in prompt

    @pytest.mark.asyncio
    async def test_run_after_explicit_start_does_not_reload(self, tmp_path: Path) -> None:
        """显式 start 后 run 走已启动分支，不重复加载上下文。"""
        winreverse_dir = tmp_path / ".winreverse"
        winreverse_dir.mkdir()
        (winreverse_dir / "KXNS.md").write_text("# ctx", encoding="utf-8")

        soul = WinReverseSoul(
            llm=_MockLLM([_make_result(content="ok")]),
            registry=ToolRegistry(),
            work_dir=tmp_path,
        )
        soul.start()
        assert soul._started is True

        result = await soul.run("hi")

        assert result == "ok"
        assert len(soul.context_manager._entries) == 1  # 幂等：未二次加载
