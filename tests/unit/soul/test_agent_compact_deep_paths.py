"""测试模块：winreverse.soul.agent — 压缩深路径与 run() 收尾分支。

覆盖点：整体压缩 LLM 路径与确定性兜底（agent.py:297–306）、压缩异常→熔断器
record_failure（327–329）、call_llm 缺 generate() 守卫（198）、run() 结束时
保留 step 期改写的状态（374）、最终答复跳过无 .text 的内容部件（386）与
str 内容防御分支（382，仅 model_construct 可构造）。
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from kosong.types import GenerateResult, Message, MessageRole, TextPart, Usage
from winreverse.soul.agent import Agent, AgentConfig, AgentState, Runtime


class _ScriptedLLM:
    """按脚本顺序返回 GenerateResult 的最小 LLM 桩。"""

    def __init__(self, responses: list[GenerateResult]) -> None:
        self._responses = list(responses)
        self._call_count = 0

    async def generate(self, messages, model=None, tools=None) -> GenerateResult:
        _ = messages, model, tools
        if self._call_count >= len(self._responses):
            return GenerateResult(
                message=Message(role=MessageRole.ASSISTANT, content="done"),
                stop_reason="stop",
                usage=Usage(),
            )
        response = self._responses[self._call_count]
        self._call_count += 1
        return response


def _gr(content: str) -> GenerateResult:
    return GenerateResult(
        message=Message(role=MessageRole.ASSISTANT, content=content),
        stop_reason="stop",
        usage=Usage(),
    )


class _StubAutoCompact:
    """AutoCompact 熔断器替身：记录 success/failure 调用次数。"""

    def __init__(self, should: bool = True) -> None:
        self.buffer_tokens = 100
        self._should = should
        self.success_calls = 0
        self.failure_calls = 0

    def should_compact(
        self, token_count: int, max_context_size: int, reserved_context_size: int = 0
    ) -> bool:
        _ = token_count, max_context_size, reserved_context_size
        return self._should

    def record_success(self) -> None:
        self.success_calls += 1

    def record_failure(self) -> None:
        self.failure_calls += 1


class _StubCleaner:
    """MicroCompact / SnipCompact 替身：原样返回消息并报固定节省量。"""

    def __init__(self, saved: int = 0, error: Exception | None = None) -> None:
        self._saved = saved
        self._error = error
        self.calls = 0

    def compact(self, messages: list[Message], model: str | None = None):
        _ = model
        self.calls += 1
        if self._error is not None:
            raise self._error
        return list(messages), self._saved


class _StubCompactor:
    """Compactor 鸭子类型替身：estimate 按脚本出队，压缩路径全可控。"""

    def __init__(
        self,
        estimates: list[int],
        *,
        should: bool = True,
        has_llm: bool = True,
        llm_messages: list[Message] | None = None,
        deterministic_messages: list[Message] | None = None,
        micro_error: Exception | None = None,
    ) -> None:
        self._estimates = list(estimates)
        self.has_llm = has_llm
        self.auto_compact = _StubAutoCompact(should)
        self.micro_compact = _StubCleaner(saved=3, error=micro_error)
        self.snip_compact = _StubCleaner(saved=2)
        self._llm_messages = llm_messages if llm_messages is not None else []
        self._deterministic = deterministic_messages if deterministic_messages is not None else []
        self.llm_calls = 0
        self.deterministic_calls = 0

    def estimate_tokens(self, messages: list[Message], model: str | None = None) -> int:
        _ = messages, model
        return self._estimates.pop(0) if self._estimates else 0

    async def compact_with_llm(self, messages: list[Message], model: str | None = None):
        _ = messages, model
        self.llm_calls += 1
        return SimpleNamespace(messages=list(self._llm_messages))

    def compact(self, messages: list[Message], model: str | None = None):
        _ = messages, model
        self.deterministic_calls += 1
        return list(self._deterministic), SimpleNamespace(ok=True)


def _agent(responses: list[GenerateResult], **cfg) -> Agent:
    config = AgentConfig(name="t", system_prompt="s", **cfg)
    return Agent(config, Runtime(llm=_ScriptedLLM(responses)))


def _compact_agent(responses: list[GenerateResult], compactor) -> Agent:
    """压缩器必须注入 Runtime（AgentConfig 上无此字段，误传会被 pydantic 忽略）。"""
    config = AgentConfig(name="t", system_prompt="s", max_context_size=100)
    return Agent(config, Runtime(llm=_ScriptedLLM(responses), compactor=compactor))


def _seed_history(agent: Agent, count: int = 2) -> list[Message]:
    """预置旧对话历史，保证 LLM 压缩结果（1 条）短于现历史。"""
    seeded = [Message(role=MessageRole.USER, content=f"旧消息{i}") for i in range(count)]
    agent.messages.extend(seeded)
    return seeded


class TestCompactionDeepPaths:
    """_maybe_compact 的整体压缩分支（微压缩/裁剪不足以回落阈值时）。"""

    async def test_llm_compaction_applied_when_micro_snip_insufficient(self):
        """has_llm 且压缩后回落阈值内 → 采纳 LLM 压缩结果，used_llm=True。"""
        summary = Message(role=MessageRole.USER, content="总结")
        compactor = _StubCompactor(
            [150, 120, 50, 40],
            should=True,
            has_llm=True,
            llm_messages=[summary],
        )
        agent = _compact_agent([_gr("done")], compactor)
        _seed_history(agent)

        answer = await agent.run("hi")

        assert answer == "done"
        # LLM 压缩结果替换原历史；其后 run() 追加了本轮 assistant 答复
        assert agent.messages[:-1] == [summary]
        assert agent.messages[-1].role == MessageRole.ASSISTANT
        assert agent.compaction_count == 1
        assert agent.last_compaction is not None
        assert agent.last_compaction.used_llm is True
        assert agent.last_compaction.before_tokens == 150
        assert agent.last_compaction.after_tokens == 40
        assert agent.last_compaction.micro_saved == 3
        assert agent.last_compaction.snip_freed == 2
        # LLM 压缩生效后无需确定性兜底
        assert compactor.llm_calls == 1
        assert compactor.deterministic_calls == 0
        assert compactor.auto_compact.success_calls == 1
        assert compactor.auto_compact.failure_calls == 0

    async def test_deterministic_compact_fallback_without_llm(self):
        """has_llm=False → 跳过 LLM 压缩，退回确定性 compact()。"""
        detached = Message(role=MessageRole.USER, content="确定性压缩结果")
        compactor = _StubCompactor(
            [150, 120, 110, 60],
            should=True,
            has_llm=False,
            deterministic_messages=[detached],
        )
        agent = _compact_agent([_gr("done")], compactor)
        _seed_history(agent)

        answer = await agent.run("hi")

        assert answer == "done"
        assert agent.messages[:-1] == [detached]
        assert agent.messages[-1].role == MessageRole.ASSISTANT
        assert agent.last_compaction is not None
        assert agent.last_compaction.used_llm is False
        assert compactor.llm_calls == 0
        assert compactor.deterministic_calls == 1
        assert compactor.auto_compact.success_calls == 1

    async def test_compaction_failure_swallowed_and_circuit_breaker_notified(self):
        """微压缩抛异常 → 不中断主循环，熔断器记 failure 而非 success。"""
        compactor = _StubCompactor(
            [150],
            should=True,
            has_llm=True,
            micro_error=RuntimeError("micro compact boom"),
        )
        agent = _compact_agent([_gr("done")], compactor)
        seeded = _seed_history(agent)

        answer = await agent.run("hi")

        # 主循环存活：正常拿到 LLM 最终答复
        assert answer == "done"
        assert compactor.auto_compact.failure_calls == 1
        assert compactor.auto_compact.success_calls == 0
        assert agent.last_compaction is None
        assert agent.compaction_count == 0
        # 历史未被半途篡改：预置消息 + 本轮 user/assistant 各一条
        assert agent.messages[:2] == seeded
        assert len(agent.messages) == 4


class TestCallLlmGuard:
    """Runtime.call_llm 的依赖守卫。"""

    async def test_call_llm_raises_when_llm_has_no_generate(self):
        """llm 对象缺 generate() 方法 → RuntimeError（而非 AttributeError）。"""
        runtime = Runtime(llm=SimpleNamespace())
        with pytest.raises(RuntimeError, match="missing generate"):
            await runtime.call_llm("agent-1", [])


class TestRunTailBranches:
    """run() 收尾：状态保留与最终答复抽取边界。"""

    async def test_run_keeps_state_changed_during_step(self):
        """step 期把状态改为 WAITING_APPROVAL → run 结束不得覆盖为 FINISHED。"""
        agent = _agent([_gr("done")])
        original_step = agent.step

        async def _step():
            result = await original_step()
            agent.state = AgentState.WAITING_APPROVAL
            return result

        agent.step = _step  # type: ignore[method-assign]
        answer = await agent.run("hi")

        assert answer == "done"
        assert agent.state is AgentState.WAITING_APPROVAL

    async def test_final_answer_skips_non_text_parts(self):
        """内容含无 .text 的部件（image_url）→ 最终答复只拼接文本部件。"""
        image_part = {"type": "image_url", "image_url": {"url": "mem://x.png"}}
        response = GenerateResult(
            message=Message(
                role=MessageRole.ASSISTANT,
                content=[TextPart(text="A"), image_part],
            ),
            stop_reason="stop",
            usage=Usage(),
        )
        agent = _agent([response])

        answer = await agent.run("hi")

        assert answer == "A"

    async def test_final_answer_raw_str_content_defensive(self):
        """防御分支：content 为裸 str（绕过校验构造）时原样返回。"""
        raw = Message.model_construct(role=MessageRole.ASSISTANT, content="裸字符串答复")
        response = GenerateResult(message=raw, stop_reason="stop", usage=Usage())
        agent = _agent([response])

        answer = await agent.run("hi")

        assert answer == "裸字符串答复"
