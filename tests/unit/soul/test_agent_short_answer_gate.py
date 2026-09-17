"""测试模块：agent「短答闸门」（P0-4）—— 空答 / 引子答 / 正常答 三类判别。

背景（2026-09-17 错峰轮实测）：
    技能 E2E 出现 146–255 字符「元话术引子」以 rc=0 交付，累计 5/23 ≈ 21.7%。
    旧行为：``run()`` 只判 ``strip() == ""``，非截断的引子答复原样直通
    （旧判别测试 ``TestShortAnswerNoGate`` 曾把该行为钉为"缺口成立"的证据，
    修复后该断言已按新契约改写，见本文件 ``TestIntroAnswerGate``）。

修复后契约（``src/winreverse/soul/agent.py``）：
    最终答复非空但「长度 < ``min_answer_chars`` 且无代码块/列表/结论标记」→
    触发**一次**不帶工具的续写（``_SHORT_ANSWER_PROMPT``）；
    续写为空 → 交给既有空答复兜底（``_SUMMARY_PROMPT``）；再空 → 抛
    ``EmptyFinalAnswerError``（不许静默交空/交引子）。
"""

from __future__ import annotations

from typing import Any

import pytest

from kosong.types import GenerateResult, Message, MessageRole, Tool, Usage
from winreverse.soul.agent import (
    _CONTINUE_PROMPT,
    _SHORT_ANSWER_PROMPT,
    _SUMMARY_PROMPT,
    Agent,
    AgentConfig,
    EmptyFinalAnswerError,
    Runtime,
)

# 实测「引子式答复」同族文本：只有开场句与计划，无结论/证据/列表/代码块
INTRO_ANSWER = (
    "好的，我先来分析一下这个样本。接下来我会先读取文件的基本信息，"
    "再进一步查看字符串与导入表，最后结合实际行为给出判断，请稍等。"
)

# 同族引子（第二轮仍给引子，用于验证"只重试一次、不循环"）
INTRO_ANSWER_2 = "收到，我这就继续深入分析这个样本，稍后把整理结果发给你。"

# 实质答复（含结论标记 → 判据命中，无需长度达标）
SUBSTANTIVE_ANSWER = (
    "结论：样本无恶意行为。\n"
    "- 证据：导入表仅 kernel32.dll 的 CreateFile/ReadFile\n"
    "- 未取得数据：上游 C2 域名未在本次会话中出现"
)

# 实质答复（长文本、无任何结构标记 → 命中长度判据）
LONG_ANSWER = (
    "本次分析覆盖了 PE 头、节区熵、导入表与字符串四个维度。"
    "节区熵最高 6.12（.text），未见加壳特征；导入表共 42 项，"
    "集中在文件与网络 API；字符串中匹配到 3 条 URL 与 2 条注册表路径，"
    "均已作为 IOC 归档。综合判断该样本为无害的压缩工具，建议纳入白名单，"
    "后续如需进一步确认可补充内存扫描与网络行为监控两个维度的数据。"
)


class _ScriptedLLM:
    """按脚本顺序返回结果的 LLM 桩；记录每次调用的完整消息历史。"""

    def __init__(self, responses: list[GenerateResult]) -> None:
        self._responses = list(responses)
        self.calls: list[list[Message]] = []

    async def generate(
        self,
        messages: list[Message],
        model: str | None = None,
        tools: list[Tool] | None = None,
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


def _agent(llm: Any, **cfg: Any) -> Agent:
    """构造 Agent（本文件专测短答闸门 → 未显式指定时打开闸门）。"""
    cfg.setdefault("short_answer_gate", True)
    config = AgentConfig(name="t", system_prompt="sys", **cfg)
    return Agent(config, Runtime(llm=llm))


class TestIntroAnswerGate:
    """引子答：非截断但无实质内容 → 触发一次续写。"""

    async def test_intro_answer_is_retried_once(self) -> None:
        """引子（140+ 字符、无结构）→ 补一次续写，返回续写得到的实质答复。"""
        llm = _ScriptedLLM(
            [_result(INTRO_ANSWER, stop_reason="end_turn"), _result(SUBSTANTIVE_ANSWER)]
        )
        agent = _agent(llm)

        answer = await agent.run("分析")

        assert answer == SUBSTANTIVE_ANSWER, "引子答必须被续写替换为实质答复"
        assert len(llm.calls) == 2, "引子答应恰好触发一次续写调用"
        assert agent.short_answer_retry_used is True
        last = llm.calls[1][-1]
        assert last.role == MessageRole.USER
        assert _SHORT_ANSWER_PROMPT[:12] in str(last.content), "续写调用应携带短答闸门提示词"

    async def test_intro_retry_happens_only_once(self) -> None:
        """续写仍是引子 → 不再循环重试，取较长的一条（避免比原答复更短）。"""
        llm = _ScriptedLLM([_result(INTRO_ANSWER), _result(INTRO_ANSWER_2)])
        agent = _agent(llm)

        answer = await agent.run("分析")

        assert len(llm.calls) == 2, "只允许一次短答续写（不循环烧预算）"
        assert answer == INTRO_ANSWER, "两条都是引子时保留更长的一条"
        assert agent.short_answer_retry_used is True

    async def test_intro_retry_empty_falls_back_to_summary(self) -> None:
        """续写取不到文本 → 走既有空答复兜底（_SUMMARY_PROMPT 调用）。"""
        llm = _ScriptedLLM([_result(INTRO_ANSWER), _result(""), _result(SUBSTANTIVE_ANSWER)])
        agent = _agent(llm)

        answer = await agent.run("分析")

        assert answer == SUBSTANTIVE_ANSWER
        assert len(llm.calls) == 3, "1 主调用 + 1 短答续写 + 1 空答复兜底"
        assert _SUMMARY_PROMPT[:12] in str(llm.calls[2][-1].content)
        assert agent.short_answer_retry_used is True
        assert agent.answer_fallback_used is True

    async def test_intro_retry_and_summary_both_empty_raise(self) -> None:
        """续写与兜底都取不到文本 → 抛 EmptyFinalAnswerError（不静默交引子）。"""
        llm = _ScriptedLLM([_result(INTRO_ANSWER), _result(""), _result("")])

        with pytest.raises(EmptyFinalAnswerError):
            await _agent(llm).run("分析")

    async def test_gate_disabled_lets_intro_through(self) -> None:
        """short_answer_gate=False → 保留旧行为（原样直通、仅 1 次调用）。"""
        llm = _ScriptedLLM([_result(INTRO_ANSWER)])

        answer = await _agent(llm, short_answer_gate=False).run("分析")

        assert answer == INTRO_ANSWER
        assert len(llm.calls) == 1


class TestSubstantiveAnswerPasses:
    """正常答：长度达标或有结构 → 不触发闸门（零额外调用）。"""

    async def test_long_answer_passes_through(self) -> None:
        llm = _ScriptedLLM([_result(LONG_ANSWER)])
        agent = _agent(llm)

        answer = await agent.run("分析")

        assert answer == LONG_ANSWER
        assert len(llm.calls) == 1, "实质答复不得触发任何额外调用"
        assert agent.short_answer_retry_used is False

    async def test_structured_short_answer_passes_through(self) -> None:
        """短但有结论/列表结构 → 视为实质，零额外调用。"""
        llm = _ScriptedLLM([_result(SUBSTANTIVE_ANSWER)])
        agent = _agent(llm)

        answer = await agent.run("分析")

        assert answer == SUBSTANTIVE_ANSWER
        assert len(llm.calls) == 1

    async def test_code_block_short_answer_passes_through(self) -> None:
        llm = _ScriptedLLM([_result("```\nimphash=1f2e3d4c\n```")])

        answer = await _agent(llm).run("分析")

        assert answer == "```\nimphash=1f2e3d4c\n```"
        assert len(llm.calls) == 1

    async def test_min_answer_chars_boundary(self) -> None:
        """长度判据按 min_answer_chars 生效：恰好达标放行，不足则触发续写。"""
        border = "x" * 60
        llm_ok = _ScriptedLLM([_result(border)])
        assert await _agent(llm_ok, min_answer_chars=60).run("分析") == border
        assert len(llm_ok.calls) == 1

        llm_short = _ScriptedLLM([_result("y" * 59), _result(SUBSTANTIVE_ANSWER)])
        assert await _agent(llm_short, min_answer_chars=60).run("分析") == SUBSTANTIVE_ANSWER
        assert len(llm_short.calls) == 2

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("", False),
            ("   ", False),
            ("好的，已完成。", False),
            ("结论：无恶意行为", True),
            ("不确定：缺少网络维度数据", True),
            ("- 第一项证据", True),
            ("1. 第一项证据", True),
            ("2) 第二项证据", True),
            ("sha256=deadbeef", True),
            ("```\ncode\n```", True),
            ("x" * 300, True),
            ("x" * 299, False),
        ],
    )
    def test_substantive_judgement_matrix(self, text: str, expected: bool) -> None:
        """判据矩阵：空白/短句 → 假；代码块/列表/结论标记/长度达标 → 真。"""
        agent = _agent(_ScriptedLLM([]))

        assert agent._is_substantive_answer(text) is expected

    def test_library_default_is_off(self) -> None:
        """库级默认关闭闸门（默认关闭=不额外消耗 LLM 调用）；应用层显式打开。"""
        config = AgentConfig(name="t", system_prompt="sys")

        assert config.short_answer_gate is False
        assert config.min_answer_chars == 300


class TestTextOfAndContinuationFailure:
    """`_text_of` 空值容错 与 续写调用失败兜底（不静默丢答复）。"""

    def test_text_of_none_and_empty_content(self) -> None:
        """None / 空串 / 空 list 内容 → 一律返回空串（供上层跳过）。"""
        assert Agent._text_of(None) == ""
        assert Agent._text_of(Message(role=MessageRole.ASSISTANT, content="")) == ""

    async def test_short_answer_continuation_call_failure_keeps_original(self) -> None:
        """续写调用抛异常 → 保留原答复（不因一次调用失败而丢内容/静默）。"""

        class _BoomLLM:
            def __init__(self) -> None:
                self.calls = 0

            async def generate(
                self, messages: list[Message], model: str | None = None, tools: Any = None
            ) -> GenerateResult:
                self.calls += 1
                if self.calls > 1:
                    raise RuntimeError("upstream 502")
                return _result(INTRO_ANSWER)

        llm = _BoomLLM()
        agent = _agent(llm)  # type: ignore[arg-type]

        answer = await agent.run("分析")

        assert answer == INTRO_ANSWER, "续写失败必须保留原答复"
        assert agent.short_answer_retry_used is True


class TestEmptyAnswerPath:
    """空答：仍走既有 P0-3② 兜底路径（不被短答闸门截走）。"""

    async def test_empty_answer_uses_summary_fallback(self) -> None:
        llm = _ScriptedLLM([_result(""), _result(SUBSTANTIVE_ANSWER)])
        agent = _agent(llm)

        answer = await agent.run("分析")

        assert answer == SUBSTANTIVE_ANSWER
        assert len(llm.calls) == 2, "空答复只走兜底一次（不叠加短答续写）"
        assert agent.short_answer_retry_used is False
        assert agent.answer_fallback_used is True
        assert _SUMMARY_PROMPT[:12] in str(llm.calls[1][-1].content)

    async def test_empty_and_empty_raises(self) -> None:
        llm = _ScriptedLLM([_result(""), _result("")])

        with pytest.raises(EmptyFinalAnswerError):
            await _agent(llm).run("分析")

    async def test_max_tokens_continuation_still_precedes_gate(self) -> None:
        """max_tokens 截断 → 先走 P0-3① 续写；续写出实质内容后不再触发短答闸门。"""
        llm = _ScriptedLLM(
            [
                _result("结论：", stop_reason="max_tokens"),
                _result(SUBSTANTIVE_ANSWER, stop_reason="stop"),
            ]
        )
        agent = _agent(llm)

        answer = await agent.run("分析")

        assert answer == f"结论：{SUBSTANTIVE_ANSWER}"
        assert len(llm.calls) == 2
        assert _CONTINUE_PROMPT[:12] in str(llm.calls[1][-1].content)
        assert agent.short_answer_retry_used is False
