"""被测模块: winreverse.app Agent 的 run_repl / run / run_from_config / shutdown 边界。

覆盖点: REPL 的 EOF/退出词/空行/正常回复/异常继续 五分支、M1 兼容 run() 与
run_from_config()、AgentConfig.to_app_config 字段透传、shutdown 对 LLM close 异常
的吞并。Soul 以假对象注入并短路 _ensure_initialized，不触真实工具链。
winreverse.app 导入链缺 yara 等 Windows 运行时依赖 → Linux 下如实报 collection
error（基线接受态），待 Windows 实机（依赖就位）实跑回填。
"""

from __future__ import annotations

from typing import Any

import pytest

from winreverse.app import Agent, AgentConfig, run_from_config


class _FakeSoul:
    """假 Soul：记录输入，可配置抛错。"""

    def __init__(self, reply: str = "fake_reply", fail: bool = False) -> None:
        self.calls: list[str] = []
        self._reply = reply
        self._fail = fail

    async def run(self, text: str) -> str:
        self.calls.append(text)
        if self._fail:
            raise RuntimeError("boom")
        return self._reply


def _make_agent(monkeypatch: pytest.MonkeyPatch, soul: _FakeSoul) -> Any:
    agent = Agent(config=AgentConfig())
    monkeypatch.setattr(Agent, "_ensure_initialized", lambda self: None)
    agent._soul = soul
    return agent


def _feed_input(monkeypatch: pytest.MonkeyPatch, lines: list[str]) -> None:
    iterator = iter(lines)

    def _fake_input(prompt: str = "") -> str:
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError from None

    monkeypatch.setattr("builtins.input", _fake_input)


class TestRunRepl:
    """REPL 主循环分支。"""

    def test_eof_exits_without_touching_soul(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        soul = _FakeSoul()
        agent = _make_agent(monkeypatch, soul)
        _feed_input(monkeypatch, [])

        assert agent.run_repl() == 0
        assert soul.calls == []
        assert "再见" in capsys.readouterr().out

    @pytest.mark.parametrize("exit_word", ["exit", "quit", "q"])
    def test_exit_words_stop_loop(
        self,
        exit_word: str,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        soul = _FakeSoul()
        agent = _make_agent(monkeypatch, soul)
        # 空行 / 纯空白必须被跳过，不进入 soul
        _feed_input(monkeypatch, ["", "   ", exit_word])

        assert agent.run_repl() == 0
        assert soul.calls == []
        out = capsys.readouterr().out
        assert out.count("再见") == 1

    def test_normal_turn_prints_answer(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        soul = _FakeSoul(reply="分析结论 X")
        agent = _make_agent(monkeypatch, soul)
        _feed_input(monkeypatch, ["analyze this", "q"])

        assert agent.run_repl() == 0
        assert soul.calls == ["analyze this"]
        assert "分析结论 X" in capsys.readouterr().out

    def test_soul_failure_prints_error_and_loop_continues(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        soul = _FakeSoul(fail=True)
        agent = _make_agent(monkeypatch, soul)
        _feed_input(monkeypatch, ["first", "q"])

        assert agent.run_repl() == 0
        out = capsys.readouterr().out
        assert "[错误]" in out
        assert "boom" in out
        assert soul.calls == ["first"], "异常后循环必须继续直到退出词"


class TestM1CompatEntries:
    """M1 兼容入口（不触发初始化链）。"""

    def test_run_prints_version_banner(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        agent = Agent(config=AgentConfig())
        assert agent.run() == 0
        out = capsys.readouterr().out
        assert "WinReverseAgent v" in out

    def test_run_from_config_returns_zero(self, tmp_path: Any) -> None:
        assert run_from_config({"work_dir": str(tmp_path), "yolo": True}) == 0

    def test_agent_config_to_app_config_roundtrip(self) -> None:
        cfg = AgentConfig(
            model="test-model",
            api_key="sk-test",
            work_dir="C:\\w",
            yolo=True,
            max_turns=7,
        )
        app_cfg = cfg.to_app_config()
        assert app_cfg.llm.model == "test-model"
        assert app_cfg.llm.api_key == "sk-test"
        assert app_cfg.agent.work_dir == "C:\\w"
        assert app_cfg.agent.yolo is True
        assert app_cfg.agent.max_turns == 7


class TestShutdownEdges:
    """shutdown 对 LLM close 异常的吞并。"""

    def test_shutdown_swallows_llm_close_failure(self) -> None:
        agent = Agent(config=AgentConfig())

        class _BadLLM:
            async def close(self) -> None:
                raise RuntimeError("close boom")

        agent._initialized = True
        agent._llm_instance = _BadLLM()
        agent.shutdown()
        assert agent._initialized is False

    def test_shutdown_without_close_method_is_noop(self) -> None:
        agent = Agent(config=AgentConfig())
        agent._initialized = True
        agent._llm_instance = object()  # 无 close 属性
        agent.shutdown()
        assert agent._initialized is False
