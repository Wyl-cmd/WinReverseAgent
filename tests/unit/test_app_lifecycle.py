"""测试模块：winreverse.app 惰性初始化与执行生命周期。

覆盖：AgentConfig.to_app_config 映射、_ensure_initialized 建链（工具 registry /
Skill 加载含坏 YAML 容错 / executor / soul）、run_skill_sync 委托、run_repl 输入
循环（正常对话 / exit / EOF / 执行异常容错）、shutdown 关闭 LLM 与幂等。
本工具为 Windows 专用：Linux 缺 yara/pymem 等专有依赖时整组跳过（真机流水线执行）。
"""

from __future__ import annotations

import builtins
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

# Windows 专有导入链（engine.tools → yara/pymem），Linux 无依赖时跳过整组
app_module = pytest.importorskip(
    "winreverse.app", reason="winreverse.app 导入链缺 Windows 专有依赖（yara 等）"
)
from winreverse.config import AgentConfig as NewAgentConfig  # noqa: E402
from winreverse.config import AppConfig, LLMConfig  # noqa: E402


def _make_agent(tmp_path: Path, skills_yaml: str | None = None, **agent_kwargs) -> app_module.Agent:
    """构造注入 mock LLM、work_dir 指向 tmp 的真实 Agent。"""
    agent_cfg = NewAgentConfig(work_dir=str(tmp_path), skills_dir="skills", **agent_kwargs)
    app_config = AppConfig(llm=LLMConfig(model="m", api_key="k"), agent=agent_cfg)
    agent = app_module.Agent(app_config=app_config, llm=MagicMock())
    if skills_yaml is not None:
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir(parents=True, exist_ok=True)
        (skills_dir / "s.yaml").write_text(skills_yaml, encoding="utf-8")
    return agent


_VALID_YAML = (
    'name: "生命周期测试"\ndescription: "app 惰性初始化回归"\n'
    'target: "测试"\nprompt_template: |\n  模板\n'
)
_BROKEN_YAML = ":\n  - [未闭合"


class TestToAppConfig:
    """M1 兼容 AgentConfig → 新 AppConfig 的字段映射。"""

    def test_mapping(self) -> None:
        old = app_module.AgentConfig(
            model="glm-4", api_key="sk-1", work_dir="/tmp/w", yolo=True, max_turns=7
        )
        new = old.to_app_config()
        assert new.llm.model == "glm-4"
        assert new.llm.api_key == "sk-1"
        assert new.agent.work_dir == "/tmp/w"
        assert new.agent.yolo is True
        assert new.agent.max_turns == 7


class TestEnsureInitialized:
    """惰性初始化：首次调用建链，重复调用幂等。"""

    def test_builds_chain_and_is_idempotent(self, tmp_path: Path) -> None:
        agent = _make_agent(tmp_path, skills_yaml=_VALID_YAML)
        assert agent._initialized is False

        agent._ensure_initialized()
        assert agent._initialized is True
        assert agent._registry is not None
        assert len(agent._registry) > 0  # 静态分析工具已注册
        assert agent._executor is not None
        assert agent._soul is not None
        names = [s["name"] for s in agent._skill_registry.list_skills()]
        assert "生命周期测试" in names

        # 幂等：再次调用不重建（registry 引用不变）
        registry_before = agent._registry
        agent._ensure_initialized()
        assert agent._registry is registry_before

    def test_broken_yaml_does_not_crash_init(self, tmp_path: Path) -> None:
        """坏 YAML 只告警不中断，初始化仍完成。"""
        agent = _make_agent(tmp_path, skills_yaml=_BROKEN_YAML)
        agent._ensure_initialized()
        assert agent._initialized is True
        assert agent._skill_registry is not None

    def test_missing_skills_dir_is_fine(self, tmp_path: Path) -> None:
        agent = _make_agent(tmp_path, skills_yaml=None)
        agent._ensure_initialized()
        assert agent._skill_registry.list_skills() == []


class TestRunSkillSync:
    """run_skill_sync 委托 executor.run 并透传参数。"""

    def test_delegates_to_executor(self, tmp_path: Path) -> None:
        agent = _make_agent(tmp_path, skills_yaml=_VALID_YAML)
        sentinel = object()
        captured: dict[str, object] = {}

        async def fake_run(skill_name: str, parameters: dict) -> object:
            captured["name"] = skill_name
            captured["params"] = parameters
            return sentinel

        agent._ensure_initialized()
        agent._executor = SimpleNamespace(run=fake_run)

        result = agent.run_skill_sync("生命周期测试", {"file_path": "a.exe"})
        assert result is sentinel
        assert captured == {"name": "生命周期测试", "params": {"file_path": "a.exe"}}

    def test_none_parameters_become_empty_dict(self, tmp_path: Path) -> None:
        agent = _make_agent(tmp_path, skills_yaml=_VALID_YAML)

        async def fake_run(skill_name: str, parameters: dict) -> dict:
            return parameters

        agent._ensure_initialized()
        agent._executor = SimpleNamespace(run=fake_run)
        assert agent.run_skill_sync("生命周期测试") == {}


class TestRunRepl:
    """REPL 循环：正常对话、exit/EOF 退出、执行异常容错。"""

    def test_conversation_then_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        agent = _make_agent(tmp_path)
        inputs = iter(["分析 notepad.exe", "exit"])

        async def fake_run(msg: str) -> str:
            return "分析结果 A"

        agent._ensure_initialized()
        agent._soul = SimpleNamespace(run=fake_run)
        monkeypatch.setattr(builtins, "input", lambda _prompt="": next(inputs))

        assert agent.run_repl() == 0
        out = capsys.readouterr().out
        assert "WinReverseAgent" in out
        assert "分析结果 A" in out
        assert "再见" in out

    def test_eof_exits(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        agent = _make_agent(tmp_path)

        def fake_input(_prompt: str = "") -> str:
            raise EOFError

        agent._ensure_initialized()

        # 修复(2026-09-12)：原写法 `run=asyncio.sleep(0)` 把协程对象（而非协程函数）挂到
        # soul.run 上 —— 该协程永不被 await，Python 3.12 + filterwarnings=error 下 GC 时
        # 的 RuntimeWarning 直接判失败。改为真正的 async 替身，并使"EOF 后不应再执行一轮"
        # 成为显式断言（比原意图更强）。
        async def _should_not_run(_msg: str) -> str:
            raise AssertionError("EOF 退出路径不应再执行 soul.run")

        agent._soul = SimpleNamespace(run=_should_not_run)
        monkeypatch.setattr(builtins, "input", fake_input)

        assert agent.run_repl() == 0
        assert "再见" in capsys.readouterr().out

    def test_execution_error_printed_not_raised(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """单轮执行异常只打印错误继续循环，不中断 REPL。"""
        agent = _make_agent(tmp_path)
        inputs = iter(["触发异常", "q"])

        def fake_input(_prompt: str = "") -> str:
            return next(inputs)

        async def fake_run(msg: str) -> str:
            raise RuntimeError("LLM 爆炸")

        agent._ensure_initialized()
        agent._soul = SimpleNamespace(run=fake_run)
        monkeypatch.setattr(builtins, "input", fake_input)

        assert agent.run_repl() == 0
        out = capsys.readouterr().out
        assert "Agent 执行失败" in out and "LLM 爆炸" in out
        assert "再见" in out  # q 正常退出


class TestShutdown:
    """shutdown：调用 LLM.close 且幂等，未初始化时不抛错。"""

    def test_shutdown_closes_llm(self, tmp_path: Path) -> None:
        llm = MagicMock()

        async def close() -> None:
            return None

        llm.close = MagicMock(side_effect=lambda: close())
        agent = _make_agent(tmp_path)
        agent._ensure_initialized()
        agent._llm_instance = llm

        agent.shutdown()
        assert agent._initialized is False
        llm.close.assert_called_once()

        # 幂等：重复 shutdown 不再触发 close
        agent.shutdown()
        assert llm.close.call_count == 1

    def test_shutdown_before_init_is_noop(self, tmp_path: Path) -> None:
        agent = _make_agent(tmp_path)
        agent.shutdown()
        assert agent._initialized is False
