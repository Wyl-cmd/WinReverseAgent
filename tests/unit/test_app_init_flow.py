"""被测模块: winreverse.app（Agent 惰性初始化流 / work_dir 覆盖 / shutdown）。

覆盖点: create_agent_from_config 后 _skill_registry 为 None 的惰性不变量（list-skills
崩溃缺陷的单元级回归）、_ensure_initialized 全链路（工具注册 + Skill 加载 + 坏 YAML
容错）、work_dir 覆盖分支、幂等初始化、shutdown 关闭注入 LLM。
winreverse.app 导入链缺 yara 等 Windows 运行时依赖 → Linux 下如实报 collection error
（基线接受态），待 Windows 实机（依赖就位）实跑回填。
"""

from __future__ import annotations

from pathlib import Path

from winreverse.app import Agent, create_agent_from_config
from winreverse.config import AgentConfig as NewAgentConfig
from winreverse.config import AppConfig, LLMConfig


def _make_config(work_dir: str | Path) -> AppConfig:
    return AppConfig(
        llm=LLMConfig(model="unit-model", api_key="unit-key"),
        agent=NewAgentConfig(work_dir=str(work_dir)),
    )


class _FakeLLM:
    """记录 close() 调用次数的最小 LLM 替身（走 Agent 注入接缝，不触网）。"""

    def __init__(self) -> None:
        self.close_calls = 0

    async def close(self) -> None:
        self.close_calls += 1


class TestLazyInitInvariant:
    """list-skills 'NoneType' object has no attribute list_skills 缺陷回归。"""

    def test_registry_is_none_until_ensure_initialized(self, tmp_path: Path) -> None:
        """构造后 registry 必须为 None，_ensure_initialized 后可用且可 list_skills。"""
        agent = create_agent_from_config(_make_config(tmp_path))
        assert agent._skill_registry is None  # 惰性不变量：漏调初始化即 NoneType 崩溃
        agent._ensure_initialized()
        assert agent._skill_registry is not None
        skills = agent._skill_registry.list_skills()
        assert isinstance(skills, list)

    def test_ensure_initialized_is_idempotent(self, tmp_path: Path) -> None:
        """二次调用不得重建 registry（否则已注册 Skill/工具状态被静默清空）。"""
        agent = Agent(app_config=_make_config(tmp_path), llm=object())
        agent._ensure_initialized()
        first = agent._skill_registry
        agent._ensure_initialized()
        assert agent._skill_registry is first
        assert agent._initialized is True


class TestInitFlow:
    """_ensure_initialized 全链路真实行为。"""

    def test_loads_valid_skill_and_tolerates_broken_yaml(self, tmp_path: Path) -> None:
        """有效 YAML 注册成功；坏 YAML 只告警不中断初始化。"""
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        (skills_dir / "probe.yaml").write_text(
            'name: unit_probe_skill\ndescription: "初始化流程探针"\n',
            encoding="utf-8",
        )
        (skills_dir / "broken.yaml").write_text(
            'description: "缺少 name 字段"\n',
            encoding="utf-8",
        )
        agent = Agent(app_config=_make_config(tmp_path), llm=object())
        agent._ensure_initialized()
        names = {s["name"] for s in agent._skill_registry.list_skills()}
        assert "unit_probe_skill" in names
        assert all("broken" not in n for n in names)

    def test_work_dir_override_keeps_skills_dir(self, tmp_path: Path) -> None:
        """Agent(work_dir=...) 覆盖分支须保留配置中的 skills_dir。"""
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        (skills_dir / "probe.yaml").write_text(
            'name: override_probe\ndescription: "work_dir 覆盖探针"\n',
            encoding="utf-8",
        )
        config_with_other_workdir = _make_config(tmp_path / "somewhere-else")
        agent = Agent(app_config=config_with_other_workdir, work_dir=str(tmp_path))
        agent._ensure_initialized()
        names = {s["name"] for s in agent._skill_registry.list_skills()}
        assert "override_probe" in names


class TestShutdown:
    """shutdown() 资源清理。"""

    def test_shutdown_closes_injected_llm(self, tmp_path: Path) -> None:
        llm = _FakeLLM()
        agent = Agent(app_config=_make_config(tmp_path), llm=llm)
        agent._ensure_initialized()
        agent.shutdown()
        assert llm.close_calls == 1
        assert agent._initialized is False

    def test_shutdown_on_fresh_agent_is_noop(self, tmp_path: Path) -> None:
        """未初始化的 Agent shutdown 不得触发 close（_llm_instance 尚不存在）。"""
        llm = _FakeLLM()
        agent = Agent(app_config=_make_config(tmp_path), llm=llm)
        agent.shutdown()
        assert llm.close_calls == 0
