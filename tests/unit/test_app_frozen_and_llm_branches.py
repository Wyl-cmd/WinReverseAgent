"""被测模块: winreverse.app（PyInstaller frozen 回退分支 / .yml 扩展名加载 / llm=None 适配器构造分支）。

覆盖点: 打包运行（sys.frozen）时 cwd 无 skills/ 回退 exe 目录加载；skills 目录仅含
.yml 文件也能注册；llm 未注入时 _ensure_initialized 从 config 构造 LLMAdapter 并挂到
_llm_instance。Skill 加载与 Soul 构造走真实实现，LLMAdapter 用记录型替身隔离（与
_FakeLLM 同为依赖注入口径）。
winreverse.app 导入链缺 yara 等 Windows 运行时依赖 → Linux 下如实报 collection error
（基线接受态），待 Windows 实机（依赖就位）实跑回填。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import winreverse.llm_runtime as llm_runtime
from winreverse.app import Agent
from winreverse.config import AgentConfig as NewAgentConfig
from winreverse.config import AppConfig, LLMConfig


def _make_config(work_dir: str | Path) -> AppConfig:
    return AppConfig(
        llm=LLMConfig(model="unit-model", api_key="unit-key"),
        agent=NewAgentConfig(work_dir=str(work_dir)),
    )


class TestFrozenSkillsFallback:
    """PyInstaller 打包运行：cwd 下无 skills/ 时回退 exe 同级目录（随包分发）。"""

    def test_frozen_falls_back_to_executable_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_exe_dir = tmp_path / "dist"
        fake_exe_dir.mkdir()
        (fake_exe_dir / "skills").mkdir()
        (fake_exe_dir / "skills" / "bundled.yaml").write_text(
            'name: frozen_probe\ndescription: "打包回退探针"\n',
            encoding="utf-8",
        )
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "executable", str(fake_exe_dir / "winreverse.exe"))
        # work_dir 下无 skills/ → 触发回退
        agent = Agent(app_config=_make_config(tmp_path), llm=object())
        agent._ensure_initialized()
        names = {s["name"] for s in agent._skill_registry.list_skills()}
        assert "frozen_probe" in names

    def test_frozen_but_cwd_skills_exist_no_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """cwd 已有 skills/ 时优先 cwd，不读 exe 目录（两处同名 Skill 不串扰）。"""
        (tmp_path / "skills").mkdir()
        (tmp_path / "skills" / "cwd.yaml").write_text(
            'name: cwd_probe\ndescription: "cwd 优先探针"\n',
            encoding="utf-8",
        )
        fake_exe_dir = tmp_path / "dist"
        fake_exe_dir.mkdir()
        (fake_exe_dir / "skills").mkdir()
        (fake_exe_dir / "skills" / "exe.yaml").write_text(
            'name: exe_probe\ndescription: "不应被加载"\n',
            encoding="utf-8",
        )
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "executable", str(fake_exe_dir / "winreverse.exe"))
        agent = Agent(app_config=_make_config(tmp_path), llm=object())
        agent._ensure_initialized()
        names = {s["name"] for s in agent._skill_registry.list_skills()}
        assert "cwd_probe" in names
        assert "exe_probe" not in names


class TestYmlExtensionLoading:
    """skills 目录仅含 .yml（非 .yaml）文件时同样加载。"""

    def test_yml_files_are_registered(self, tmp_path: Path) -> None:
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        (skills_dir / "probe.yml").write_text(
            'name: yml_probe\ndescription: "yml 扩展名探针"\n',
            encoding="utf-8",
        )
        agent = Agent(app_config=_make_config(tmp_path), llm=object())
        agent._ensure_initialized()
        names = {s["name"] for s in agent._skill_registry.list_skills()}
        assert "yml_probe" in names


class TestLlmAdapterConstructionBranch:
    """llm 未注入：_ensure_initialized 必须用生效 config 的 llm 构造 LLMAdapter。"""

    def test_adapter_constructed_from_effective_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        constructed: list[object] = []
        seen_configs: list[object] = []

        class _RecordingAdapter:
            def __init__(self, config: object) -> None:
                self.config = config
                constructed.append(self)
                seen_configs.append(config)

        monkeypatch.setattr(llm_runtime, "LLMAdapter", _RecordingAdapter)
        config = _make_config(tmp_path)
        agent = Agent(app_config=config)  # llm 缺省 None → 走构造分支
        agent._ensure_initialized()
        assert len(constructed) == 1
        assert seen_configs[0] is config.llm
        assert agent._llm_instance is constructed[0]
