"""测试模块：winreverse.skill.loader

测试 Skill 数据模型、SkillLoader Protocol 契约、SkillRegistry 注册中心。
覆盖：
- Skill 数据类的参数校验与 Prompt 渲染
- SkillParameter 默认值
- SkillRegistry 注册/查询/注销
- SkillNotFoundError 异常
"""

from __future__ import annotations

from pathlib import Path

import pytest

from winreverse.skill.loader import (
    Skill,
    SkillLoader,
    SkillNotFoundError,
    SkillParameter,
    SkillRegistry,
)

# =============================================================================
# SkillParameter 测试
# =============================================================================


class TestSkillParameter:
    """SkillParameter 数据类测试"""

    def test_default_values(self) -> None:
        """默认值：type=string, default=None, description='', required=False。"""
        param = SkillParameter(name="test")
        assert param.name == "test"
        assert param.type == "string"
        assert param.default is None
        assert param.description == ""
        assert param.required is False

    def test_full_parameter(self) -> None:
        """完整参数构造。"""
        param = SkillParameter(
            name="process_name",
            type="string",
            default="game.exe",
            description="目标进程名",
            required=True,
        )
        assert param.name == "process_name"
        assert param.type == "string"
        assert param.default == "game.exe"
        assert param.description == "目标进程名"
        assert param.required is True


# =============================================================================
# Skill 数据模型测试
# =============================================================================


class TestSkillModel:
    """Skill 数据模型测试"""

    def test_minimal_skill(self) -> None:
        """最小 Skill 构造（仅 name + description）。"""
        skill = Skill(name="test", description="测试技能")
        assert skill.name == "test"
        assert skill.description == "测试技能"
        assert skill.target == "通用"
        assert skill.parameters == []
        assert skill.prompt_template == ""
        assert skill.execution_flow == []
        assert skill.source_path is None

    def test_render_prompt_replaces_variables(self) -> None:
        """render_prompt 应替换 {{var}} 占位符。"""
        skill = Skill(
            name="test",
            description="测试",
            prompt_template="附加进程 {{process_name}}，超时 {{timeout}}秒",
        )
        result = skill.render_prompt({"process_name": "game.exe", "timeout": 30})
        assert result == "附加进程 game.exe，超时 30秒"

    def test_render_prompt_with_missing_variable(self) -> None:
        """render_prompt 对未提供的变量保持原占位符。"""
        skill = Skill(
            name="test",
            description="测试",
            prompt_template="附加 {{process_name}}，超时 {{timeout}}",
        )
        result = skill.render_prompt({"process_name": "game.exe"})
        # timeout 未提供，占位符保持
        assert "{{timeout}}" in result
        assert "game.exe" in result

    def test_validate_parameters_required_missing(self) -> None:
        """必填参数缺失应返回错误。"""
        skill = Skill(
            name="test",
            description="测试",
            parameters=[
                SkillParameter(name="process_name", required=True),
                SkillParameter(name="timeout", required=False),
            ],
        )
        errors = skill.validate_parameters({})
        assert len(errors) == 1
        assert "process_name" in errors[0]

    def test_validate_parameters_all_provided(self) -> None:
        """所有必填参数已提供应无错误。"""
        skill = Skill(
            name="test",
            description="测试",
            parameters=[
                SkillParameter(name="process_name", required=True),
                SkillParameter(name="timeout", required=True),
            ],
        )
        errors = skill.validate_parameters({"process_name": "game.exe", "timeout": 30})
        assert errors == []


# =============================================================================
# SkillRegistry 测试
# =============================================================================


class TestSkillRegistry:
    """SkillRegistry 注册中心测试"""

    def test_register_single_skill(self, skill_registry: SkillRegistry) -> None:
        """注册单个 Skill 应成功。"""
        skill = Skill(name="memory_scan", description="内存扫描")
        skill_registry.register(skill)
        assert len(skill_registry) == 1
        assert "memory_scan" in skill_registry

    def test_register_duplicate_raises(self, skill_registry: SkillRegistry) -> None:
        """重复注册同名 Skill 应抛出 ValueError。"""
        skill_registry.register(Skill(name="memory_scan", description="内存扫描"))
        with pytest.raises(ValueError, match="Skill 已注册"):
            skill_registry.register(Skill(name="memory_scan", description="另一个"))

    def test_get_existing_skill(self, skill_registry: SkillRegistry) -> None:
        """获取已注册的 Skill 应返回实例。"""
        skill = Skill(name="memory_scan", description="内存扫描")
        skill_registry.register(skill)
        result = skill_registry.get("memory_scan")
        assert result is skill

    def test_get_nonexistent_raises(self, skill_registry: SkillRegistry) -> None:
        """获取未注册的 Skill 应抛出 SkillNotFoundError。"""
        with pytest.raises(SkillNotFoundError, match="nonexistent"):
            skill_registry.get("nonexistent")

    def test_list_skills(self, skill_registry: SkillRegistry) -> None:
        """list_skills 应返回所有 Skill 的 name 与 description。"""
        skill_registry.register(Skill(name="memory_scan", description="内存扫描"))
        skill_registry.register(Skill(name="pe_analyzer", description="PE 分析"))
        skills = skill_registry.list_skills()
        assert len(skills) == 2
        names = [s["name"] for s in skills]
        assert "memory_scan" in names
        assert "pe_analyzer" in names

    def test_clear_all(self, skill_registry: SkillRegistry) -> None:
        """clear 应清空所有 Skill。"""
        skill_registry.register(Skill(name="a", description=""))
        skill_registry.register(Skill(name="b", description=""))
        skill_registry.clear()
        assert len(skill_registry) == 0


# =============================================================================
# SkillLoader Protocol 契约测试
# =============================================================================


class TestSkillLoaderContract:
    """SkillLoader Protocol 契约测试"""

    def test_protocol_exists(self) -> None:
        """SkillLoader Protocol 已定义。"""
        assert SkillLoader is not None

    def test_protocol_has_load_and_supports(self) -> None:
        """SkillLoader 必须包含 load 与 supports 方法。"""
        assert hasattr(SkillLoader, "load")
        assert hasattr(SkillLoader, "supports")

    def test_minimal_implementation_satisfies_protocol(
        self, tmp_path: Path, sample_skill_yaml: str
    ) -> None:
        """最小实现应满足 SkillLoader 契约。"""

        class _MinLoader:
            def load(self, path: Path) -> Skill:
                return Skill(name="test", description="from loader")

            def supports(self, path: Path) -> bool:
                return path.suffix == ".yaml"

        loader = _MinLoader()
        test_file = tmp_path / "test.yaml"
        test_file.write_text(sample_skill_yaml, encoding="utf-8")

        assert loader.supports(test_file) is True
        skill = loader.load(test_file)
        assert isinstance(skill, Skill)
        assert skill.name == "test"


class TestFilenameAlias:
    """文件名别名测试（CLI 用 pe_analyzer 调用 YAML name 为中文的技能）。"""

    def test_get_by_source_stem(self, tmp_path: Path) -> None:
        """name 未命中时按来源文件名 stem 匹配。"""
        from pathlib import Path as P

        registry = SkillRegistry()
        skill = Skill(
            name="PE 文件分析",
            description="d",
            source_path=P("/x/pe_analyzer.yaml"),
        )
        registry.register(skill)
        assert registry.get("pe_analyzer") is skill

    def test_missing_still_raises(self) -> None:
        """两者都未命中时仍抛 SkillNotFoundError。"""
        registry = SkillRegistry()
        with pytest.raises(SkillNotFoundError):
            registry.get("nope")
