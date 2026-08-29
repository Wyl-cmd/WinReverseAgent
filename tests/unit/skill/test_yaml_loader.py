"""测试模块：winreverse.skill.loader.YamlSkillLoader

测试 YAML 格式 Skill 加载器。

覆盖：
- supports() 后缀判断
- load() 成功路径（完整字段、最小字段、示例 Skill 文件）
- load() 错误路径（文件不存在、YAML 语法错误、字段缺失、格式错误）
- SkillLoader Protocol 满足性
"""

from __future__ import annotations

from pathlib import Path

import pytest

from winreverse.skill.loader import (
    Skill,
    SkillLoadError,
    YamlSkillLoader,
)

# 项目根目录（WinReverseAgent/），用于定位 skills/ 示例文件
# 本文件路径：WinReverseAgent/tests/unit/skill/test_yaml_loader.py
# parents[0]=skill/ [1]=unit/ [2]=tests/ [3]=WinReverseAgent/
PROJECT_ROOT = Path(__file__).resolve().parents[3]
SKILLS_DIR = PROJECT_ROOT / "skills"


# =============================================================================
# supports() 测试
# =============================================================================


class TestSupports:
    """supports() 后缀判断测试。"""

    def test_yaml_suffix(self) -> None:
        """.yaml 后缀返回 True。"""
        loader = YamlSkillLoader()
        assert loader.supports(Path("test.yaml")) is True

    def test_yml_suffix(self) -> None:
        """.yml 后缀返回 True。"""
        loader = YamlSkillLoader()
        assert loader.supports(Path("test.yml")) is True

    def test_uppercase_suffix(self) -> None:
        """大写后缀也支持（不区分大小写）。"""
        loader = YamlSkillLoader()
        assert loader.supports(Path("test.YAML")) is True
        assert loader.supports(Path("test.YML")) is True

    def test_md_suffix(self) -> None:
        """.md 后缀返回 False。"""
        loader = YamlSkillLoader()
        assert loader.supports(Path("test.md")) is False

    def test_json_suffix(self) -> None:
        """.json 后缀返回 False。"""
        loader = YamlSkillLoader()
        assert loader.supports(Path("test.json")) is False

    def test_no_suffix(self) -> None:
        """无后缀返回 False。"""
        loader = YamlSkillLoader()
        assert loader.supports(Path("test")) is False


# =============================================================================
# load() 成功路径测试
# =============================================================================


class TestLoadSuccess:
    """load() 成功路径测试。"""

    def test_full_skill(self, tmp_path: Path, sample_skill_yaml: str) -> None:
        """加载完整 Skill（含所有字段）。"""
        skill_file = tmp_path / "test.yaml"
        skill_file.write_text(sample_skill_yaml, encoding="utf-8")

        loader = YamlSkillLoader()
        skill = loader.load(skill_file)

        assert isinstance(skill, Skill)
        assert skill.name == "测试技能"
        assert skill.description == "用于单元测试的示例技能"
        assert skill.target == "通用"
        assert skill.source_path == skill_file

        # 参数解析
        assert len(skill.parameters) == 1
        param = skill.parameters[0]
        assert param.name == "process_name"
        assert param.type == "string"
        assert param.default == "test.exe"
        assert param.required is True

        # Prompt 模板
        assert "{{process_name}}" in skill.prompt_template
        assert "附加进程" in skill.prompt_template

        # 执行流
        assert len(skill.execution_flow) == 1
        assert skill.execution_flow[0]["action"] == "memory.attach"

    def test_minimal_skill(self, tmp_path: Path) -> None:
        """加载最小 Skill（仅 name + description）。"""
        skill_file = tmp_path / "minimal.yaml"
        skill_file.write_text(
            'name: "最小技能"\ndescription: "仅必填字段"\n',
            encoding="utf-8",
        )

        loader = YamlSkillLoader()
        skill = loader.load(skill_file)

        assert skill.name == "最小技能"
        assert skill.description == "仅必填字段"
        assert skill.target == "通用"  # 默认值
        assert skill.parameters == []
        assert skill.prompt_template == ""
        assert skill.execution_flow == []

    def test_skill_without_target_uses_default(self, tmp_path: Path) -> None:
        """未提供 target 时使用默认值 '通用'。"""
        skill_file = tmp_path / "no_target.yaml"
        skill_file.write_text(
            'name: "无目标"\ndescription: "测试默认 target"\n',
            encoding="utf-8",
        )

        loader = YamlSkillLoader()
        skill = loader.load(skill_file)

        assert skill.target == "通用"

    def test_skill_with_multiple_parameters(self, tmp_path: Path) -> None:
        """多参数 Skill 解析。"""
        skill_file = tmp_path / "multi.yaml"
        skill_file.write_text(
            """
name: "多参数"
description: "测试多参数解析"
parameters:
  - name: "process_name"
    type: "string"
    required: true
  - name: "timeout"
    type: "int"
    default: 30
    required: false
  - name: "verbose"
    type: "bool"
    default: false
""".strip(),
            encoding="utf-8",
        )

        loader = YamlSkillLoader()
        skill = loader.load(skill_file)

        assert len(skill.parameters) == 3
        assert skill.parameters[0].name == "process_name"
        assert skill.parameters[0].required is True
        assert skill.parameters[1].name == "timeout"
        assert skill.parameters[1].default == 30
        assert skill.parameters[2].name == "verbose"
        assert skill.parameters[2].default is False

    def test_skill_with_multiple_execution_flow(self, tmp_path: Path) -> None:
        """多步骤执行流解析。"""
        skill_file = tmp_path / "flow.yaml"
        skill_file.write_text(
            """
name: "多步骤"
description: "测试多步骤执行流"
execution_flow:
  - action: "memory.attach"
    args: "game.exe"
  - action: "memory.read"
    args:
      type: "int"
  - action: "memory.write"
    args: 100
""".strip(),
            encoding="utf-8",
        )

        loader = YamlSkillLoader()
        skill = loader.load(skill_file)

        assert len(skill.execution_flow) == 3
        assert skill.execution_flow[0]["action"] == "memory.attach"
        assert skill.execution_flow[1]["action"] == "memory.read"
        assert skill.execution_flow[2]["action"] == "memory.write"

    def test_load_actual_skill_files(self) -> None:
        """加载项目 skills/ 目录下的实际示例 Skill 文件。

        验证 4 个预置 Skill 都能被正确加载。
        """
        if not SKILLS_DIR.exists():
            pytest.skip(f"skills 目录不存在: {SKILLS_DIR}")

        loader = YamlSkillLoader()
        skill_files = sorted(SKILLS_DIR.glob("*.yaml"))
        assert len(skill_files) >= 4, f"应至少有 4 个示例 Skill，实际: {len(skill_files)}"

        expected_names = {"自动锁定血量", "协议分析", "内存扫描", "PE 文件分析"}
        actual_names: set[str] = set()

        for skill_file in skill_files:
            skill = loader.load(skill_file)
            assert isinstance(skill, Skill)
            assert skill.source_path == skill_file
            actual_names.add(skill.name)
            # 每个 Skill 应有 prompt_template
            assert len(skill.prompt_template) > 0
            # 每个 Skill 应有至少一个参数
            assert len(skill.parameters) >= 1

        assert expected_names.issubset(actual_names), f"缺失 Skill: {expected_names - actual_names}"


# =============================================================================
# load() 错误路径测试
# =============================================================================


class TestLoadErrors:
    """load() 错误路径测试。"""

    def test_file_not_found(self, tmp_path: Path) -> None:
        """文件不存在抛 FileNotFoundError。"""
        loader = YamlSkillLoader()
        with pytest.raises(FileNotFoundError):
            loader.load(tmp_path / "nonexistent.yaml")

    def test_yaml_syntax_error(self, tmp_path: Path) -> None:
        """YAML 语法错误抛 SkillLoadError。"""
        skill_file = tmp_path / "bad.yaml"
        skill_file.write_text(
            'name: "test"\ndescription: "test"\n  bad: indent\n',
            encoding="utf-8",
        )

        loader = YamlSkillLoader()
        with pytest.raises(SkillLoadError, match="YAML 语法错误"):
            loader.load(skill_file)

    def test_top_level_not_dict(self, tmp_path: Path) -> None:
        """顶层非字典抛 SkillLoadError。"""
        skill_file = tmp_path / "list.yaml"
        skill_file.write_text("- item1\n- item2\n", encoding="utf-8")

        loader = YamlSkillLoader()
        with pytest.raises(SkillLoadError, match="顶层结构必须是字典"):
            loader.load(skill_file)

    def test_missing_name(self, tmp_path: Path) -> None:
        """缺少 name 字段抛 SkillLoadError。"""
        skill_file = tmp_path / "no_name.yaml"
        skill_file.write_text(
            'description: "无 name 字段"\n',
            encoding="utf-8",
        )

        loader = YamlSkillLoader()
        with pytest.raises(SkillLoadError, match="缺少必填字段 'name'"):
            loader.load(skill_file)

    def test_missing_description(self, tmp_path: Path) -> None:
        """缺少 description 字段抛 SkillLoadError。"""
        skill_file = tmp_path / "no_desc.yaml"
        skill_file.write_text(
            'name: "无描述"\n',
            encoding="utf-8",
        )

        loader = YamlSkillLoader()
        with pytest.raises(SkillLoadError, match="缺少必填字段 'description'"):
            loader.load(skill_file)

    def test_empty_name(self, tmp_path: Path) -> None:
        """name 为空字符串抛 SkillLoadError。"""
        skill_file = tmp_path / "empty_name.yaml"
        skill_file.write_text(
            'name: ""\ndescription: "空 name"\n',
            encoding="utf-8",
        )

        loader = YamlSkillLoader()
        with pytest.raises(SkillLoadError, match="缺少必填字段 'name'"):
            loader.load(skill_file)

    def test_parameters_not_list(self, tmp_path: Path) -> None:
        """parameters 非列表抛 SkillLoadError。"""
        skill_file = tmp_path / "bad_params.yaml"
        skill_file.write_text(
            """
name: "测试"
description: "parameters 非列表"
parameters: "not a list"
""".strip(),
            encoding="utf-8",
        )

        loader = YamlSkillLoader()
        with pytest.raises(SkillLoadError, match="'parameters' 必须是列表"):
            loader.load(skill_file)

    def test_parameter_item_not_dict(self, tmp_path: Path) -> None:
        """parameters 项非字典抛 SkillLoadError。"""
        skill_file = tmp_path / "bad_param_item.yaml"
        skill_file.write_text(
            """
name: "测试"
description: "parameter 项非字典"
parameters:
  - "not a dict"
""".strip(),
            encoding="utf-8",
        )

        loader = YamlSkillLoader()
        with pytest.raises(SkillLoadError, match="'parameters\\[0\\]' 必须是字典"):
            loader.load(skill_file)

    def test_parameter_missing_name(self, tmp_path: Path) -> None:
        """parameter 项缺少 name 抛 SkillLoadError。"""
        skill_file = tmp_path / "param_no_name.yaml"
        skill_file.write_text(
            """
name: "测试"
description: "parameter 缺少 name"
parameters:
  - type: "string"
""".strip(),
            encoding="utf-8",
        )

        loader = YamlSkillLoader()
        with pytest.raises(SkillLoadError, match="'parameters\\[0\\]' 缺少 'name'"):
            loader.load(skill_file)

    def test_execution_flow_not_list(self, tmp_path: Path) -> None:
        """execution_flow 非列表抛 SkillLoadError。"""
        skill_file = tmp_path / "bad_flow.yaml"
        skill_file.write_text(
            """
name: "测试"
description: "execution_flow 非列表"
execution_flow: "not a list"
""".strip(),
            encoding="utf-8",
        )

        loader = YamlSkillLoader()
        with pytest.raises(SkillLoadError, match="'execution_flow' 必须是列表"):
            loader.load(skill_file)

    def test_execution_flow_item_not_dict(self, tmp_path: Path) -> None:
        """execution_flow 项非字典抛 SkillLoadError。"""
        skill_file = tmp_path / "bad_flow_item.yaml"
        skill_file.write_text(
            """
name: "测试"
description: "execution_flow 项非字典"
execution_flow:
  - "not a dict"
""".strip(),
            encoding="utf-8",
        )

        loader = YamlSkillLoader()
        with pytest.raises(SkillLoadError, match="'execution_flow\\[0\\]' 必须是字典"):
            loader.load(skill_file)

    def test_execution_flow_missing_action(self, tmp_path: Path) -> None:
        """execution_flow 项缺少 action 抛 SkillLoadError。"""
        skill_file = tmp_path / "flow_no_action.yaml"
        skill_file.write_text(
            """
name: "测试"
description: "execution_flow 缺少 action"
execution_flow:
  - args: "no action"
""".strip(),
            encoding="utf-8",
        )

        loader = YamlSkillLoader()
        with pytest.raises(SkillLoadError, match="'execution_flow\\[0\\]' 缺少 'action'"):
            loader.load(skill_file)


# =============================================================================
# SkillLoader Protocol 满足性测试
# =============================================================================


class TestProtocolConformance:
    """YamlSkillLoader 应满足 SkillLoader Protocol。"""

    def test_satisfies_protocol(self) -> None:
        """YamlSkillLoader 实例应满足 SkillLoader Protocol。"""
        loader = YamlSkillLoader()
        # Protocol 是结构性子类型，只要有 load 和 supports 方法即满足
        assert hasattr(loader, "load")
        assert hasattr(loader, "supports")
        assert callable(loader.load)
        assert callable(loader.supports)

    def test_protocol_runtime_check(self) -> None:
        """runtime check: isinstance(loader, SkillLoader) 应返回 True。

        注意：Protocol 默认是结构性子类型，runtime check 需要
        @runtime_checkable 装饰器。这里用 hasattr 替代。
        """
        loader = YamlSkillLoader()
        # SkillLoader Protocol 没有加 @runtime_checkable，所以不能用 isinstance
        # 但可以通过 hasattr 验证结构
        assert all(hasattr(loader, attr) for attr in ("load", "supports"))
