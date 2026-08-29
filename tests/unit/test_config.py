"""测试模块：winreverse.config

覆盖配置系统核心功能：
- AppConfig / LLMConfig / AgentConfig / ToolsConfig 模型默认值与验证
- load_config / save_config 往返读写
- ensure_config_exists 首次创建
- LLMConfig.resolve_api_key 环境变量回退
- _tomlkit_to_native 转换
- 异常处理（语法错误、验证失败、读写失败）
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from winreverse.config import (
    AgentConfig,
    AppConfig,
    ConfigError,
    LLMConfig,
    ToolsConfig,
    create_default_config,
    ensure_config_exists,
    get_default_config_path,
    load_config,
    load_or_default,
    save_config,
)

# =============================================================================
# 默认值与模型验证测试
# =============================================================================


class TestLLMConfig:
    """LLMConfig 模型测试。"""

    def test_default_values(self) -> None:
        """默认值正确。"""
        cfg = LLMConfig()
        assert cfg.provider == "openai"
        assert cfg.model == ""
        assert cfg.api_key == ""
        assert cfg.base_url == ""
        assert cfg.max_tokens == 8192
        assert cfg.temperature == 0.7

    def test_custom_values(self) -> None:
        """自定义值。"""
        cfg = LLMConfig(
            provider="openai",
            model="gpt-4",
            api_key="sk-xxx",
            base_url="https://api.openai.com/v1",
            max_tokens=4096,
            temperature=0.5,
        )
        assert cfg.provider == "openai"
        assert cfg.model == "gpt-4"
        assert cfg.api_key == "sk-xxx"
        assert cfg.max_tokens == 4096
        assert cfg.temperature == 0.5

    def test_max_tokens_must_be_positive(self) -> None:
        """max_tokens 必须 >=1。"""
        with pytest.raises(ValueError, match="greater_than_equal"):
            LLMConfig(max_tokens=0)

    def test_temperature_range(self) -> None:
        """temperature 必须 0.0-2.0。"""
        with pytest.raises(ValueError, match="less_than_equal"):
            LLMConfig(temperature=2.5)
        with pytest.raises(ValueError, match="greater_than_equal"):
            LLMConfig(temperature=-0.1)

    def test_resolve_api_key_from_config(self) -> None:
        """配置文件中的 api_key 优先。"""
        cfg = LLMConfig(api_key="config_key", provider="openai")
        assert cfg.resolve_api_key() == "config_key"

    def test_resolve_api_key_strips_whitespace(self) -> None:
        """api_key 去除首尾空白。"""
        cfg = LLMConfig(api_key="  sk-xxx  ")
        assert cfg.resolve_api_key() == "sk-xxx"

    def test_resolve_api_key_from_env_openai(self) -> None:
        """openai 协议从 OPENAI_API_KEY 环境变量读取。"""
        cfg = LLMConfig(api_key="", provider="openai")
        with patch.dict(os.environ, {"OPENAI_API_KEY": "env_key"}):
            assert cfg.resolve_api_key() == "env_key"

    def test_resolve_api_key_empty_when_no_env(self) -> None:
        """无环境变量时返回空字符串。"""
        cfg = LLMConfig(api_key="", provider="openai")
        with patch.dict(os.environ, {}, clear=True):
            assert cfg.resolve_api_key() == ""

    def test_resolve_api_key_config_overrides_env(self) -> None:
        """配置文件 api_key 优先于环境变量。"""
        cfg = LLMConfig(api_key="config_key", provider="openai")
        with patch.dict(os.environ, {"OPENAI_API_KEY": "env_key"}):
            assert cfg.resolve_api_key() == "config_key"

    def test_resolve_api_key_unknown_provider(self) -> None:
        """未知 provider 返回空字符串。"""
        cfg = LLMConfig(api_key="", provider="unknown")
        assert cfg.resolve_api_key() == ""


class TestAgentConfig:
    """AgentConfig 模型测试。"""

    def test_default_values(self) -> None:
        cfg = AgentConfig()
        assert cfg.work_dir == "."
        assert cfg.skills_dir == "skills"
        assert cfg.max_turns == 50
        assert cfg.yolo is False
        assert cfg.default_agent_type == "default"

    def test_max_turns_range(self) -> None:
        """max_turns 必须 1-500。"""
        with pytest.raises(ValueError):
            AgentConfig(max_turns=0)
        with pytest.raises(ValueError):
            AgentConfig(max_turns=501)


class TestToolsConfig:
    """ToolsConfig 模型测试。"""

    def test_default_values(self) -> None:
        cfg = ToolsConfig()
        assert cfg.tools_dir == "tools"
        assert cfg.verify_on_startup is True


class TestAppConfig:
    """AppConfig 聚合模型测试。"""

    def test_default_has_all_sections(self) -> None:
        cfg = AppConfig()
        assert isinstance(cfg.llm, LLMConfig)
        assert isinstance(cfg.agent, AgentConfig)
        assert isinstance(cfg.tools, ToolsConfig)

    def test_nested_override(self) -> None:
        cfg = AppConfig(
            llm=LLMConfig(provider="openai", model="gpt-4"),
            agent=AgentConfig(max_turns=100, yolo=True),
        )
        assert cfg.llm.provider == "openai"
        assert cfg.agent.max_turns == 100
        assert cfg.agent.yolo is True

    def test_partial_dict_validation(self) -> None:
        """部分字段缺失时使用默认值。"""
        cfg = AppConfig.model_validate({"llm": {"provider": "openai"}})
        assert cfg.llm.provider == "openai"
        # model 未指定，使用默认值
        assert cfg.llm.model == ""
        # agent/tools 段缺失，使用默认值
        assert cfg.agent.max_turns == 50
        assert cfg.tools.verify_on_startup is True


# =============================================================================
# load_config / save_config 往返测试
# =============================================================================


class TestLoadSaveConfig:
    """load_config 与 save_config 往返读写测试。"""

    def test_save_creates_file(self, tmp_path: Path) -> None:
        """save_config 创建文件。"""
        config_path = tmp_path / "config.toml"
        cfg = AppConfig()
        save_config(cfg, config_path)

        assert config_path.exists()
        content = config_path.read_text(encoding="utf-8")
        assert "[llm]" in content
        assert "[agent]" in content
        assert "[tools]" in content
        assert "openai" in content

    def test_save_with_comments(self, tmp_path: Path) -> None:
        """保存的文件包含注释。"""
        config_path = tmp_path / "config.toml"
        save_config(AppConfig(), config_path)
        content = config_path.read_text(encoding="utf-8")
        assert "WinReverseAgent 配置文件" in content
        assert "api_key 留空" in content

    def test_load_returns_default_when_file_missing(self, tmp_path: Path) -> None:
        """文件不存在时返回默认配置。"""
        config_path = tmp_path / "nonexistent.toml"
        cfg = load_config(config_path)
        assert isinstance(cfg, AppConfig)
        assert cfg.llm.provider == "openai"  # 默认值

    def test_round_trip_preserves_values(self, tmp_path: Path) -> None:
        """保存后重新加载，值保持一致。"""
        config_path = tmp_path / "config.toml"
        original = AppConfig(
            llm=LLMConfig(
                provider="openai",
                model="gpt-4",
                api_key="sk-test",
                base_url="https://api.openai.com/v1",
                max_tokens=2048,
                temperature=0.3,
            ),
            agent=AgentConfig(max_turns=100, yolo=True, default_agent_type="reverse"),
            tools=ToolsConfig(tools_dir="custom_tools", verify_on_startup=False),
        )
        save_config(original, config_path)
        loaded = load_config(config_path)

        assert loaded.llm.provider == "openai"
        assert loaded.llm.model == "gpt-4"
        assert loaded.llm.api_key == "sk-test"
        assert loaded.llm.base_url == "https://api.openai.com/v1"
        assert loaded.llm.max_tokens == 2048
        assert loaded.llm.temperature == 0.3
        assert loaded.agent.max_turns == 100
        assert loaded.agent.yolo is True
        assert loaded.agent.default_agent_type == "reverse"
        assert loaded.tools.tools_dir == "custom_tools"
        assert loaded.tools.verify_on_startup is False

    def test_load_partial_config(self, tmp_path: Path) -> None:
        """加载部分字段配置，缺失字段用默认值。"""
        config_path = tmp_path / "config.toml"
        config_path.write_text(
            """
[llm]
provider = "openai"
# 其他字段缺失
""",
            encoding="utf-8",
        )
        cfg = load_config(config_path)
        assert cfg.llm.provider == "openai"
        assert cfg.llm.model == ""  # 默认值
        assert cfg.agent.max_turns == 50  # 默认值

    def test_load_empty_file(self, tmp_path: Path) -> None:
        """空文件返回默认配置。"""
        config_path = tmp_path / "config.toml"
        config_path.write_text("", encoding="utf-8")
        cfg = load_config(config_path)
        assert cfg.llm.provider == "openai"

    def test_load_invalid_toml_raises(self, tmp_path: Path) -> None:
        """TOML 语法错误抛出 ConfigError。"""
        config_path = tmp_path / "config.toml"
        config_path.write_text("not = valid = toml", encoding="utf-8")
        with pytest.raises(ConfigError, match="TOML 语法错误"):
            load_config(config_path)

    def test_load_validation_error_raises(self, tmp_path: Path) -> None:
        """字段验证失败抛出 ConfigError。"""
        config_path = tmp_path / "config.toml"
        config_path.write_text(
            """
[llm]
max_tokens = -1
""",
            encoding="utf-8",
        )
        with pytest.raises(ConfigError, match="字段验证失败"):
            load_config(config_path)

    def test_save_creates_parent_directory(self, tmp_path: Path) -> None:
        """保存时自动创建父目录。"""
        config_path = tmp_path / "subdir" / "nested" / "config.toml"
        save_config(AppConfig(), config_path)
        assert config_path.exists()


# =============================================================================
# ensure_config_exists 测试
# =============================================================================


class TestEnsureConfigExists:
    """ensure_config_exists 测试。"""

    def test_creates_default_when_missing(self, tmp_path: Path) -> None:
        """文件不存在时创建默认配置。"""
        config_path = tmp_path / "config.toml"
        assert not config_path.exists()

        path, cfg = ensure_config_exists(config_path)

        assert path == config_path
        assert config_path.exists()
        assert isinstance(cfg, AppConfig)
        assert cfg.llm.provider == "openai"

    def test_loads_existing(self, tmp_path: Path) -> None:
        """文件已存在时加载而非覆盖。"""
        config_path = tmp_path / "config.toml"
        original = AppConfig(llm=LLMConfig(provider="openai"))
        save_config(original, config_path)

        path, cfg = ensure_config_exists(config_path)

        assert path == config_path
        assert cfg.llm.provider == "openai"


# =============================================================================
# load_or_default 测试
# =============================================================================


class TestLoadOrDefault:
    """load_or_default 优雅降级测试。"""

    def test_returns_loaded_config(self, tmp_path: Path) -> None:
        """正常加载。"""
        config_path = tmp_path / "config.toml"
        save_config(AppConfig(llm=LLMConfig(provider="openai")), config_path)

        cfg = load_or_default(config_path)
        assert cfg.llm.provider == "openai"

    def test_returns_default_on_error(self, tmp_path: Path) -> None:
        """加载失败时返回默认值。"""
        config_path = tmp_path / "config.toml"
        config_path.write_text("invalid = = toml", encoding="utf-8")

        cfg = load_or_default(config_path)
        assert isinstance(cfg, AppConfig)
        assert cfg.llm.provider == "openai"

    def test_returns_default_when_missing(self, tmp_path: Path) -> None:
        """文件不存在时返回默认值。"""
        cfg = load_or_default(tmp_path / "nonexistent.toml")
        assert isinstance(cfg, AppConfig)


# =============================================================================
# get_default_config_path 测试
# =============================================================================


class TestGetDefaultConfigPath:
    """get_default_config_path 测试。"""

    def test_prefers_cwd_config(self, tmp_path: Path) -> None:
        """优先使用当前目录的 config.toml。"""
        cwd_config = tmp_path / "config.toml"
        cwd_config.write_text("[llm]\nprovider = 'openai'\n", encoding="utf-8")

        with patch("winreverse.config.settings.Path.cwd", return_value=tmp_path):
            path = get_default_config_path()
            assert path == cwd_config

    def test_falls_back_to_home(self, tmp_path: Path) -> None:
        """当前目录无配置时回退到用户主目录。"""
        with (
            patch("winreverse.config.settings.Path.cwd", return_value=tmp_path),
            patch("winreverse.config.settings.Path.home", return_value=tmp_path / "home"),
        ):
            path = get_default_config_path()
            assert path == tmp_path / "home" / ".winreverse" / "config.toml"


# =============================================================================
# _tomlkit_to_native 测试
# =============================================================================


class TestTomlkitToNative:
    """_tomlkit_to_native 转换测试。"""

    def test_dict_conversion(self) -> None:
        """字典转换。"""
        import tomlkit

        from winreverse.config.settings import _tomlkit_to_native

        doc = tomlkit.parse('[section]\nkey = "value"\nnum = 42')
        result = _tomlkit_to_native(doc)
        assert isinstance(result, dict)
        assert result["section"]["key"] == "value"
        assert result["section"]["num"] == 42

    def test_list_conversion(self) -> None:
        """列表转换。"""
        import tomlkit

        from winreverse.config.settings import _tomlkit_to_native

        doc = tomlkit.parse('items = ["a", "b", "c"]')
        result = _tomlkit_to_native(doc)
        assert isinstance(result["items"], list)
        assert result["items"] == ["a", "b", "c"]

    def test_nested_structure(self) -> None:
        """嵌套结构转换。"""
        import tomlkit

        from winreverse.config.settings import _tomlkit_to_native

        doc = tomlkit.parse('[a]\n[a.b]\nlist = [1, 2, 3]\nstr = "hello"')
        result = _tomlkit_to_native(doc)
        assert result["a"]["b"]["list"] == [1, 2, 3]
        assert result["a"]["b"]["str"] == "hello"

    def test_primitive_passthrough(self) -> None:
        """原始类型直接返回。"""
        from winreverse.config.settings import _tomlkit_to_native

        assert _tomlkit_to_native(42) == 42
        assert _tomlkit_to_native("hello") == "hello"
        assert _tomlkit_to_native(True) is True
        assert _tomlkit_to_native(3.14) == 3.14


# =============================================================================
# create_default_config 测试
# =============================================================================


class TestCreateDefaultConfig:
    """create_default_config 工厂函数测试。"""

    def test_returns_app_config(self) -> None:
        cfg = create_default_config()
        assert isinstance(cfg, AppConfig)
        assert cfg.llm.provider == "openai"
        assert cfg.agent.max_turns == 50
        assert cfg.tools.verify_on_startup is True
