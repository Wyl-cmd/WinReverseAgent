"""被测模块: winreverse.tools.runner（ToolRunner 尾部防御路径）。

覆盖点: _get_tool_entry 非 dict 条目 ValueError（runner.py:159）、
get_entry_path 非字符串 install_path/entry ValueError（runner.py:184）、
run() 缺省 args=None → []（runner.py:230）。全程无 Windows 专有依赖。
"""

from __future__ import annotations

import subprocess
from collections import UserDict
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from winreverse.tools.runner import ToolRunner


@pytest.fixture
def runner(tmp_path: Path) -> ToolRunner:
    """指向临时 manifest 的 ToolRunner（manifest 内容按需注入）。"""
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text("tools: []\n", encoding="utf-8")
    return ToolRunner(manifest_path=manifest, project_root=tmp_path)


def _inject_manifest(
    monkeypatch: pytest.MonkeyPatch, runner: ToolRunner, data: dict[str, Any]
) -> None:
    """注入手工构造的 manifest 数据（UserDict 等无法经 yaml.safe_load 表达）。"""
    monkeypatch.setattr(runner, "_load_manifest", lambda: data)


class TestGetToolEntryTypeGuard:
    """manifest 中工具条目为非 dict 类型时的防御分支。"""

    def test_non_dict_entry_raises_value_error(
        self, monkeypatch: pytest.MonkeyPatch, runner: ToolRunner
    ) -> None:
        entry_like = UserDict(
            {"name": "tshark", "install_path": "tools/tshark/", "entry": "tshark.exe"}
        )
        _inject_manifest(monkeypatch, runner, {"tools": [entry_like]})
        with pytest.raises(ValueError, match="配置项应为字典，实际为 UserDict"):
            runner.get_entry_path("tshark")


class TestGetEntryPathTypeGuard:
    """install_path / entry 字段类型防御。"""

    def test_non_string_install_path_raises(
        self, monkeypatch: pytest.MonkeyPatch, runner: ToolRunner
    ) -> None:
        _inject_manifest(
            monkeypatch,
            runner,
            {"tools": [{"name": "tshark", "install_path": 123, "entry": "tshark.exe"}]},
        )
        with pytest.raises(ValueError, match="install_path/entry 应为字符串"):
            runner.get_entry_path("tshark")

    def test_non_string_entry_raises(
        self, monkeypatch: pytest.MonkeyPatch, runner: ToolRunner
    ) -> None:
        _inject_manifest(
            monkeypatch,
            runner,
            {"tools": [{"name": "yara", "install_path": "tools/yara/", "entry": ["yara64.exe"]}]},
        )
        with pytest.raises(ValueError, match="install_path/entry 应为字符串"):
            runner.get_entry_path("yara")


class TestRunWithDefaultArgs:
    """run() 未传 args 时以空参数表执行（runner.py:229-230）。"""

    def test_args_none_becomes_empty_argv(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runner: ToolRunner
    ) -> None:
        tool_dir = tmp_path / "tools" / "tshark"
        tool_dir.mkdir(parents=True)
        (tool_dir / "tshark.exe").touch()
        monkeypatch.chdir(tmp_path)
        _inject_manifest(
            monkeypatch,
            runner,
            {"tools": [{"name": "tshark", "install_path": "tools/tshark/", "entry": "tshark.exe"}]},
        )
        # text=True 语义下 subprocess 回传 str，模拟须忠实于该契约
        proc = MagicMock(returncode=0, stdout="PING", stderr="")
        with patch.object(subprocess, "run", return_value=proc) as mock_run:
            result = runner.run("tshark")
        argv = mock_run.call_args.args[0]
        assert argv == [str(tmp_path / "tools" / "tshark" / "tshark.exe")]
        assert mock_run.call_args.kwargs["errors"] == "replace"
        assert mock_run.call_args.kwargs["text"] is True
        assert result.command == argv
        assert result.returncode == 0
        assert result.stdout == "PING"
        assert result.timed_out is False
        assert result.success is True
