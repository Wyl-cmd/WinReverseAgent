"""测试模块：winreverse.cli.mem

测试 winreverse mem 内存取证子命令：
- mem 无参数显示帮助
- mem analyze 对合成转储目录的完整输出
- mem analyze 缺失 manifest 时的错误路径
- mem regions/dump 的附加失败路径（进程不存在）
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from winreverse.cli import app

runner = CliRunner()


def _make_dump_dir(tmp_path: Path) -> Path:
    """构造含 manifest 的合成转储目录。"""
    dump_dir = tmp_path / "dump"
    dump_dir.mkdir()
    content = b"c2_marker http://c2.evil.top/gate\x00"
    (dump_dir / "region_0000.bin").write_bytes(content)
    manifest = {
        "pid": 1234,
        "created_at": "2026-08-29T00:00:00+00:00",
        "regions": [
            {
                "file": "region_0000.bin",
                "sha256": hashlib.sha256(content).hexdigest(),
                "suspicious": True,
                "base_address": "0x10000",
                "protect": "RWX",
                "type": "private",
            }
        ],
    }
    (dump_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return dump_dir


class TestMemHelp:
    """mem 子命令帮助测试。"""

    def test_mem_help_shows_subcommands(self) -> None:
        """--help 显示三个子命令。"""
        result = runner.invoke(app, ["mem", "--help"])
        assert result.exit_code == 0
        assert "regions" in result.stdout
        assert "dump" in result.stdout
        assert "analyze" in result.stdout

    def test_mem_no_args_shows_usage(self) -> None:
        """无参数调用显示用法提示（click no_args_is_help 退出码为 2）。"""
        result = runner.invoke(app, ["mem"])
        assert result.exit_code == 2
        assert "regions" in result.stdout


class TestMemAnalyze:
    """mem analyze 命令测试。"""

    def test_analyze_synthetic_dump(self, tmp_path: Path) -> None:
        """对合成转储目录输出完整报告（概览/可疑区域/IOC 汇总）。"""
        dump_dir = _make_dump_dir(tmp_path)
        json_out = tmp_path / "report.json"
        result = runner.invoke(
            app,
            ["mem", "analyze", str(dump_dir), "--json", str(json_out)],
        )
        assert result.exit_code == 0, result.output
        assert "1,234" in result.stdout or "1234" in result.stdout
        assert "IOC" in result.stdout
        assert "c2.evil.top" in result.stdout
        # JSON 报告已落盘且结构完整
        report = json.loads(json_out.read_text(encoding="utf-8"))
        assert report["pid"] == 1234
        assert report["total_ioc_count"] >= 1
        assert len(report["suspicious_regions"]) == 1

    def test_analyze_missing_manifest_fails(self, tmp_path: Path) -> None:
        """目录缺 manifest 时命令以非零退出并给出提示。"""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        result = runner.invoke(app, ["mem", "analyze", str(empty_dir)])
        assert result.exit_code == 1
        assert "manifest.json 缺失" in result.stdout

    def test_analyze_missing_dir_fails(self, tmp_path: Path) -> None:
        """目录不存在时命令以非零退出。"""
        result = runner.invoke(app, ["mem", "analyze", str(tmp_path / "nope")])
        assert result.exit_code == 1
        assert "转储目录不存在" in result.stdout

    def test_analyze_with_yara_rules(self, tmp_path: Path) -> None:
        """--rules 传入 YARA 规则文件时展示命中。"""
        dump_dir = _make_dump_dir(tmp_path)
        rules_file = tmp_path / "rules.yar"
        rules_file.write_text(
            'rule c2_marker { strings: $a = "c2_marker" ascii condition: $a }',
            encoding="utf-8",
        )
        result = runner.invoke(app, ["mem", "analyze", str(dump_dir), "--rules", str(rules_file)])
        assert result.exit_code == 0, result.output
        assert "c2_marker" in result.stdout


class TestMemAttachFailure:
    """mem regions/dump 附加失败路径测试。"""

    def test_regions_nonexistent_process_fails(self) -> None:
        """不存在的进程名导致退出码 1 并提示。"""
        result = runner.invoke(app, ["mem", "regions", "no_such_process_xyz.exe"])
        assert result.exit_code == 1

    def test_dump_nonexistent_process_fails(self) -> None:
        """不存在的进程名导致退出码 1 并提示。"""
        result = runner.invoke(app, ["mem", "dump", "no_such_process_xyz.exe"])
        assert result.exit_code == 1
