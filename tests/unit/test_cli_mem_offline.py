"""测试模块：winreverse.cli.mem 的 CLI 层（离线密闭，Linux 可跑）。

覆盖点：mem regions/dump/analyze 三命令的表格渲染、选项透传（--all/--out/
--max-mb/--top/--no-carve/--rules/--json）与错误路径（附加失败/转储失败/
分析失败），通过向 sys.modules 注入 fake core 模块隔离 pymem/yara 等
Windows 专有依赖；真实管线集成测试见 test_cli_mem.py（真机运行）。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

from typer.testing import CliRunner

from winreverse.cli import app

runner = CliRunner()


# =============================================================================
# fake core 模块构造
# =============================================================================


def _fake_module(name: str, **attrs: object) -> ModuleType:
    """构造带属性的假模块。"""
    module = ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    return module


def _install_core_fakes(monkeypatch: object, **modules: ModuleType) -> None:
    """把 fake 模块同时注入 sys.modules 与 winreverse.core 包属性。

    cli.mem 用 `from winreverse.core import xxx` 延迟导入：包属性命中优先，
    sys.modules 兜底覆盖嵌套 import，双写确保任何路径都拿到 fake。
    """
    import winreverse.core as core_pkg

    for attr, fake in modules.items():
        monkeypatch.setitem(sys.modules, f"winreverse.core.{attr}", fake)
        monkeypatch.setattr(core_pkg, attr, fake, raising=False)


def _region(
    base: int,
    size: int,
    *,
    protect_name: str = "RWX",
    type_name: str = "private",
    mapped_file: str | None = None,
    is_executable: bool = True,
    is_suspicious: bool = True,
) -> SimpleNamespace:
    """构造 MemoryRegion 形状的区域对象。"""
    return SimpleNamespace(
        base_address=base,
        size=size,
        protect_name=protect_name,
        type_name=type_name,
        mapped_file=mapped_file,
        is_executable=is_executable,
        is_suspicious=is_suspicious,
    )


def _fake_pymem(pid: int = 4242, handle: int = 999) -> SimpleNamespace:
    return SimpleNamespace(process_id=pid, process_handle=handle)


class _MemFakes:
    """收集 fake 模块中可调用对象的引用，便于断言透传参数。"""

    def __init__(self) -> None:
        self.calls: dict[str, object] = {}

    def attach_ok(self, target: str) -> SimpleNamespace:
        self.calls["attach_target"] = target
        return _fake_pymem()

    def enumerate_regions(self, handle: int, only_committed: bool = True) -> list:
        self.calls["enumerate_handle"] = handle
        return [
            _region(0x7FF60000, 0x1000, mapped_file=None),  # 可执行私有 RWX → 可疑
            _region(
                0x7FF70000,
                0x2000,
                protect_name="RX",
                mapped_file="C:\\Windows\\system32\\kernel32.dll",
                is_suspicious=False,
            ),
            _region(
                0x00990000,
                0x3000,
                protect_name="RW",
                type_name="private",
                mapped_file="Z:\\hidden.sys",
                is_executable=False,
                is_suspicious=False,
            ),
        ]

    def dump_process(self, handle: int, output_dir, min_size: int, max_total_bytes: int):
        self.calls["dump"] = {
            "handle": handle,
            "output_dir": output_dir,
            "min_size": min_size,
            "max_total_bytes": max_total_bytes,
        }
        return SimpleNamespace(
            output_dir=str(output_dir),
            manifest_path=str(Path(output_dir) / "manifest.json"),
            region_count=12,
            dumped_count=10,
            skipped_count=2,
            truncated_count=1,
            total_bytes=1234567,
            suspicious_count=3,
        )

    def analyze_dump_dir(self, dump_dir, *, rules_path=None, top_strings: int, carve: bool):
        self.calls["analyze"] = {
            "dump_dir": dump_dir,
            "rules_path": rules_path,
            "top_strings": top_strings,
            "carve": carve,
        }
        if self.analyze_error is not None:
            raise self.analyze_error
        return self.report

    analyze_error: Exception | None = None
    report: SimpleNamespace = SimpleNamespace()


def _make_report() -> SimpleNamespace:
    """构造 DumpAnalysisReport 形状的完整报告（含可疑区域/YARA 命中/告警）。"""
    ioc = SimpleNamespace(kind="url", value="http://c2.evil.top/gate")
    file_result = SimpleNamespace(
        file="region_0000.bin",
        size=4096,
        entropy=7.53,
        string_count=12,
        iocs=[ioc],
        carved_pes=[],
        warnings=["读取截断"],
    )
    yara_hit = SimpleNamespace(rule="c2_marker", tags=["c2"], meta={"author": "qa"})
    return SimpleNamespace(
        dump_dir="D:\\dumps\\sample",
        pid=1234,
        created_at="2026-08-29T00:00:00+00:00",
        files=[file_result],
        yara_matches={"region_0000.bin": [yara_hit]},
        suspicious_regions=[
            {
                "file": "region_0000.bin",
                "base_address": "0x10000",
                "protect": "RWX",
                "type": "private",
            }
        ],
        total_bytes=4096,
        warnings=["全局告警：manifest 版本较旧"],
        total_ioc_count=1,
        total_carved_pe_count=0,
        to_dict=lambda: {"pid": 1234, "total_ioc_count": 1},
    )


# =============================================================================
# mem regions
# =============================================================================


class TestMemRegions:
    """mem regions 渲染逻辑（默认仅可执行 / --all 全量 / 可疑标注）。"""

    def _invoke(self, monkeypatch, *args: str):
        fakes = _MemFakes()
        memory_api = _fake_module(
            "memory_api",
            MemoryAccessError=type("MemoryAccessError", (RuntimeError,), {}),
            attach=fakes.attach_ok,
        )
        memdump_api = _fake_module("memdump_api", enumerate_regions=fakes.enumerate_regions)
        _install_core_fakes(monkeypatch, memory_api=memory_api, memdump_api=memdump_api)
        result = runner.invoke(app, ["mem", "regions", "notepad.exe", *args])
        return result, fakes

    def test_default_shows_executable_and_suspicious_only(self, monkeypatch) -> None:
        """默认仅列可执行区域：可疑计数正确、非可执行区域不可见。"""
        result, fakes = self._invoke(monkeypatch)
        assert result.exit_code == 0, result.output
        assert fakes.calls["attach_target"] == "notepad.exe"
        assert fakes.calls["enumerate_handle"] == 999
        # 概览行：已提交 3 个 / 可执行 2 个 / 可疑 1 个
        assert "已提交区域 3 个" in result.stdout
        assert "可执行 2 个" in result.stdout
        assert "可疑注入候选 1 个" in result.stdout
        # 可疑 RWX 区域入表（十六进制基地址）
        assert "0x7FF60000" in result.stdout
        # 默认不显示非可执行区域
        assert "0x990000" not in result.stdout
        assert "Z:\\hidden.sys" not in result.stdout

    def test_all_flag_includes_non_executable(self, monkeypatch) -> None:
        """--all 显示全部已提交区域（含非可执行及其映射文件）。"""
        result, _fakes = self._invoke(monkeypatch, "--all")
        assert result.exit_code == 0, result.output
        assert "全部区域" in result.stdout
        assert "0x990000" in result.stdout
        assert "Z:\\hidden.sys" in result.stdout


# =============================================================================
# mem dump
# =============================================================================


class TestMemDump:
    """mem dump 汇总面板、输出目录解析与失败路径。"""

    def _invoke(self, monkeypatch, *args: str):
        fakes = _MemFakes()
        memory_api = _fake_module(
            "memory_api",
            MemoryAccessError=type("MemoryAccessError", (RuntimeError,), {}),
            attach=fakes.attach_ok,
        )
        memdump_api = _fake_module("memdump_api", dump_process=fakes.dump_process)
        _install_core_fakes(monkeypatch, memory_api=memory_api, memdump_api=memdump_api)
        result = runner.invoke(app, ["mem", "dump", "notepad.exe", *args])
        return result, fakes

    def test_default_output_dir_and_limits(self, monkeypatch) -> None:
        """默认输出目录 output/memory_dumps/<pid>_<ts>，--max-mb/--min-size 透传。"""
        result, fakes = self._invoke(monkeypatch, "--max-mb", "2048", "--min-size", "65536")
        assert result.exit_code == 0, result.output
        dumped = fakes.calls["dump"]
        # 修复(2026-09-12)：Windows 上 Path 用反斜杠，原断言硬编码 "/" → guest 必失败。
        # 统一归一化后比较（跨平台语义一致）。
        assert str(dumped["output_dir"]).replace("\\", "/").startswith("output/memory_dumps/4242_")
        assert dumped["max_total_bytes"] == 2048 * 1024 * 1024
        assert dumped["min_size"] == 65536
        # 面板渲染计数与后续命令提示
        assert "转储完成" in result.stdout
        assert "区域总数" in result.stdout
        assert "可疑区域" in result.stdout
        assert "mem analyze" in result.stdout

    def test_custom_output_dir(self, monkeypatch, tmp_path: Path) -> None:
        """--out 指定目录时原样透传给 dump_process。"""
        out_dir = tmp_path / "mydump"
        result, fakes = self._invoke(monkeypatch, "--out", str(out_dir))
        assert result.exit_code == 0, result.output
        assert fakes.calls["dump"]["output_dir"] == out_dir

    def test_dump_failure_exits_1(self, monkeypatch) -> None:
        """dump_process 抛 MemoryAccessError → 退出码 1 并提示「转储失败」。"""
        fakes = _MemFakes()
        error = type("MemoryAccessError", (RuntimeError,), {})
        memory_api = _fake_module("memory_api", MemoryAccessError=error, attach=fakes.attach_ok)

        def _boom(*a, **k):
            raise error("读取内存失败")

        memdump_api = _fake_module("memdump_api", dump_process=_boom)
        _install_core_fakes(monkeypatch, memory_api=memory_api, memdump_api=memdump_api)
        result = runner.invoke(app, ["mem", "dump", "notepad.exe"])
        assert result.exit_code == 1
        assert "转储失败" in result.stdout


# =============================================================================
# mem analyze
# =============================================================================


class TestMemAnalyzeOffline:
    """mem analyze 渲染、选项透传与错误路径（fake memanalysis_api）。"""

    def _invoke(self, monkeypatch, report, *args: str, error: Exception | None = None):
        fakes = _MemFakes()
        fakes.report = report
        fakes.analyze_error = error
        # 异常类必须与 error 实例同类，_attach/analyze 的 except 才能命中
        error_cls = (
            type(error) if error is not None else type("MemoryAnalysisError", (RuntimeError,), {})
        )
        memanalysis_api = _fake_module(
            "memanalysis_api",
            MemoryAnalysisError=error_cls,
            analyze_dump_dir=fakes.analyze_dump_dir,
        )
        _install_core_fakes(monkeypatch, memanalysis_api=memanalysis_api)
        result = runner.invoke(app, ["mem", "analyze", "D:\\dumps\\x", *args])
        return result, fakes

    def test_full_report_rendering_and_json_export(self, monkeypatch, tmp_path: Path) -> None:
        """完整报告：概览/可疑区域表/YARA 命中/文件明细/IOC 汇总/JSON 落盘。"""
        json_out = tmp_path / "nested" / "report.json"
        rules = tmp_path / "rules.yar"
        result, fakes = self._invoke(
            monkeypatch,
            _make_report(),
            "--json",
            str(json_out),
            "--rules",
            str(rules),
            "--top",
            "5",
            "--no-carve",
        )
        assert result.exit_code == 0, result.output
        # 选项透传
        passed = fakes.calls["analyze"]
        assert passed["rules_path"] == rules
        assert passed["top_strings"] == 5
        assert passed["carve"] is False
        # 概览与可疑区域表
        assert "内存取证分析报告" in result.stdout
        assert "可疑区域（注入候选）" in result.stdout
        assert "0x10000" in result.stdout
        # YARA 命中（按文件名分组 + 规则名 + meta JSON）
        assert "YARA 命中: region_0000.bin" in result.stdout
        assert "c2_marker" in result.stdout
        assert '"author": "qa"' in result.stdout
        # 文件明细与全局告警
        assert "region_0000.bin" in result.stdout
        assert "全局告警" in result.stdout
        # IOC 汇总（跨文件去重）
        assert "IOC 汇总" in result.stdout
        assert "c2.evil.top" in result.stdout
        # JSON 报告落盘内容 == to_dict() 输出
        assert "完整报告已写入" in result.stdout
        assert json.loads(json_out.read_text(encoding="utf-8")) == {
            "pid": 1234,
            "total_ioc_count": 1,
        }

    def test_default_options_passthrough(self, monkeypatch) -> None:
        """默认参数：top=20、carve=True、rules_path=None。"""
        result, fakes = self._invoke(monkeypatch, _make_report())
        assert result.exit_code == 0, result.output
        passed = fakes.calls["analyze"]
        assert passed["top_strings"] == 20
        assert passed["carve"] is True
        assert passed["rules_path"] is None

    def test_analysis_error_exits_1(self, monkeypatch) -> None:
        """MemoryAnalysisError → 退出码 1 并提示「分析失败」。"""
        error_cls = type("MemoryAnalysisError", (RuntimeError,), {})
        result, _fakes = self._invoke(
            monkeypatch,
            _make_report(),
            error=error_cls("manifest.json 缺失"),
        )
        assert result.exit_code == 1
        assert "分析失败" in result.stdout
        assert "manifest.json 缺失" in result.stdout


# =============================================================================
# _attach 错误提示
# =============================================================================


class TestAttachErrorHints:
    """_attach 附加失败时的管理员提示语分支。"""

    @staticmethod
    def _make_error(message: str) -> Exception:
        return type("MemoryAccessError", (RuntimeError,), {})(message)

    def _invoke(self, monkeypatch, error: Exception) -> object:
        memory_api = _fake_module(
            "memory_api",
            # 异常类必须与 error 实例同类，except 才能命中
            MemoryAccessError=type(error),
            attach=lambda target: (_ for _ in ()).throw(error),
        )
        _install_core_fakes(monkeypatch, memory_api=memory_api)
        return runner.invoke(app, ["mem", "regions", "target.exe"])

    def test_attach_failure_shows_admin_hint(self, monkeypatch) -> None:
        """「附加进程失败」类错误额外提示需要管理员权限。"""
        result = self._invoke(monkeypatch, self._make_error("附加进程失败: 拒绝访问"))
        assert result.exit_code == 1
        assert "管理员" in result.stdout

    def test_attach_failure_without_admin_hint(self, monkeypatch) -> None:
        """非权限类错误（如进程不存在）不提示管理员。"""
        result = self._invoke(monkeypatch, self._make_error("找不到进程: target.exe"))
        assert result.exit_code == 1
        assert "管理员" not in result.stdout
