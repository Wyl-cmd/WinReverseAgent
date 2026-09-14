"""测试模块：winreverse.core.memanalysis_api（增量缺口补充）。

覆盖点：_parse_pe_header 各早退校验分支、carve_pe min_size/SizeOfImage 回退、
analyze_dump_dir manifest 形态校验（顶层非字典 / regions 非列表 / region 非字典 /
空文件名）、analyze_bytes top_strings 截断去重、数据类 to_dict 序列化。

平台口径：本模块经 yara_api 引用 yara（Windows 实机依赖），Linux 本机
collection error = 基线接受态，用例在 Windows 实机流水线实跑回填。
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest

from winreverse.core.memanalysis_api import (
    CarvedPE,
    FileAnalysis,
    IocHit,
    MemoryAnalysisError,
    StringHit,
    analyze_bytes,
    analyze_dump_dir,
    carve_pe,
    entropy,
    extract_strings,
)
from winreverse.core.yara_api import YaraMatch

# =============================================================================
# 测试辅助
# =============================================================================


def _mz_buffer(total: int, lfanew: int) -> bytearray:
    """构造带 MZ 签名与指定 e_lfanew 的缓冲区。"""
    buf = bytearray(total)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, lfanew)
    return buf


def _make_dump_dir(
    tmp_path: Path,
    files: dict[str, bytes],
    regions: list[object],
    *,
    manifest: object | None = None,
) -> Path:
    """构造伪造转储目录；manifest 显式传入时可注入非法形态。"""
    dump_dir = tmp_path / "dump"
    dump_dir.mkdir()
    for name, content in files.items():
        (dump_dir / name).write_bytes(content)
    if manifest is None:
        manifest = {"pid": 1, "created_at": "t", "regions": regions}
    (dump_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
    )
    return dump_dir


# =============================================================================
# _parse_pe_header 校验分支（经 carve_pe 间接驱动）
# =============================================================================


class TestParsePeHeaderRejects:
    """PE 头各校验失败分支均返回空列表而非抛异常。"""

    def test_mz_at_end_of_data(self) -> None:
        """MZ 位于数据末尾、DOS 头不完整时跳过。"""
        assert carve_pe(b"\x00" * 0x3F + b"MZ") == []

    def test_lfanew_too_small(self) -> None:
        """e_lfanew < 0x40 视为无效 PE。"""
        assert carve_pe(bytes(_mz_buffer(0x80, 0x20))) == []

    def test_lfanew_beyond_limit(self) -> None:
        """e_lfanew 超过 0x1000 上限视为无效 PE。"""
        assert carve_pe(bytes(_mz_buffer(0x80, 0x2000))) == []

    def test_pe_signature_mismatch(self) -> None:
        """e_lfanew 处不是 PE\\x00\\x00 签名时跳过。"""
        buf = _mz_buffer(0x80, 0x40)
        buf[0x40:0x44] = b"NE\x00\x00"
        assert carve_pe(bytes(buf)) == []

    def test_pe_signature_area_truncated(self) -> None:
        """PE 签名 + COFF 头超出数据末尾时跳过。"""
        assert carve_pe(bytes(_mz_buffer(0x50, 0x40))) == []

    def test_sizeof_opt_header_too_small(self) -> None:
        """SizeOfOptionalHeader < 2 视为无效 PE。"""
        buf = _mz_buffer(0x58, 0x40)
        buf[0x40:0x44] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", buf, 0x44, 0x8664, 1, 0, 0, 0, 0, 0x0102)
        assert carve_pe(bytes(buf)) == []

    def test_opt_header_extends_past_data(self) -> None:
        """可选头声明大小超出数据末尾时跳过。"""
        buf = _mz_buffer(0x58, 0x40)
        buf[0x40:0x44] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", buf, 0x44, 0x8664, 1, 0, 0, 0, 0xF0, 0x0102)
        assert carve_pe(bytes(buf)) == []

    def test_opt_magic_invalid(self) -> None:
        """可选头 magic 非 PE32/PE32+（如 ROM 镜像 0x107）时跳过。"""
        buf = _mz_buffer(0x60, 0x40)
        buf[0x40:0x44] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", buf, 0x44, 0x8664, 1, 0, 0, 0, 8, 0x0102)
        struct.pack_into("<H", buf, 0x58, 0x107)
        assert carve_pe(bytes(buf)) == []

    def test_sizeof_image_field_missing_falls_back(self) -> None:
        """可选头在 SizeOfImage 字段前截断时按数据边界回退雕刻。"""
        buf = _mz_buffer(0x90, 0x40)
        buf[0x40:0x44] = b"PE\x00\x00"
        # SizeOfOptionalHeader = 0x38（56 字节，恰好不含 SizeOfImage 字段）
        struct.pack_into("<HHIIIHH", buf, 0x44, 0x8664, 1, 0, 0, 0, 0x38, 0x0102)
        struct.pack_into("<H", buf, 0x58, 0x20B)
        results = carve_pe(bytes(buf), min_size=0x10)
        assert len(results) == 1
        assert results[0].size == 0x90
        assert results[0].size_of_image == 0
        assert results[0].truncated is False

    def test_min_size_filter(self) -> None:
        """有效 PE 但雕刻大小低于 min_size 时被过滤。"""
        buf = _mz_buffer(0x80, 0x40)
        buf[0x40:0x44] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", buf, 0x44, 0x8664, 1, 0, 0, 0, 8, 0x0102)
        struct.pack_into("<H", buf, 0x58, 0x20B)
        assert carve_pe(bytes(buf), min_size=0x400) == []


# =============================================================================
# manifest 形态校验
# =============================================================================


class TestAnalyzeDumpDirManifestShapes:
    """analyze_dump_dir 对 manifest 非常规形态的处理。"""

    def test_manifest_top_level_not_dict(self, tmp_path: Path) -> None:
        """manifest 顶层为 JSON 数组时报「顶层应为字典」。"""
        dump_dir = tmp_path / "dump"
        dump_dir.mkdir()
        (dump_dir / "manifest.json").write_text("[]", encoding="utf-8")
        with pytest.raises(MemoryAnalysisError, match="顶层应为字典"):
            analyze_dump_dir(dump_dir)

    def test_regions_not_a_list(self, tmp_path: Path) -> None:
        """manifest.regions 非列表时报「regions 字段应为列表」。"""
        dump_dir = _make_dump_dir(
            tmp_path,
            files={"r0.bin": b"marker_data_string"},
            regions=[],
            manifest={"regions": "nope"},
        )
        with pytest.raises(MemoryAnalysisError, match="regions 字段应为列表"):
            analyze_dump_dir(dump_dir)

    def test_region_entry_not_dict_skipped(self, tmp_path: Path) -> None:
        """regions 中非字典条目被跳过，不影响其余区域分析。"""
        content = b"marker_one_string"
        dump_dir = _make_dump_dir(
            tmp_path,
            files={"r0.bin": content},
            regions=["junk", {"file": "r0.bin", "sha256": hashlib.sha256(content).hexdigest()}],
        )
        report = analyze_dump_dir(dump_dir)
        assert len(report.files) == 1
        assert report.files[0].file == "r0.bin"
        assert report.warnings == []

    def test_region_empty_filename_skipped(self, tmp_path: Path) -> None:
        """region 缺少 file 字段（空文件名）时静默跳过、不产出告警。"""
        dump_dir = _make_dump_dir(
            tmp_path, files={"r0.bin": b"x"}, regions=[{"file": "", "suspicious": False}]
        )
        report = analyze_dump_dir(dump_dir)
        assert report.files == []
        assert report.warnings == []


# =============================================================================
# analyze_bytes / 数据类序列化
# =============================================================================


class TestAnalyzeBytesExtras:
    """analyze_bytes 代表性字符串截断去重等补充。"""

    def test_top_strings_cap_and_dedup(self) -> None:
        """top_strings 按长度降序截断且去重。"""
        data = b"AAAAA\x00BBBBBB\x00AAAAA\x00"
        analysis = analyze_bytes(data, top_strings=2)
        assert analysis.top_strings == ["BBBBBB", "AAAAA"]
        assert analysis.string_count == 3  # 两次 AAAAA 均计入字符串总数

    def test_min_string_length_one(self) -> None:
        """min_length=1 边界：单字符 run 也被提取。

        数据不含 \\x00 分隔，避免「字符+\\x00」被同时判为长度 1 的
        UTF-16LE run（模块真实行为，见 extract_strings 实现）。
        """
        hits = extract_strings(b"ab!", min_length=1)
        assert [(h.value, h.offset, h.encoding) for h in hits] == [("ab!", 0, "ascii")]

    def test_string_hit_to_dict(self) -> None:
        """StringHit.to_dict 字段完整。"""
        assert StringHit(offset=1, encoding="ascii", value="ab").to_dict() == {
            "offset": 1,
            "encoding": "ascii",
            "value": "ab",
        }

    def test_ioc_hit_to_dict(self) -> None:
        """IocHit.to_dict 字段完整。"""
        assert IocHit(kind="ip", value="1.2.3.4", offset=7).to_dict() == {
            "kind": "ip",
            "value": "1.2.3.4",
            "offset": 7,
        }

    def test_file_analysis_to_dict_empty(self) -> None:
        """FileAnalysis 空结果 to_dict 可 JSON 序列化且熵值四舍五入。"""
        d = FileAnalysis(file="x.bin", entropy=1.23456).to_dict()
        assert d["entropy"] == 1.235
        assert d["iocs"] == {}
        json.dumps(d)

    def test_report_to_dict_with_yara_matches(self) -> None:
        """DumpAnalysisReport 含 YARA 命中时 to_dict 可 JSON 序列化。"""
        from winreverse.core.memanalysis_api import DumpAnalysisReport

        report = DumpAnalysisReport(
            dump_dir="d",
            yara_matches={
                "a.bin": [YaraMatch(rule="r", namespace="n", tags=["t"], meta={"fam": "x"})]
            },
        )
        d = report.to_dict()
        assert d["total_ioc_count"] == 0
        assert d["yara_matches"]["a.bin"][0]["rule"] == "r"
        json.dumps(d)


class TestEntropyExtras:
    """entropy 补充：单字节输入。"""

    def test_single_byte(self) -> None:
        """单字节输入熵为 0（只有一个符号）。"""
        assert entropy(b"\x41") == 0.0


# 保持 CarvedPE 导入被引用（缺口用例集中断言其字段语义）
def test_carved_pe_minimal_to_dict() -> None:
    """CarvedPE 默认字段 to_dict 可 JSON 序列化。"""
    d = CarvedPE(offset=0, size=0x1000).to_dict()
    assert d["machine"] == "0x0000"
    assert d["truncated"] is False
    json.dumps(d)
