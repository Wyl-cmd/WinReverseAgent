"""测试模块：winreverse.core.memanalysis_api

全部基于合成数据，无平台/权限依赖。覆盖：
- entropy 熵计算（空/全零/随机/下采样）
- extract_strings 字符串提取（ASCII / UTF-16LE / 参数校验）
- extract_iocs IOC 提取（URL/IP/域名/邮箱/路径/注册表）
- carve_pe PE 雕刻（合成 PE / 无 PE / 截断 / 落盘）
- analyze_bytes / analyze_dump_file 单文件分析
- analyze_dump_dir 转储目录汇总（manifest 校验 / YARA / 告警路径）
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import struct
from pathlib import Path

import pytest

from winreverse.core import memanalysis_api
from winreverse.core.memanalysis_api import (
    CarvedPE,
    MemoryAnalysisError,
    analyze_bytes,
    analyze_dump_dir,
    analyze_dump_file,
    carve_pe,
    carve_pe_to_files,
    entropy,
    extract_iocs,
    extract_strings,
)

# =============================================================================
# 测试辅助：合成数据构造
# =============================================================================


def _build_fake_pe(
    *,
    machine: int = 0x8664,
    size_of_image: int = 0x2000,
    is_dll: bool = False,
    timestamp: int = 1700000000,
    payload: bytes = b"",
) -> bytes:
    """构造一个仅头部有效、可供雕刻器识别的最小 PE 内存映像。"""
    dos_header = bytearray(0x40)
    dos_header[0:2] = b"MZ"
    # e_lfanew = 0x40
    struct.pack_into("<I", dos_header, 0x3C, 0x40)

    pe_sig = b"PE\x00\x00"
    num_sections = 1
    # 可执行 EXE 常见特征位（0x0102），DLL 时追加 0x2000
    characteristics = 0x0102 | (0x2000 if is_dll else 0x0000)
    coff_header = struct.pack(
        "<HHIIIHH",
        machine,
        num_sections,
        timestamp,
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        0xF0,  # SizeOfOptionalHeader（PE32+ 标准大小）
        characteristics,
    )
    # PE32+ 可选头：magic(2) + 主/次版本(4) + SizeOfCode 等(16) + 入口/代码基(12)
    # + 镜像基址(8) + 节对齐/文件对齐(8) + ... 填充至 56 处写 SizeOfImage
    opt_header = bytearray(0xF0)
    struct.pack_into("<H", opt_header, 0, 0x20B)  # PE32+
    struct.pack_into("<I", opt_header, 56, size_of_image)

    section_table = bytearray(40)  # 单个节表项
    return (
        bytes(dos_header)
        + pe_sig
        + coff_header
        + bytes(opt_header)
        + bytes(section_table)
        + payload
    )


def _make_dump_dir(
    tmp_path: Path,
    *,
    files: dict[str, bytes],
    regions: list[dict[str, object]] | None = None,
    include_manifest: bool = True,
    pid: int = 4242,
) -> Path:
    """构造伪造的转储目录（region bin + manifest.json）。"""
    dump_dir = tmp_path / "dump"
    dump_dir.mkdir()
    region_entries: list[dict[str, object]] = []
    for index, (name, content) in enumerate(files.items()):
        (dump_dir / name).write_bytes(content)
        entry: dict[str, object] = regions[index] if regions else {}
        entry.setdefault("file", name)
        entry.setdefault("sha256", hashlib.sha256(content).hexdigest())
        entry.setdefault("suspicious", False)
        region_entries.append(entry)
    if include_manifest:
        manifest = {
            "schema_version": "1.0",
            "tool": "winreverse-memdump",
            "created_at": "2026-08-29T00:00:00+00:00",
            "pid": pid,
            "regions": region_entries,
        }
        (dump_dir / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
        )
    return dump_dir


# =============================================================================
# entropy 熵计算
# =============================================================================


class TestEntropy:
    """entropy 熵计算测试。"""

    def test_empty_returns_zero(self) -> None:
        """空输入返回 0。"""
        assert entropy(b"") == 0.0

    def test_uniform_returns_zero(self) -> None:
        """单一字节重复，熵为 0。"""
        assert entropy(b"\x00" * 1024) == 0.0

    def test_random_is_high(self) -> None:
        """随机数据熵接近 8（加密/压缩区域特征）。"""
        assert entropy(os.urandom(4096)) > 7.5

    def test_range_bound(self) -> None:
        """熵值不超过 8。"""
        assert entropy(os.urandom(1024 * 1024)) <= 8.0

    def test_large_input_sampled(self) -> None:
        """超过采样上限的大输入可正常计算（走下采样路径）。"""
        value = entropy(os.urandom(6 * 1024 * 1024))
        assert value > 7.5


# =============================================================================
# extract_strings 字符串提取
# =============================================================================


class TestExtractStrings:
    """extract_strings 字符串提取测试。"""

    def test_ascii_string(self) -> None:
        """ASCII 字符串按偏移提取。"""
        data = b"\x00\x00hello world\x00trailing"
        hits = extract_strings(data, min_length=5)
        assert ("hello world", 2, "ascii") in [(h.value, h.offset, h.encoding) for h in hits]

    def test_utf16le_string(self) -> None:
        """UTF-16LE 宽字符串提取（木马 C2 配置常见形态）。"""
        data = b"\x00\x00" + "http://evil.com".encode("utf-16-le") + b"\x00\x00"
        hits = extract_strings(data, min_length=5)
        utf16_hits = [h for h in hits if h.encoding == "utf-16le"]
        assert any(h.value == "http://evil.com" for h in utf16_hits)

    def test_min_length_filter(self) -> None:
        """短于 min_length 的字符串被过滤。"""
        data = b"abc\x00abcdefgh\x00"
        hits = extract_strings(data, min_length=6)
        values = [h.value for h in hits]
        assert "abc" not in values
        assert "abcdefgh" in values

    def test_encodings_subset(self) -> None:
        """仅请求 utf-16le 时不返回 ascii 命中。"""
        # 双 \x00 结尾避免前缀末字符与宽字符意外组成 UTF-16 对
        data = b"prefix\x00\x00" + "wideonedata".encode("utf-16-le")
        hits = extract_strings(data, min_length=5, encodings=("utf-16le",))
        assert hits
        assert all(h.encoding == "utf-16le" for h in hits)
        assert any(h.value == "wideonedata" for h in hits)

    def test_unsupported_encoding_raises(self) -> None:
        """不支持的编码名抛 ValueError。"""
        with pytest.raises(ValueError, match="不支持的编码"):
            extract_strings(b"test", encodings=("gbk",))  # type: ignore[arg-type]

    def test_invalid_min_length_raises(self) -> None:
        """min_length < 1 抛 ValueError。"""
        with pytest.raises(ValueError, match="min_length"):
            extract_strings(b"test", min_length=0)


# =============================================================================
# extract_iocs IOC 提取
# =============================================================================


class TestExtractIocs:
    """extract_iocs IOC 提取测试。"""

    def test_url_and_ip_ascii(self) -> None:
        """ASCII 形态的 URL / IP 提取。"""
        data = b"GET / HTTP/1.1\x00Host: 45.33.32.156\x00"
        iocs = extract_iocs(data)
        by_kind = {h.kind: h.value for h in iocs}
        assert by_kind.get("ip") == "45.33.32.156"

    def test_url_utf16le(self) -> None:
        """UTF-16LE 形态的 URL 提取（配置块常见）。"""
        data = "https://c2.malicious.top/gate.php".encode("utf-16-le")
        iocs = extract_iocs(data)
        urls = [h.value for h in iocs if h.kind == "url"]
        assert "https://c2.malicious.top/gate.php" in urls

    def test_registry_and_filepath(self) -> None:
        """注册表持久化键与落盘路径提取。"""
        data = (
            b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
            b"C:\\Users\\admin\\AppData\\Roaming\\svchost.exe\x00"
        )
        iocs = extract_iocs(data)
        by_kind = {h.kind: h.value for h in iocs}
        assert "registry" in by_kind
        assert "filepath" in by_kind

    def test_domain_and_email(self) -> None:
        """独立域名与邮箱提取。"""
        data = b"contact: attacker@evil-corp.net\x00backup.xn--host.top\x00"
        iocs = extract_iocs(data)
        kinds = {h.kind for h in iocs}
        assert "email" in kinds
        assert "domain" in kinds

    def test_no_false_positive_on_binary(self) -> None:
        """纯二进制噪声不产生 IOC 误报。

        输入固定为「定种子 PRNG 生成的 64KiB 二进制噪声」，不再用 os.urandom：
        IOC 正则是概率匹配，随机样本约 3.4% 会偶然命中弱模式（实测
        B:\\4E / hKU / c@z.FT / dH.me）→ 原用例偶发失败（约每 30 次一次）。
        固定种子消除非确定性；用例语义（纯二进制噪声 → 无 IOC）保持不变。
        """
        noise = random.Random(0).randbytes(64 * 1024)
        assert extract_iocs(noise) == []

    def test_offset_records_position(self) -> None:
        """IOC 记录来源偏移。"""
        data = b"\x00" * 100 + b"visit http://example.com now\x00"
        iocs = extract_iocs(data)
        assert iocs
        assert all(h.offset >= 100 for h in iocs)


# =============================================================================
# carve_pe PE 雕刻
# =============================================================================


class TestCarvePe:
    """carve_pe PE 雕刻测试。"""

    def test_carve_fake_pe(self) -> None:
        """能从任意偏移雕刻出合成 PE，字段正确。"""
        fake_pe = _build_fake_pe(size_of_image=0x2000)
        data = b"\x00" * 0x123 + fake_pe + b"\xcc" * 0x2000
        results = carve_pe(data)
        assert len(results) == 1
        pe = results[0]
        assert pe.offset == 0x123
        assert pe.size == 0x2000
        assert pe.arch == "x64"
        assert pe.is_dll is False
        assert pe.timestamp == 1700000000
        assert pe.truncated is False
        assert pe.sha256 == hashlib.sha256(data[0x123 : 0x123 + 0x2000]).hexdigest()

    def test_carve_dll_flag(self) -> None:
        """DLL 特征位正确识别。"""
        fake_dll = _build_fake_pe(is_dll=True) + b"\x00" * 0x2000
        results = carve_pe(fake_dll)
        assert results[0].is_dll is True

    def test_carve_truncated(self) -> None:
        """SizeOfImage 超出数据边界时标记截断。"""
        fake_pe = _build_fake_pe(size_of_image=0x8000) + b"\xaa" * 0x8000
        truncated_data = fake_pe[:0x500]  # 数据不足 SizeOfImage
        results = carve_pe(truncated_data)
        assert len(results) == 1
        assert results[0].truncated is True
        assert results[0].size == 0x500

    def test_no_pe_returns_empty(self) -> None:
        """无 PE 数据返回空列表。"""
        assert carve_pe(os.urandom(8192)) == []
        assert carve_pe(b"MZ" + os.urandom(4096)) == []  # 仅有 MZ 无有效头

    def test_max_count_limit(self) -> None:
        """max_count 限制返回数量。"""
        fake_pe = _build_fake_pe()
        data = fake_pe * 5
        results = carve_pe(data, max_count=3)
        assert len(results) == 3

    def test_to_dict_json_serializable(self) -> None:
        """CarvedPE.to_dict 可 JSON 序列化。"""
        pe = CarvedPE(offset=0, size=0x1000, machine=0x8664, arch="x64")
        json.dumps(pe.to_dict())

    def test_carve_to_files(self, tmp_path: Path) -> None:
        """carve_pe_to_files 落盘文件名含偏移与架构。"""
        fake_pe = _build_fake_pe()
        data = b"\x00" * 0x10 + fake_pe + b"\x00" * 0x2000
        written = carve_pe_to_files(data, tmp_path / "out")
        assert len(written) == 1
        assert written[0].name == "carved_0x10_x64.bin"
        assert written[0].read_bytes()[:2] == b"MZ"


# =============================================================================
# analyze_bytes / analyze_dump_file 单文件分析
# =============================================================================


class TestAnalyzeBytes:
    """analyze_bytes 单文件分析测试。"""

    def test_full_analysis(self) -> None:
        """合成木马内存片段：字符串 + IOC + PE + 高熵段一次出齐。"""
        fake_pe = _build_fake_pe(size_of_image=0x400)
        data = (
            b"User-Agent: Mozilla/5.0\x00"
            b"192.168.1.7:8080\x00"
            + os.urandom(2048)  # 高熵（加密配置/载荷）
            + fake_pe
            + b"\x00" * 0x400  # 满足 SizeOfImage，保证 PE 可完整雕刻
        )
        analysis = analyze_bytes(data, file_name="region.bin")
        assert analysis.size == len(data)
        assert analysis.sha256 == hashlib.sha256(data).hexdigest()
        assert analysis.entropy > 5.0
        assert analysis.string_count > 0
        assert any("User-Agent" in s for s in analysis.top_strings)
        kinds = {h.kind for h in analysis.iocs}
        assert "ip" in kinds
        assert len(analysis.carved_pes) == 1
        json.dumps(analysis.to_dict())

    def test_carve_disabled(self) -> None:
        """carve=False 时不执行 PE 雕刻。"""
        fake_pe = _build_fake_pe()
        analysis = analyze_bytes(fake_pe, carve=False)
        assert analysis.carved_pes == []


class TestAnalyzeDumpFile:
    """analyze_dump_file 单文件分析测试。"""

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        """文件不存在抛 MemoryAnalysisError。"""
        with pytest.raises(MemoryAnalysisError, match="不存在"):
            analyze_dump_file(tmp_path / "nope.bin")

    def test_analyze_bin_file(self, tmp_path: Path) -> None:
        """分析落盘的转储文件。"""
        dump_file = tmp_path / "region_0000.bin"
        dump_file.write_bytes(b"secret_payload_string\x00" + os.urandom(1024))
        analysis = analyze_dump_file(dump_file)
        assert analysis.file == "region_0000.bin"
        assert analysis.string_count >= 1


# =============================================================================
# analyze_dump_dir 转储目录汇总
# =============================================================================


class TestAnalyzeDumpDir:
    """analyze_dump_dir 汇总分析测试。"""

    def test_basic_report(self, tmp_path: Path) -> None:
        """正常转储目录：逐文件分析 + 汇总统计 + 可疑区域透传。"""
        content_a = b"malicious_payload_marker\x00" + os.urandom(512)
        content_b = _build_fake_pe() + b"\x00" * 0x2000 + b"ping 1.2.3.4\x00"
        dump_dir = _make_dump_dir(
            tmp_path,
            files={
                "region_0000_0000.bin": content_a,
                "region_0001_1000.bin": content_b,
            },
            regions=[
                {"suspicious": True, "protect": "RWX", "type": "private"},
                {"suspicious": False},
            ],
        )
        report = analyze_dump_dir(dump_dir)
        assert report.pid == 4242
        assert len(report.files) == 2
        assert report.total_bytes == len(content_a) + len(content_b)
        assert len(report.suspicious_regions) == 1
        assert report.suspicious_regions[0]["protect"] == "RWX"
        assert any("malicious_payload_marker" in f.top_strings for f in report.files)
        carved = [pe for f in report.files for pe in f.carved_pes]
        assert len(carved) == 1
        assert report.total_carved_pe_count == 1
        assert report.total_ioc_count >= 1  # 1.2.3.4
        json.dumps(report.to_dict())

    def test_missing_dir_raises(self, tmp_path: Path) -> None:
        """目录不存在抛 MemoryAnalysisError。"""
        with pytest.raises(MemoryAnalysisError, match="转储目录不存在"):
            analyze_dump_dir(tmp_path / "nope")

    def test_missing_manifest_raises(self, tmp_path: Path) -> None:
        """manifest 缺失抛 MemoryAnalysisError（提示先用 memory.dump）。"""
        dump_dir = tmp_path / "dump"
        dump_dir.mkdir()
        with pytest.raises(MemoryAnalysisError, match=r"manifest\.json 缺失"):
            analyze_dump_dir(dump_dir)

    def test_broken_manifest_raises(self, tmp_path: Path) -> None:
        """manifest 格式错误抛 MemoryAnalysisError。"""
        dump_dir = tmp_path / "dump"
        dump_dir.mkdir()
        (dump_dir / "manifest.json").write_text("{broken", encoding="utf-8")
        with pytest.raises(MemoryAnalysisError, match="解析失败"):
            analyze_dump_dir(dump_dir)

    def test_missing_region_file_warns(self, tmp_path: Path) -> None:
        """manifest 登记的区域文件缺失时产出告警而非失败。"""
        dump_dir = _make_dump_dir(
            tmp_path,
            files={"region_0000.bin": b"data\x00string"},
            regions=[{"file": "region_9999_missing.bin", "sha256": "", "suspicious": False}],
        )
        report = analyze_dump_dir(dump_dir)
        assert report.files == []
        assert any("缺失" in w for w in report.warnings)

    def test_sha256_mismatch_warns(self, tmp_path: Path) -> None:
        """区域文件被篡改时 SHA256 对账告警。"""
        content = b"original\x00contentstring"
        dump_dir = _make_dump_dir(
            tmp_path,
            files={"region_0000.bin": content},
            regions=[{"sha256": "0" * 64, "suspicious": False}],
        )
        report = analyze_dump_dir(dump_dir)
        assert report.files
        assert any("SHA256" in w for w in report.files[0].warnings)

    def test_yara_rule_source_scan(self, tmp_path: Path) -> None:
        """传入 YARA 规则源码可命中转储内容。"""
        content = b"MALICIOUS_PAYLOAD_STRING\x00padding"
        dump_dir = _make_dump_dir(tmp_path, files={"region_0000.bin": content})
        rule = 'rule test_family { strings: $a = "MALICIOUS_PAYLOAD_STRING" ascii condition: $a }'
        report = analyze_dump_dir(dump_dir, rules_source=rule)
        assert "region_0000.bin" in report.yara_matches
        assert report.yara_matches["region_0000.bin"][0].rule == "test_family"

    def test_yara_scan_error_becomes_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """单文件 YARA 扫描失败转为告警，不中断整体分析。"""
        dump_dir = _make_dump_dir(tmp_path, files={"region_0000.bin": b"abc\x00stringdata"})
        rule = "rule always_hit { condition: true }"

        def _boom(rules: object, path: object) -> list[object]:
            raise RuntimeError("模拟扫描失败")

        monkeypatch.setattr(memanalysis_api, "scan_file", _boom)
        report = analyze_dump_dir(dump_dir, rules_source=rule)
        assert any("YARA 扫描失败" in w for w in report.warnings)
