"""winreverse.core.memanalysis_api — 内存取证分析层（内存取证第二阶段）。

对内存转储文件（memdump_api 的产物）或任意内存快照字节做静态取证分析：
1. 熵计算（识别加密 / 压缩 / 加壳区域）
2. 字符串提取（ASCII + UTF-16LE）
3. IOC 提取（URL / IP / 域名 / 邮箱 / Windows 路径 / 注册表键）
4. PE 雕刻（从内存快照中定位并提取 PE 文件，含内存映像布局）
5. 转储目录一键分析（读 manifest.json → 逐文件分析 → 汇总报告）

设计原则：
- 纯数据分析，不依赖 Windows API，输入就是 bytes / 文件路径，
  完全脱离进程状态，单测友好
- PE 雕刻采用手工 DOS/NT 头解析（内存中的 PE 节区为虚拟布局，
  pefile 按 raw 布局解析常失败），仅在整体有效时才产出结果
- 所有输出均为 JSON 兼容 dict，供工具层 / 报告直接序列化

参考：实施方案 §4.2、§10（木马行为分析预留）
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from winreverse.core.yara_api import YaraMatch, compile_file, compile_source, scan_file

# =============================================================================
# 常量与正则
# =============================================================================

# ASCII 可打印字符运行（长度下限动态填入）
_ASCII_RUN_TMPL = rb"[\x20-\x7e]{%d,}"
# UTF-16LE：ASCII 范围字符 + 0x00 高字节（木马最常见宽字符串形态）
_UTF16LE_RUN_TMPL = rb"(?:[\x20-\x7e]\x00){%d,}"

_DEFAULT_MIN_STRING_LENGTH = 5

# 可选头 magic
_PE_MAGIC_PE32 = 0x10B
_PE_MAGIC_PE32PLUS = 0x20B

# 机器类型 → 架构名
_MACHINE_NAMES: dict[int, str] = {
    0x014C: "i386",
    0x01C0: "arm",
    0x01C4: "armnt",
    0x8664: "x64",
    0xAA64: "arm64",
}

# COFF Characteristics
_IMAGE_FILE_DLL = 0x2000

# DOS 头校验上限：e_lfanew 合理范围（标准对齐下 ≤ 0x400，放宽到 0x1000 兼容手工构 PE）
_MAX_LFANEW = 0x1000

# IOC 正则（作用于提取出的字符串文本，避免二进制噪声误报）
_IOC_PATTERNS: dict[str, re.Pattern[str]] = {
    "url": re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"'<>\\]{4,}"),
    "ip": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}" r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    ),
    # 磁盘路径：字符类**必须**允许反斜杠（2026-09-15 真机实测：原实现把 `\x5c` 也排除，
    # 导致 `C:\work\x\y.cmd` 只截出 `C:\work`，多级路径 IOC 全部退化成 `<盘符>:\<首段>`）。
    # UNC 路径：原 `\b\\\\...` 的 `\b` 要求位置两侧之一为单词字符，而 UNC 前面总是
    # 空白/引号（非单词字符）→ 实际永不匹配；改用 `\\` 直接起头。
    "filepath": re.compile(
        r"(?i)\b[A-Za-z]:\\[^\s\"'<>|*?]{1,120}"
        r"|\\\\[A-Za-z0-9_.-]+\\[^\s\"'<>|*?]{1,120}"
    ),
    # 注册表键：短别名（HKLM/HKCU/HKCR/HKU）必须带子键路径（\\子键），
    # 否则纯随机字符串里的 \"hKU\" 之类 3 字母噪声会被误判为注册表 IOC。
    # HKEY_* 全名较长、误报概率极低，保留可选路径。
    "registry": re.compile(
        r"(?i)\bHKEY_[A-Z_]+(?:\\[^\s\"']{1,120})?" r"|\b(?:HKLM|HKCU|HKCR|HKU)\\[^\s\"']{1,120}"
    ),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "domain": re.compile(
        r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"(?:com|net|org|cn|io|ru|info|biz|top|xyz|cc|su|tk|me|gov|edu|online|site|club)\b"
    ),
}

# 熵计算输入超过该大小时均匀下采样（保持结果稳定、控制耗时）
_ENTROPY_SAMPLE_LIMIT = 4 * 1024 * 1024


# =============================================================================
# 数据模型
# =============================================================================


@dataclass(frozen=True)
class StringHit:
    """提取到的字符串。

    Attributes:
        offset: 在数据中的偏移（字节）
        encoding: 提取编码（ascii / utf-16le）
        value: 解码后的字符串
    """

    offset: int
    encoding: str
    value: str

    def to_dict(self) -> dict[str, Any]:
        """转为 JSON 兼容字典。"""
        return {"offset": self.offset, "encoding": self.encoding, "value": self.value}


@dataclass(frozen=True)
class IocHit:
    """提取到的 IOC（Indicator of Compromise）。

    Attributes:
        kind: IOC 类型（url / ip / domain / email / filepath / registry）
        value: IOC 内容
        offset: 所在偏移
    """

    kind: str
    value: str
    offset: int

    def to_dict(self) -> dict[str, Any]:
        """转为 JSON 兼容字典。"""
        return {"kind": self.kind, "value": self.value, "offset": self.offset}


@dataclass(frozen=True)
class CarvedPE:
    """从内存快照中雕刻出的 PE 文件。

    Attributes:
        offset: PE 在数据中的起始偏移（'MZ' 位置）
        size: 雕刻大小（字节，按 SizeOfImage 估算，受数据边界截断）
        machine: 机器类型原始值
        arch: 架构名（x64 / i386 / arm64 …）
        timestamp: 编译时间戳（Unix 秒，未知为 0）
        is_dll: 是否为 DLL
        size_of_image: PE 头声明的映像大小
        sha256: 雕刻内容 SHA256
        truncated: 雕刻内容是否被数据边界截断
    """

    offset: int
    size: int
    machine: int = 0
    arch: str = ""
    timestamp: int = 0
    is_dll: bool = False
    size_of_image: int = 0
    sha256: str = ""
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """转为 JSON 兼容字典。"""
        return {
            "offset": self.offset,
            "size": self.size,
            "machine": f"0x{self.machine:04X}",
            "arch": self.arch,
            "timestamp": self.timestamp,
            "is_dll": self.is_dll,
            "size_of_image": self.size_of_image,
            "sha256": self.sha256,
            "truncated": self.truncated,
        }


@dataclass
class FileAnalysis:
    """单个转储文件的分析结果。

    Attributes:
        file: 文件名（相对转储目录）
        size: 文件大小（字节）
        sha256: 文件 SHA256
        entropy: 香农熵（0-8；>7.2 通常意味着加密/压缩/加壳）
        string_count: 提取到的字符串总数
        top_strings: 按长度排序的代表性字符串
        iocs: IOC 命中（kind → IocHit 列表）
        carved_pes: 雕刻出的 PE 列表
        warnings: 分析过程中的告警
    """

    file: str
    size: int = 0
    sha256: str = ""
    entropy: float = 0.0
    string_count: int = 0
    top_strings: list[str] = field(default_factory=list)
    iocs: list[IocHit] = field(default_factory=list)
    carved_pes: list[CarvedPE] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """转为 JSON 兼容字典。"""
        return {
            "file": self.file,
            "size": self.size,
            "sha256": self.sha256,
            "entropy": round(self.entropy, 3),
            "string_count": self.string_count,
            "top_strings": self.top_strings,
            "iocs": {
                kind: [h.to_dict() for h in hits] for kind, hits in _group_iocs(self.iocs).items()
            },
            "carved_pes": [pe.to_dict() for pe in self.carved_pes],
            "warnings": self.warnings,
        }


@dataclass
class DumpAnalysisReport:
    """整个转储目录的汇总分析报告。

    Attributes:
        dump_dir: 转储目录路径
        pid: 转储时的目标进程 ID（manifest 缺失时为 None）
        created_at: 转储时间（manifest 记录）
        files: 各文件分析结果
        yara_matches: YARA 规则命中（按文件名分组）
        suspicious_regions: manifest 中标记为可疑的区域条目
        total_bytes: 分析的总字节数
        warnings: 全局告警
    """

    dump_dir: str
    pid: int | None = None
    created_at: str = ""
    files: list[FileAnalysis] = field(default_factory=list)
    yara_matches: dict[str, list[YaraMatch]] = field(default_factory=dict)
    suspicious_regions: list[dict[str, Any]] = field(default_factory=list)
    total_bytes: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def total_ioc_count(self) -> int:
        """全部文件的 IOC 命中总数。"""
        return sum(len(f.iocs) for f in self.files)

    @property
    def total_carved_pe_count(self) -> int:
        """全部文件雕刻出的 PE 总数。"""
        return sum(len(f.carved_pes) for f in self.files)

    def to_dict(self) -> dict[str, Any]:
        """转为 JSON 兼容字典（可直接 json.dump 落盘为报告）。"""
        return {
            "dump_dir": self.dump_dir,
            "pid": self.pid,
            "created_at": self.created_at,
            "total_bytes": self.total_bytes,
            "total_ioc_count": self.total_ioc_count,
            "total_carved_pe_count": self.total_carved_pe_count,
            "files": [f.to_dict() for f in self.files],
            "yara_matches": {
                name: [
                    {
                        "rule": m.rule,
                        "tags": m.tags,
                        "meta": m.meta,
                    }
                    for m in matches
                ]
                for name, matches in self.yara_matches.items()
            },
            "suspicious_regions": self.suspicious_regions,
            "warnings": self.warnings,
        }


class MemoryAnalysisError(RuntimeError):
    """内存分析失败的统一异常（文件缺失 / manifest 格式错误等）。"""


# =============================================================================
# 基础分析原语
# =============================================================================


def entropy(data: bytes) -> float:
    """计算字节序列的香农熵（单位：bit/byte，范围 0-8）。

    输入超过 4MB 时均匀下采样（隔 len/n 取一个字节），保证耗时可控；
    下采样对熵值的影响通常 < 0.01，满足区域分级用途。

    Args:
        data: 字节序列

    Returns:
        香农熵值（空输入返回 0.0）
    """
    if not data:
        return 0.0
    if len(data) > _ENTROPY_SAMPLE_LIMIT:
        step = len(data) // _ENTROPY_SAMPLE_LIMIT
        data = data[::step]
    counts = Counter(data)
    total = len(data)
    result = 0.0
    for count in counts.values():
        p = count / total
        result -= p * math.log2(p)
    return result


def extract_strings(
    data: bytes,
    min_length: int = _DEFAULT_MIN_STRING_LENGTH,
    encodings: tuple[str, ...] = ("ascii", "utf-16le"),
) -> list[StringHit]:
    """从字节序列中提取可读字符串。

    Args:
        data: 待提取的字节序列
        min_length: 最小字符串长度（默认 5）
        encodings: 提取的编码（ascii / utf-16le 子集）

    Returns:
        StringHit 列表（按偏移升序；同一偏移两种编码同时命中时保留 ascii）

    Raises:
        ValueError: encodings 含不支持的编码名
    """
    unsupported = set(encodings) - {"ascii", "utf-16le"}
    if unsupported:
        raise ValueError(f"不支持的编码: {sorted(unsupported)}（支持: ascii / utf-16le）")
    if min_length < 1:
        raise ValueError(f"min_length 必须 >= 1，实际为 {min_length}")

    hits: list[StringHit] = []
    if "ascii" in encodings:
        for m in re.finditer(_ASCII_RUN_TMPL % min_length, data):
            hits.append(
                StringHit(offset=m.start(), encoding="ascii", value=m.group().decode("ascii"))
            )
    if "utf-16le" in encodings:
        pattern = re.compile(_UTF16LE_RUN_TMPL % min_length)
        for m in pattern.finditer(data):
            value = m.group().decode("utf-16le")
            hits.append(StringHit(offset=m.start(), encoding="utf-16le", value=value))
    hits.sort(key=lambda h: (h.offset, h.encoding))
    return hits


def extract_iocs(
    data: bytes,
    *,
    min_length: int = _DEFAULT_MIN_STRING_LENGTH,
) -> list[IocHit]:
    """从字节序列中提取 IOC（基于字符串提取 + 规则匹配）。

    先提取 ASCII / UTF-16LE 字符串，再对每个字符串跑 IOC 正则，
    避免直接对二进制数据做正则产生海量误报。

    Args:
        data: 待分析的字节序列
        min_length: 字符串最小长度

    Returns:
        IocHit 列表（按偏移升序）
    """
    iocs: list[IocHit] = []
    seen: set[tuple[str, str, int]] = set()
    for hit in extract_strings(data, min_length=min_length):
        for kind, pattern in _IOC_PATTERNS.items():
            for m in pattern.finditer(hit.value):
                value = m.group().rstrip(".,;:)]}\"'")
                key = (kind, value, hit.offset)
                if key in seen:
                    continue
                seen.add(key)
                iocs.append(IocHit(kind=kind, value=value, offset=hit.offset))
    iocs.sort(key=lambda h: (h.offset, h.kind))
    return iocs


def extract_iocs_from_text(text: str) -> list[IocHit]:
    """从文本（命令行/日志/行为事件描述）中提取 IOC。

    行为监控层复用本函数：把进程命令行、网络远端地址等拼接为文本后
    提取 IOC，与内存转储的提取规则完全一致。

    Args:
        text: 待提取的文本

    Returns:
        IocHit 列表（offset 为文本内字符偏移）
    """
    iocs: list[IocHit] = []
    seen: set[tuple[str, str, int]] = set()
    for kind, pattern in _IOC_PATTERNS.items():
        for m in pattern.finditer(text):
            value = m.group().rstrip(".,;:)]}\"'")
            key = (kind, value, m.start())
            if key in seen:
                continue
            seen.add(key)
            iocs.append(IocHit(kind=kind, value=value, offset=m.start()))
    return iocs


def _group_iocs(iocs: list[IocHit]) -> dict[str, list[IocHit]]:
    """按 kind 分组 IOC（保持原顺序）。"""
    grouped: dict[str, list[IocHit]] = {}
    for hit in iocs:
        grouped.setdefault(hit.kind, []).append(hit)
    return grouped


# =============================================================================
# PE 雕刻
# =============================================================================


def _parse_pe_header(data: bytes, offset: int) -> dict[str, Any] | None:
    """解析 data[offset:] 处的 PE 头（手工 DOS/NT 头解析）。

    Returns:
        解析出的头字段字典；不是有效 PE 返回 None
    """
    if offset + 0x40 > len(data):
        return None
    if data[offset : offset + 2] != b"MZ":
        return None
    # DOS 头：e_lfanew 位于 0x3C
    (e_lfanew,) = struct.unpack_from("<I", data, offset + 0x3C)
    if e_lfanew < 0x40 or e_lfanew > _MAX_LFANEW:
        return None
    pe_sig_offset = offset + e_lfanew
    if pe_sig_offset + 24 > len(data):
        return None
    if data[pe_sig_offset : pe_sig_offset + 4] != b"PE\x00\x00":
        return None
    # COFF 头（PE 签名后 20 字节）
    (
        machine,
        num_sections,
        timestamp,
        _ptr_symtab,
        _num_symbols,
        size_opt_header,
        characteristics,
    ) = struct.unpack_from("<HHIIIHH", data, pe_sig_offset + 4)
    coff_end = pe_sig_offset + 24
    if size_opt_header < 2 or coff_end + size_opt_header > len(data):
        return None
    (opt_magic,) = struct.unpack_from("<H", data, coff_end)
    if opt_magic not in (_PE_MAGIC_PE32, _PE_MAGIC_PE32PLUS):
        return None
    # SizeOfImage 在可选头偏移 56 处（PE32 与 PE32+ 布局一致）
    size_of_image_offset = coff_end + 56
    size_of_image = 0
    if size_of_image_offset + 4 <= len(data):
        (size_of_image,) = struct.unpack_from("<I", data, size_of_image_offset)
    return {
        "machine": machine,
        "num_sections": num_sections,
        "timestamp": timestamp,
        "characteristics": characteristics,
        "opt_magic": opt_magic,
        "size_of_image": size_of_image,
        "opt_header_size": size_opt_header,
    }


def carve_pe(
    data: bytes,
    *,
    max_count: int = 32,
    min_size: int = 0x400,
) -> list[CarvedPE]:
    """从内存快照字节中雕刻（carve）PE 文件。

    扫描 'MZ' 签名并做完整头校验（e_lfanew → PE 签名 → 可选头 magic），
    按内存映像布局以 SizeOfImage 估算雕刻大小。

    Args:
        data: 待扫描的字节序列
        max_count: 最多返回的 PE 数量
        min_size: 最小雕刻大小（过滤尾部数据不足的残片）

    Returns:
        CarvedPE 列表（按偏移升序）
    """
    results: list[CarvedPE] = []
    search_from = 0
    while len(results) < max_count:
        mz_offset = data.find(b"MZ", search_from)
        if mz_offset < 0:
            break
        search_from = mz_offset + 1
        header = _parse_pe_header(data, mz_offset)
        if header is None:
            continue
        size_of_image = header["size_of_image"]
        available = len(data) - mz_offset
        # 雕刻大小：优先 SizeOfImage（内存映像），异常时退回数据边界
        carve_size = size_of_image if 0 < size_of_image <= available else available
        if carve_size < min_size:
            continue
        carved = data[mz_offset : mz_offset + carve_size]
        results.append(
            CarvedPE(
                offset=mz_offset,
                size=carve_size,
                machine=header["machine"],
                arch=_MACHINE_NAMES.get(header["machine"], f"0x{header['machine']:04X}"),
                timestamp=header["timestamp"],
                is_dll=bool(header["characteristics"] & _IMAGE_FILE_DLL),
                size_of_image=size_of_image,
                sha256=hashlib.sha256(carved).hexdigest(),
                truncated=carve_size < size_of_image,
            )
        )
    return results


def carve_pe_to_files(
    data: bytes,
    output_dir: str | Path,
    *,
    max_count: int = 32,
    min_size: int = 0x400,
) -> list[Path]:
    """雕刻 PE 并落盘为可独立分析的 .bin 文件。

    文件命名：carved_0xOFFSET_ARCH.bin

    Args:
        data: 待扫描的字节序列
        output_dir: 输出目录（不存在则创建）
        max_count: 最多雕刻数量
        min_size: 最小雕刻大小

    Returns:
        写入的文件路径列表
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for pe in carve_pe(data, max_count=max_count, min_size=min_size):
        content = data[pe.offset : pe.offset + pe.size]
        file_path = out / f"carved_0x{pe.offset:X}_{pe.arch or 'unknown'}.bin"
        file_path.write_bytes(content)
        written.append(file_path)
    return written


# =============================================================================
# 转储文件 / 目录分析
# =============================================================================


def analyze_bytes(
    data: bytes,
    *,
    file_name: str = "<memory>",
    min_string_length: int = _DEFAULT_MIN_STRING_LENGTH,
    top_strings: int = 20,
    carve: bool = True,
    max_carve: int = 16,
) -> FileAnalysis:
    """分析一段内存快照字节（字符串 / IOC / 熵 / PE 雕刻）。

    Args:
        data: 内存快照字节
        file_name: 展示用文件名
        min_string_length: 字符串最小长度
        top_strings: 报告中保留的代表性字符串数量
        carve: 是否执行 PE 雕刻
        max_carve: 最多雕刻数量

    Returns:
        FileAnalysis 分析结果
    """
    analysis = FileAnalysis(
        file=file_name,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        entropy=entropy(data),
    )
    hits = extract_strings(data, min_length=min_string_length)
    analysis.string_count = len(hits)
    # 代表性字符串：按长度降序取前 N（长字符串信息量更高），去重
    seen: set[str] = set()
    for hit in sorted(hits, key=lambda h: len(h.value), reverse=True):
        if hit.value in seen:
            continue
        seen.add(hit.value)
        analysis.top_strings.append(hit.value)
        if len(analysis.top_strings) >= top_strings:
            break
    analysis.iocs = extract_iocs(data, min_length=min_string_length)
    if carve:
        analysis.carved_pes = carve_pe(data, max_count=max_carve)
    return analysis


def analyze_dump_file(
    file_path: str | Path,
    *,
    min_string_length: int = _DEFAULT_MIN_STRING_LENGTH,
    top_strings: int = 20,
    carve: bool = True,
    max_carve: int = 16,
) -> FileAnalysis:
    """分析单个内存转储文件。

    Args:
        file_path: 转储文件路径（.bin / .raw / .dmp 均可，按纯字节读取）
        min_string_length: 字符串最小长度
        top_strings: 代表性字符串数量
        carve: 是否执行 PE 雕刻
        max_carve: 最多雕刻数量

    Returns:
        FileAnalysis 分析结果

    Raises:
        MemoryAnalysisError: 文件不存在
    """
    path = Path(file_path)
    if not path.is_file():
        raise MemoryAnalysisError(f"转储文件不存在: {path}")
    data = path.read_bytes()
    return analyze_bytes(
        data,
        file_name=path.name,
        min_string_length=min_string_length,
        top_strings=top_strings,
        carve=carve,
        max_carve=max_carve,
    )


def _load_manifest(dump_dir: Path) -> dict[str, Any]:
    """加载转储目录的 manifest.json。

    Raises:
        MemoryAnalysisError: 目录不存在 / manifest 缺失或格式错误
    """
    if not dump_dir.is_dir():
        raise MemoryAnalysisError(f"转储目录不存在: {dump_dir}")
    manifest_path = dump_dir / "manifest.json"
    if not manifest_path.is_file():
        raise MemoryAnalysisError(
            f"manifest.json 缺失: {manifest_path}（请先用 memory.dump 生成转储）"
        )
    try:
        with manifest_path.open(encoding="utf-8") as f:
            manifest = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        raise MemoryAnalysisError(f"manifest.json 解析失败: {e}") from e
    if not isinstance(manifest, dict):
        raise MemoryAnalysisError("manifest.json 顶层应为字典")
    return manifest


def analyze_dump_dir(
    dump_dir: str | Path,
    *,
    rules_path: str | Path | None = None,
    rules_source: str | None = None,
    min_string_length: int = _DEFAULT_MIN_STRING_LENGTH,
    top_strings: int = 20,
    carve: bool = True,
    max_carve: int = 16,
) -> DumpAnalysisReport:
    """一键分析内存转储目录（读 manifest → 逐文件分析 → 汇总报告）。

    Args:
        dump_dir: 转储目录（需含 memdump_api 生成的 manifest.json）
        rules_path: 可选，YARA 规则文件路径（.yar/.yara）
        rules_source: 可选，YARA 规则源码字符串（与 rules_path 二选一）
        min_string_length: 字符串最小长度
        top_strings: 每个文件的代表性字符串数量
        carve: 是否执行 PE 雕刻
        max_carve: 每个文件最多雕刻数量

    Returns:
        DumpAnalysisReport 汇总报告

    Raises:
        MemoryAnalysisError: 目录 / manifest 异常
        YaraCompileError: YARA 规则编译失败
    """
    directory = Path(dump_dir)
    manifest = _load_manifest(directory)

    rules = None
    if rules_path is not None:
        rules = compile_file(rules_path)
    elif rules_source is not None:
        rules = compile_source(rules_source)

    regions = manifest.get("regions", [])
    if not isinstance(regions, list):
        raise MemoryAnalysisError("manifest.json 的 regions 字段应为列表")

    report = DumpAnalysisReport(
        dump_dir=str(directory),
        pid=manifest.get("pid"),
        created_at=str(manifest.get("created_at", "")),
    )

    for region in regions:
        if not isinstance(region, dict):
            continue
        if region.get("suspicious"):
            report.suspicious_regions.append(region)
        file_name = str(region.get("file", ""))
        if not file_name:
            continue
        file_path = directory / file_name
        if not file_path.is_file():
            report.warnings.append(f"区域文件缺失: {file_name}")
            continue
        data = file_path.read_bytes()
        analysis = analyze_bytes(
            data,
            file_name=file_name,
            min_string_length=min_string_length,
            top_strings=top_strings,
            carve=carve,
            max_carve=max_carve,
        )
        report.total_bytes += analysis.size
        # SHA256 与 manifest 对账（转储后文件被篡改/损坏时告警）
        manifest_sha = str(region.get("sha256", ""))
        if manifest_sha and manifest_sha != analysis.sha256:
            analysis.warnings.append("SHA256 与 manifest 记录不一致（文件可能已损坏或被篡改）")
        report.files.append(analysis)
        if rules is not None:
            try:
                matches = scan_file(rules, file_path)
            except Exception as e:  # YARA 扫描失败不应中断整体分析
                report.warnings.append(f"YARA 扫描失败 {file_name}: {e}")
                continue
            if matches:
                report.yara_matches[file_name] = matches

    return report
