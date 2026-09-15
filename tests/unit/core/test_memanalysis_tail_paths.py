"""被测模块: winreverse.core.memanalysis_api 收尾路径（真机 coverage 缺 377/431/595）。

覆盖点: extract_iocs 同串重复 IOC 去重 continue（377）、_parse_pe_header
非 MZ 签名防御分支（431）、analyze_bytes 代表性字符串按值去重 continue（595）。
403 行（extract_iocs_from_text 去重 continue）为防御性死弧：单次 finditer
遍历不可能对同一 (kind, value, start) 产生两次命中，无真实输入可触发，登记不伪造。
"""

from __future__ import annotations

from winreverse.core.memanalysis_api import _parse_pe_header, analyze_bytes, extract_iocs


def test_extract_iocs_dedupes_same_value_in_one_string() -> None:
    """同一字符串内重复出现的相同 IOC 只保留一条（377 去重 continue）。"""
    data = b"host 10.0.0.1 up 10.0.0.1 end"
    iocs = extract_iocs(data)
    ip_hits = [h for h in iocs if h.kind == "ip" and h.value == "10.0.0.1"]
    assert len(ip_hits) == 1
    assert ip_hits[0].offset == 0


def test_parse_pe_header_rejects_non_mz_and_short_data() -> None:
    """候选偏移处数据不足 0x40 字节或非 MZ 签名时头解析返回 None（431）。"""
    assert _parse_pe_header(b"A" * 0x3F, 0) is None  # 长度守卫（428-429）
    assert _parse_pe_header(b"A" * 0x40, 0) is None  # 非 MZ（431）


def test_analyze_bytes_top_strings_dedup() -> None:
    """analyze_bytes 代表性字符串按值去重：同值不同偏移只保留一条（595）。"""
    # 空格属于可打印 run 字符集，须用 \x00 切断才能产出两个同名串
    data = b"abcde\x00abcde"
    analysis = analyze_bytes(data, carve=False)
    assert analysis.string_count == 2
    assert analysis.top_strings == ["abcde"]
