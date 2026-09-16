"""被测模块: winreverse.core.memanalysis_api（IOC `filepath` 正则）。

覆盖点（2026-09-15 真机 Windows 实测暴露的缺陷回归锁）：

真机现象（`extract_iocs_from_text` 对真实命令行文本）::

    cmd.exe /c C:\\work\\wr_cli_behav\\bhv_...\\sandbox\\wr_benign.cmd
    C:\\Users\\admin\\AppData\\Roaming\\svchost.exe
    C:\\Windows\\System32\\cmd.exe /c whoami
    \\\\fileserver\\share\\evil\\payload.dll

    实际输出: filepath 'C:\\work' / 'C:\\Users' / 'C:\\Windows'（UNC 一条都没有）

根因（两条，均在 `_IOC_PATTERNS["filepath"]`）：
1. 磁盘路径分支字符类**把反斜杠本身也排除了**（`[^...\\x5c\\x5c]`），
   于是匹配在第二个分隔符处截断 → 多级路径 IOC 全部退化成 `<盘符>:\\<首段>`，
   对取证毫无价值（真实恶意路径丢失）。
2. UNC 分支以 `\\b` 起头，而 `\\b` 要求位置两侧之一为单词字符；UNC 路径前总是
   空白/引号（非单词字符）→ 行首/空格后的 UNC 路径**永不匹配**。

修复：磁盘分支字符类允许反斜杠；UNC 分支去掉 `\\b`。
本模块顶层链路 import yara（Windows 运行时专有）→ Linux 上如实报 collection
error（基线接受态，与 tests/unit/core/test_memanalysis_api.py 一致）。
"""

from __future__ import annotations

import re

from winreverse.core.memanalysis_api import _IOC_PATTERNS, extract_iocs_from_text


def _by_kind(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for hit in extract_iocs_from_text(text):
        out.setdefault(hit.kind, []).append(hit.value)
    return out


class TestFilepathPattern:
    """`filepath` 正则：多级路径必须完整、UNC 必须可提取。"""

    def test_drive_path_keeps_all_separators(self) -> None:
        """真机复现用例：多级路径不得截断成 `C:\\work`。"""
        text = r"cmd.exe /c C:\work\wr_cli_behav\bhv_20260915_152529_5cf9\sandbox\wr_benign.cmd"
        paths = _by_kind(text).get("filepath", [])
        assert paths == [r"C:\work\wr_cli_behav\bhv_20260915_152529_5cf9\sandbox\wr_benign.cmd"]

    def test_users_tree_path_not_truncated(self) -> None:
        """典型落盘路径（AppData）完整提取。"""
        text = r"C:\Users\admin\AppData\Roaming\svchost.exe"
        assert _by_kind(text).get("filepath") == [text]

    def test_path_terminated_by_quote_and_space(self) -> None:
        """路径在引号/空白处终止，不吞后续文本。"""
        text = r'"C:\Windows\System32\cmd.exe" /c whoami'
        hit = _by_kind(text).get("filepath")
        assert hit == [r"C:\Windows\System32\cmd.exe"]

    def test_unc_path_at_line_start(self) -> None:
        """行首 UNC 路径（`\\\\host\\share\\x`）必须提取。"""
        text = r"\\fileserver\share\evil\payload.dll"
        assert _by_kind(text).get("filepath") == [text]

    def test_unc_path_after_space(self) -> None:
        """空格后的 UNC 路径必须提取（旧 `\\b` 分支在此永不匹配）。"""
        text = r"copy \\fileserver\share\evil\payload.dll ."
        assert r"\\fileserver\share\evil\payload.dll" in _by_kind(text).get("filepath", [])

    def test_single_component_drive_path_still_matches(self) -> None:
        """盘符 + 单段（无法再截断）仍按原语义命中。"""
        assert _by_kind(r"C:\Windows")["filepath"] == [r"C:\Windows"]

    def test_registry_and_url_unaffected(self) -> None:
        """同文本内的其它 IOC 种类不受本次改动影响。"""
        text = (
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            "connect https://c2.malicious.top/gate.php now"
        )
        kinds = _by_kind(text)
        assert "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" in kinds["registry"]
        assert "https://c2.malicious.top/gate.php" in kinds["url"]

    def test_registry_path_stops_at_whitespace(self) -> None:
        """注册表 IOC 在空白处终止（文本池口径：行为层以 \\n 拼接命令行）。

        注：*文本* 输入里若用 `\\x00` 直接拼接，注册表路径的 `[^\\s\"']{1,120}`
        会跨过 NUL 继续吞；
        但两条真实调用路径都不会出现这种情况（内存侧先按字符串切分、
        行为侧以 `\\n` 拼接），故不作为缺陷登记。
        """
        text = "HKLM\\Software\\Evil\\Run C:\\Windows\\System32\\cmd.exe"
        kinds = _by_kind(text)
        assert "HKLM\\Software\\Evil\\Run" in kinds["registry"]
        assert r"C:\Windows\System32\cmd.exe" in kinds["filepath"]

    def test_pattern_is_compiled_without_backslash_exclusion(self) -> None:
        """结构锁：磁盘分支字符类不得再排除反斜杠（防止回归）。"""
        pattern = _IOC_PATTERNS["filepath"].pattern
        assert r"\x5c" not in pattern
        first_branch = pattern.split("|")[0]
        # 反斜杠须在字符类之外作为分隔符占位（`[A-Za-z]:\\`）
        assert re.search(r"\[A-Za-z\]:\\\\", first_branch), first_branch
