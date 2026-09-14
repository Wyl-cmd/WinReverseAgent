"""winreverse.forensics.network — 网络分析与抓包桥接。

封装内置的 tshark（Wireshark CLI）与 editcap：
1. 列出抓包接口（net.interfaces）
2. 实时抓包（net.live_capture：指定接口/时长/过滤 → pcap 落盘）
3. 解析 pcap（net.read_pcap：字段提取 / 显示过滤 / 统计）
4. pcap 文件级编辑（net.edit_pcap：editcap 裁剪/筛选，如提取木马 C2 流量段）

边界说明：
- tshark 侧为抓包 + 解析 + 过滤；editcap 为 pcap 文件级编辑（去包/截断）
- 实时改包 / 流量注入（如伪造 C2 应答）不在本层，
  需 scapy / mitmproxy 类工具（路线图 P7）

tshark 路径解析顺序：显式路径 → tools/tshark/tshark.exe（内置）→ PATH。
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# 抓包默认超时（秒；由 duration 参数控制实际时长，此处为兜底）
_CAPTURE_TIMEOUT = 7200
# 解析命令超时（秒）
_READ_TIMEOUT = 300
# 实时抓包 -a duration 上限（单次）
_MAX_CAPTURE_SECONDS = 3600

# 接口编号（tshark -D 输出格式：1. eth0 ...）
_INTERFACE_PATTERN = re.compile(r"^(\d+)\.\s+(.+?)(?:\s+\(([^)]+)\))?$")


class NetworkToolError(RuntimeError):
    """网络工具调用失败的统一异常（tshark 缺失 / 无接口 / 命令失败）。"""


@dataclass
class NetworkInterface:
    """一个可抓包的网络接口。

    Attributes:
        index: tshark 接口编号（用于 -i 参数）
        name: 系统接口名
        description: 人可读描述（Windows 上通常为网卡名）
        loopback: 是否环回接口
    """

    index: int
    name: str
    description: str = ""
    loopback: bool = False

    def to_dict(self) -> dict[str, object]:
        """转为 JSON 兼容字典。"""
        return {
            "index": self.index,
            "name": self.name,
            "description": self.description,
            "loopback": self.loopback,
        }


@dataclass
class PcapReadResult:
    """pcap 解析结果。

    Attributes:
        file: pcap 路径
        display_filter: 使用的显示过滤（空为不过滤）
        packet_count: 解析出的包数（-T fields 模式下为行数）
        lines: 输出行（按调用方指定的字段格式）
    """

    file: str
    display_filter: str = ""
    packet_count: int = 0
    lines: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """转为 JSON 兼容字典。"""
        return {
            "file": self.file,
            "display_filter": self.display_filter,
            "packet_count": self.packet_count,
            "lines": self.lines[:1000],
        }


class TsharkBridge:
    """tshark 桥接（接口枚举 / 实时抓包 / pcap 解析）。"""

    def __init__(self, tshark_path: str | Path | None = None) -> None:
        """初始化桥接。

        Args:
            tshark_path: tshark 可执行路径（None 时按
                tools/tshark/tshark.exe → PATH 顺序解析）

        Raises:
            NetworkToolError: 找不到 tshark
        """
        self._tshark_path = self._resolve_tshark(tshark_path)

    @staticmethod
    def _resolve_tshark(tshark_path: str | Path | None) -> Path:
        """按 显式路径 → tools/tshark/tshark.exe（内置）→ PATH 解析。"""
        candidates: list[Path] = []
        if tshark_path is not None:
            candidates.append(Path(tshark_path))
        candidates.append(Path.cwd() / "tools" / "tshark" / "tshark.exe")
        for candidate in candidates:
            if candidate.is_file():
                return candidate
        which = shutil.which("tshark")
        if which:
            return Path(which)
        raise NetworkToolError(
            "找不到 tshark。请运行 'winreverse tools update tshark' 后"
            "按 manifest 注记提取，或安装 Wireshark 后加入 PATH"
        )

    @property
    def tshark_path(self) -> Path:
        """tshark 二进制路径。"""
        return self._tshark_path

    def _run(self, args: list[str], *, timeout: int = _READ_TIMEOUT) -> str:
        """执行 tshark 命令并返回 stdout。"""
        try:
            completed = subprocess.run(
                [str(self._tshark_path), *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as e:
            raise NetworkToolError(f"tshark 不可用: {self._tshark_path}") from e
        except subprocess.TimeoutExpired as e:
            raise NetworkToolError(f"tshark 命令超时: {' '.join(args[:3])}") from e
        if completed.returncode != 0:
            stderr = completed.stderr.strip()
            # -a duration 到期属正常结束，部分版本返回非零
            if "duration" not in stderr.lower():
                raise NetworkToolError(f"tshark 失败: {stderr[:500]}")
        return completed.stdout

    def version(self) -> str:
        """tshark 版本号（首行）。"""
        lines = self._run(["-v"]).splitlines()
        if not lines or not lines[0].strip():
            raise NetworkToolError("tshark -v 无输出")
        return lines[0].strip()

    def list_interfaces(self) -> list[NetworkInterface]:
        """列出可抓包的网络接口（tshark -D）。"""
        output = self._run(["-D"])
        interfaces: list[NetworkInterface] = []
        for line in output.splitlines():
            m = _INTERFACE_PATTERN.match(line.strip())
            if not m:
                continue
            index, name, description = m.group(1), m.group(2), m.group(3) or ""
            loopback = "loopback" in (name + description).lower() or name.startswith("lo")
            interfaces.append(
                NetworkInterface(
                    index=int(index), name=name, description=description, loopback=loopback
                )
            )
        return interfaces

    def live_capture(
        self,
        output_pcap: str | Path,
        *,
        interface: int | str = 1,
        duration_seconds: int = 30,
        capture_filter: str = "",
    ) -> Path:
        """实时抓包落盘（tshark -i <接口> -a duration -w <pcap>）。

        Args:
            output_pcap: 输出 pcap 路径
            interface: 接口编号（list_interfaces 的 index）或名称
            duration_seconds: 抓包时长（秒，上限 3600）
            capture_filter: BPF 捕获过滤（如 'host 1.2.3.4'）

        Returns:
            pcap 文件路径

        Raises:
            NetworkToolError: 时长非法 / 无抓包权限 / 接口不存在
        """
        if not 1 <= duration_seconds <= _MAX_CAPTURE_SECONDS:
            raise NetworkToolError(
                f"抓包时长应为 1-{_MAX_CAPTURE_SECONDS} 秒，实际: {duration_seconds}"
            )
        out = Path(output_pcap)
        out.parent.mkdir(parents=True, exist_ok=True)
        args = [
            "-i",
            str(interface),
            "-a",
            f"duration:{duration_seconds}",
            "-w",
            str(out),
        ]
        if capture_filter:
            args.extend(["-f", capture_filter])
        self._run(args, timeout=duration_seconds + 120)
        if not out.is_file():
            raise NetworkToolError(f"抓包未产出 pcap（检查管理员权限与接口编号）: {out}")
        return out

    def read_pcap(
        self,
        pcap_path: str | Path,
        *,
        display_filter: str = "",
        fields: list[str] | None = None,
    ) -> PcapReadResult:
        """解析 pcap（-r；可带显示过滤与字段提取）。

        Args:
            pcap_path: pcap 路径
            display_filter: 显示过滤（如 'http.request || dns'）
            fields: 字段提取列表（如 ['ip.src', 'ip.dst', 'http.host']；
                指定时输出为 TSV，每行一条记录）

        Returns:
            PcapReadResult 结果

        Raises:
            NetworkToolError: 文件不存在 / 解析失败
        """
        pcap = Path(pcap_path)
        if not pcap.is_file():
            raise NetworkToolError(f"pcap 不存在: {pcap}")
        args = ["-r", str(pcap)]
        if display_filter:
            args.extend(["-Y", display_filter])
        if fields:
            for f in fields:
                args.extend(["-e", f])
            args.append("-T")
            args.append("fields")
            args.append("-E")
            args.append("header=y")
        output = self._run(args)
        lines = [line for line in output.splitlines() if line.strip()]
        return PcapReadResult(
            file=str(pcap),
            display_filter=display_filter,
            packet_count=len(lines),
            lines=lines,
        )


class EditcapBridge:
    """editcap 桥接（pcap 文件级编辑：去包 / 时间裁剪 / 截断）。"""

    def __init__(self, editcap_path: str | Path | None = None) -> None:
        """初始化桥接（路径解析逻辑同 TsharkBridge）。"""
        candidates: list[Path] = []
        if editcap_path is not None:
            candidates.append(Path(editcap_path))
        candidates.append(Path.cwd() / "tools" / "tshark" / "editcap.exe")
        for candidate in candidates:
            if candidate.is_file():
                self._editcap_path: Path | None = candidate
                break
        else:
            which = shutil.which("editcap")
            self._editcap_path = Path(which) if which else None

    def is_available(self) -> bool:
        """editcap 是否可用。"""
        return self._editcap_path is not None

    def edit_pcap(
        self,
        input_pcap: str | Path,
        output_pcap: str | Path,
        *,
        keep_first_n: int | None = None,
        remove_duplicates: bool = False,
    ) -> Path:
        """编辑 pcap 文件（editcap）。

        Args:
            input_pcap: 输入 pcap
            output_pcap: 输出 pcap
            keep_first_n: 只保留前 N 个包（提取木马流量样本段）
            remove_duplicates: 去除重复包

        Returns:
            输出 pcap 路径

        Raises:
            NetworkToolError: editcap 不可用 / 输入不存在 / 失败
        """
        if self._editcap_path is None:
            raise NetworkToolError(
                "editcap 不可用（tshark 内置包应包含 editcap.exe，或安装 Wireshark）"
            )
        src = Path(input_pcap)
        if not src.is_file():
            raise NetworkToolError(f"pcap 不存在: {src}")
        # editcap 语法：[-r] <infile> <outfile> [packet#[-packet#]]；
        # -r 为"保留选中"开关（缺省删除选中），范围是末尾位置参数
        args = [str(self._editcap_path)]
        if keep_first_n is not None:
            args.append("-r")
        if remove_duplicates:
            args.append("-d")
        out = Path(output_pcap)
        out.parent.mkdir(parents=True, exist_ok=True)
        args.extend([str(src), str(out)])
        if keep_first_n is not None:
            args.append(f"1-{keep_first_n}")
        try:
            completed = subprocess.run(
                args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_READ_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise NetworkToolError("editcap 超时") from e
        if completed.returncode != 0 or not out.is_file():
            raise NetworkToolError(f"editcap 失败: {completed.stderr.strip()[:300]}")
        return out
