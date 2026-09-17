"""winreverse.engine.tools.memory_tools — 内存操作工具。

将 core.memory_api 封装为 ToolInterface 实现。

工具清单：
- memory.attach: 附加到目标进程
- memory.read: 读取进程内存
- memory.write: 写入进程内存

注意：
- memory.attach 返回 Pymem 实例的进程 ID（pid），后续 read/write 需传入 pid
- 当前实现通过全局 _sessions 字典维护 pid -> Pymem 的映射
- 这是因为 ToolInterface 要求输入/输出为 JSON 兼容字典，不能直接传递 Pymem 实例
- 未来可改为进程级会话管理（session_id -> Pymem）

参考：实施方案 §7.2
"""

from __future__ import annotations

from typing import Any, ClassVar

from winreverse.core import memory_api
from winreverse.engine.bus import ToolParameterSpec
from winreverse.engine.tools._base import BaseTool

# 进程会话表：pid -> Pymem 实例
# 注意：这是进程级全局状态，仅用于工具层传递 Pymem 引用
# 测试中可通过 _clear_sessions() 清空
_sessions: dict[int, Any] = {}


def _clear_sessions() -> None:
    """清空会话表（主要用于测试）。"""
    _sessions.clear()


def get_session(pid: int) -> Any:
    """获取已附加进程的 Pymem 会话。

    Args:
        pid: memory.attach 返回的进程 ID

    Returns:
        Pymem 实例

    Raises:
        KeyError: 进程未附加或会话已失效
    """
    if pid not in _sessions:
        raise KeyError(f"进程未附加或会话已失效: pid={pid}（请先调用 memory.attach）")
    return _sessions[pid]


class MemoryAttachTool(BaseTool):
    """memory.attach — 附加到目标进程。

    输入: {"process_name": "notepad.exe"}
    输出: {"status": "success", "pid": int, "process_name": str}

    Note:
        返回的 pid 用于后续 memory.read / memory.write 调用。
    """

    name = "memory.attach"
    description = "附加到目标进程（需管理员权限），返回进程 ID 供后续读写使用"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        process_name = self._require(input_data, "process_name")
        pm = memory_api.attach(process_name)
        pid = int(pm.process_id)
        _sessions[pid] = pm
        return {
            "pid": pid,
            "process_name": process_name,
        }


class MemoryReadTool(BaseTool):
    """memory.read — 读取进程内存。

    输入: {
        "pid": 1234,          # memory.attach 返回的进程 ID
        "address": 4194304,   # 起始地址（十进制）
        "length": 16,         # 读取长度（字节）
        "type": "bytes"       # 可选：bytes/int/string，默认 bytes
    }
    输出: {
        "status": "success",
        "data": "<base64 编码>",  # type=bytes 时
        "value": 12345,           # type=int 时
        "string": "hello",        # type=string 时
    }
    """

    name = "memory.read"
    description = "读取目标进程的内存数据（需先用 memory.attach 附加）"

    # 显式声明参数 schema（P0-1）：length 只在 type=bytes 时必须，
    # 单靠源码推断会把它当成无条件必填，误导 LLM 传无用参数。
    parameters: ClassVar[list[ToolParameterSpec]] = [
        ToolParameterSpec("pid", "integer", "memory.attach 返回的进程 ID", True),
        ToolParameterSpec("address", "integer", "起始地址（十进制）", True),
        ToolParameterSpec(
            "type", "string", "读取类型：bytes/int/string（默认 bytes）", False, "bytes"
        ),
        ToolParameterSpec("length", "integer", "读取长度（字节，type=bytes 时必填）", False, 16),
        ToolParameterSpec(
            "max_len", "integer", "最大长度（type=string 时使用，默认 50）", False, 50
        ),
        ToolParameterSpec(
            "encoding", "string", "字符串编码（type=string 时使用，默认 UTF-8）", False, "UTF-8"
        ),
    ]

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        import base64

        pid = int(self._require(input_data, "pid"))
        address = int(self._require(input_data, "address"))
        read_type = str(input_data.get("type", "bytes"))

        if pid not in _sessions:
            return {
                "status": "error",
                "error_message": f"进程未附加或会话已失效: pid={pid}（请先调用 memory.attach）",
            }
        pm = _sessions[pid]

        if read_type == "bytes":
            length = int(self._require(input_data, "length"))
            data = memory_api.read_bytes(pm, address, length)
            return {"data": base64.b64encode(data).decode("ascii")}
        elif read_type == "int":
            int_val = memory_api.read_int(pm, address)
            return {"value": int_val}
        elif read_type == "string":
            max_len = int(input_data.get("max_len", 50))
            encoding = str(input_data.get("encoding", "UTF-8"))
            str_val = memory_api.read_string(pm, address, max_len, encoding)
            return {"string": str_val}
        else:
            return {
                "status": "error",
                "error_message": f"不支持的读取类型: {read_type}（支持: bytes/int/string）",
            }


class MemoryWriteTool(BaseTool):
    """memory.write — 写入进程内存。

    输入: {
        "pid": 1234,
        "address": 4194304,
        "type": "bytes",      # bytes/int/string
        "data": "<base64>",   # type=bytes 时
        "value": 12345,       # type=int 时
        "string": "hello"     # type=string 时
    }
    输出: {"status": "success", "written": <写入字节数>}
    """

    name = "memory.write"
    description = "向目标进程内存写入数据（需先用 memory.attach 附加）"

    # 显式声明参数 schema（P0-1）：data/value/string 由 type 判别式决定，
    # 源码推断会把三者都当必填。
    parameters: ClassVar[list[ToolParameterSpec]] = [
        ToolParameterSpec("pid", "integer", "memory.attach 返回的进程 ID", True),
        ToolParameterSpec("address", "integer", "目标地址（十进制）", True),
        ToolParameterSpec(
            "type", "string", "写入类型：bytes/int/string（默认 bytes）", False, "bytes"
        ),
        ToolParameterSpec("data", "string", "base64 数据（type=bytes 时使用）", False),
        ToolParameterSpec("value", "integer", "整数值（type=int 时使用）", False),
        ToolParameterSpec("string", "string", "字符串值（type=string 时使用）", False),
        ToolParameterSpec(
            "encoding", "string", "字符串编码（type=string 时使用，默认 UTF-8）", False, "UTF-8"
        ),
    ]

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        import base64

        pid = int(self._require(input_data, "pid"))
        address = int(self._require(input_data, "address"))
        write_type = str(input_data.get("type", "bytes"))

        if pid not in _sessions:
            return {
                "status": "error",
                "error_message": f"进程未附加或会话已失效: pid={pid}（请先调用 memory.attach）",
            }
        pm = _sessions[pid]

        if write_type == "bytes":
            data_raw = self._require(input_data, "data")
            if isinstance(data_raw, str):
                data = base64.b64decode(data_raw)
            elif isinstance(data_raw, (list, bytes, bytearray)):
                data = bytes(data_raw)
            else:
                data = bytes(data_raw)
            memory_api.write_bytes(pm, address, data)
            return {"written": len(data)}
        elif write_type == "int":
            int_val = int(self._require(input_data, "value"))
            memory_api.write_int(pm, address, int_val)
            return {"written": 4}  # 32 位整数
        elif write_type == "string":
            str_val = str(self._require(input_data, "string"))
            encoding = str(input_data.get("encoding", "UTF-8"))
            memory_api.write_string(pm, address, str_val, encoding)
            return {"written": len(str_val.encode(encoding))}
        else:
            return {
                "status": "error",
                "error_message": f"不支持的写入类型: {write_type}（支持: bytes/int/string）",
            }


# 工具实例列表
MEMORY_TOOLS: list[BaseTool] = [
    MemoryAttachTool(),
    MemoryReadTool(),
    MemoryWriteTool(),
]
