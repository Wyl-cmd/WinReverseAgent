"""winreverse.engine.tools._base — 所有内部工具的基类 BaseTool。

统一实现 ToolInterface 契约的执行外壳：
- execute(): 调用子类 _run()，成功时自动补充 status="success"（已有 status 不覆盖）
- 异常兜底：RuntimeError / ValueError / KeyError 及其他异常统一转换为
  {"status": "error", "error_message": "<异常类型>: <异常文本>"}，不向总线抛出
- _require(): 必填参数校验助手，缺失时抛 KeyError("缺少必需参数: <key>")
  （消息同时含参数名，便于 execute() 转换为可读的 error_message）

子类只需声明 name / description 并实现 _run()。

契约参考：winreverse.engine.bus.ToolInterface（实施方案 §7.1）
"""

from __future__ import annotations

from typing import Any


class BaseTool:
    """内部工具基类。

    所有注册到 ToolRegistry 的工具都继承此类，实现 _run() 即可。
    execute() 负责状态字段规范与异常兜底，保证总线拿到的永远是
    JSON 兼容字典（含 status 字段）。

    Attributes:
        name: 工具唯一标识（点分命名空间，如 'pe.parse'、'memory.attach'）
        description: 工具用途说明，供 LLM 理解与调用
    """

    name: str = ""
    description: str = ""

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """执行工具（ToolInterface 契约入口）。

        Args:
            input_data: 输入参数（JSON 兼容字典）

        Returns:
            输出结果（JSON 兼容字典）：
            - 成功：_run() 的返回值，无 status 时补充 status="success"
            - 失败：{"status": "error", "error_message": "<异常类型>: <异常文本>"}
        """
        try:
            result = self._run(input_data)
        except (RuntimeError, ValueError, KeyError) as exc:
            return {"status": "error", "error_message": f"{type(exc).__name__}: {exc}"}
        except Exception as exc:  # 兜底：任何工具异常都不穿透总线
            return {"status": "error", "error_message": f"{type(exc).__name__}: {exc}"}
        if "status" not in result:
            result["status"] = "success"
        return result

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """工具实际逻辑，子类必须实现。

        Args:
            input_data: 输入参数（JSON 兼容字典）

        Returns:
            输出结果（JSON 兼容字典，status 字段可省略）
        """
        raise NotImplementedError

    @staticmethod
    def _require(input_data: dict[str, Any], key: str) -> Any:
        """读取必填参数，缺失时抛 KeyError。

        Args:
            input_data: 输入参数
            key: 参数名

        Returns:
            参数值

        Raises:
            KeyError: 参数缺失（由 execute() 兜底转换为 error 结果）
        """
        if key not in input_data:
            raise KeyError(f"缺少必需参数: {key}")
        return input_data[key]
