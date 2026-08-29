"""测试模块：winreverse.engine.tools._base

测试 BaseTool 基类的错误处理逻辑。
"""

from __future__ import annotations

from typing import Any

from winreverse.engine.tools._base import BaseTool


class _SuccessTool(BaseTool):
    """测试用：成功返回的工具。"""

    name = "test.success"
    description = "测试成功路径"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {"result": "ok"}


class _RequireParamTool(BaseTool):
    """测试用：需要必需参数的工具。"""

    name = "test.require"
    description = "测试参数校验"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        value = self._require(input_data, "required_key")
        return {"value": value}


class _RuntimeErrorTool(BaseTool):
    """测试用：抛出 RuntimeError 的工具。"""

    name = "test.error"
    description = "测试异常捕获"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("模拟执行失败")


class _ValueErrorTool(BaseTool):
    """测试用：抛出 ValueError 的工具。"""

    name = "test.value_error"
    description = "测试 ValueError 捕获"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        raise ValueError("参数格式错误")


class TestBaseToolExecute:
    """BaseTool.execute 方法测试。"""

    def test_success_auto_adds_status(self) -> None:
        """成功返回时自动补充 status=success。"""
        tool = _SuccessTool()
        result = tool.execute({})
        assert result["status"] == "success"
        assert result["result"] == "ok"

    def test_success_keeps_existing_status(self) -> None:
        """_run 返回字典已含 status 时不覆盖。"""
        tool = _SuccessTool()
        # 修改 _run 返回带 status 的字典
        tool._run = lambda input_data: {"status": "success", "custom": True}  # type: ignore[assignment]
        result = tool.execute({})
        assert result["status"] == "success"
        assert result["custom"] is True

    def test_missing_required_param_returns_error(self) -> None:
        """缺少必需参数时返回 error。"""
        tool = _RequireParamTool()
        result = tool.execute({})
        assert result["status"] == "error"
        assert "required_key" in result["error_message"]

    def test_runtime_error_caught(self) -> None:
        """RuntimeError 被捕获并返回 error。"""
        tool = _RuntimeErrorTool()
        result = tool.execute({})
        assert result["status"] == "error"
        assert "RuntimeError" in result["error_message"]
        assert "模拟执行失败" in result["error_message"]

    def test_value_error_caught(self) -> None:
        """ValueError 被捕获并返回 error。"""
        tool = _ValueErrorTool()
        result = tool.execute({})
        assert result["status"] == "error"
        assert "ValueError" in result["error_message"]


class TestRequireHelper:
    """BaseTool._require 静态方法测试。"""

    def test_require_returns_value(self) -> None:
        """参数存在时返回值。"""
        tool = _SuccessTool()
        value = tool._require({"key": "value"}, "key")
        assert value == "value"

    def test_require_raises_keyerror(self) -> None:
        """参数缺失时抛 KeyError。"""
        tool = _SuccessTool()
        try:
            tool._require({}, "missing")
            assert False, "应抛出 KeyError"
        except KeyError as e:
            assert "missing" in str(e)
