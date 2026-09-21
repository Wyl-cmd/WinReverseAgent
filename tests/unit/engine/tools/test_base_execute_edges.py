"""测试模块：winreverse.engine.tools._base（execute 兜底边界）。

覆盖点：泛化 except Exception 兜底的精确消息格式、BaseException 不吞、
已带非 success 状态不覆盖、_require 按存在性而非真值取参、空结果补 status。

口径：BaseTool 本身平台无关，但导入必经 winreverse.engine.tools 包 __init__
聚合链（behavior_tools → memanalysis_api → yara_api）拉入 Windows 专有依赖
yara，缺依赖的 Linux 上如实报 collection error＝基线接受态，待 Windows 实机
依赖就位后实跑回填（与既有 test_base.py 同链同口径，禁加平台守卫）。
"""

from __future__ import annotations

from typing import Any

import pytest

from winreverse.engine.tools._base import BaseTool


class _SuccessTool(BaseTool):
    """测试用：可替换 _run 的成功工具骨架。"""

    name = "test.edge.success"
    description = "测试边界"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {}


class _TypeErrorTool(BaseTool):
    """测试用：抛出未列名异常（走泛化兜底分支）。"""

    name = "test.edge.type_error"
    description = "测试泛化兜底"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        raise TypeError("类型不匹配")


class _KeyErrorTool(BaseTool):
    """测试用：直接抛 KeyError（非经 _require）。"""

    name = "test.edge.key_error"
    description = "测试 KeyError 兜底"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        raise KeyError("上游键缺失")


class _InterruptTool(BaseTool):
    """测试用：抛 BaseException（KeyboardInterrupt）。"""

    name = "test.edge.interrupt"
    description = "测试兜底边界"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        raise KeyboardInterrupt("用户中断")


class TestGenericExceptionFallback:
    """泛化兜底分支（except Exception）测试。"""

    def test_unexpected_exception_message_format(self) -> None:
        """未列名异常被兜底且 error_message 精确为 "<类型>: <文本>"。"""
        result = _TypeErrorTool().execute({})
        assert result == {"status": "error", "error_message": "TypeError: 类型不匹配"}

    def test_key_error_directly_raised_caught(self) -> None:
        """_run 直接抛 KeyError（非 _require）同样被兜底转换。"""
        result = _KeyErrorTool().execute({})
        assert result["status"] == "error"
        assert "KeyError" in result["error_message"]
        assert "上游键缺失" in result["error_message"]

    def test_base_exception_not_swallowed(self) -> None:
        """兜底只吞 Exception：KeyboardInterrupt 照常穿透，不吞用户中断。"""
        with pytest.raises(KeyboardInterrupt):
            _InterruptTool().execute({})


class TestStatusFieldContract:
    """status 字段补全契约测试。"""

    def test_empty_result_gets_success_status(self) -> None:
        """_run 返回空字典时补 status=success。"""
        assert _SuccessTool().execute({}) == {"status": "success"}

    def test_existing_non_success_status_preserved(self) -> None:
        """_run 已带非 success 的 status 时不覆盖（execute 不篡改业务状态）。"""
        tool = _SuccessTool()
        tool._run = lambda input_data: {"status": "partial", "progress": 0.5}  # type: ignore[assignment]
        assert tool.execute({}) == {"status": "partial", "progress": 0.5}


class TestRequirePresenceSemantics:
    """_require 按键存在性取参，真值为假但不缺失时必须原样返回。"""

    @pytest.mark.parametrize(("key", "falsy"), [("k", None), ("k", 0), ("k", ""), ("k", False)])
    def test_present_falsy_value_returned(self, key: str, falsy: Any) -> None:
        """存在但真值为假的参数不视为缺失（缺失检查是 `key not in` 而非真值判断）。"""
        assert BaseTool._require({key: falsy}, key) is falsy

    def test_present_empty_containers_returned(self) -> None:
        """空列表/空字典同上：返回原对象本身。"""
        empty_list: list[Any] = []
        empty_dict: dict[str, Any] = {}
        assert BaseTool._require({"a": empty_list}, "a") is empty_list
        assert BaseTool._require({"b": empty_dict}, "b") is empty_dict
