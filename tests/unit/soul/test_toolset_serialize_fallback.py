"""测试模块：winreverse.soul.toolset

覆盖 SoulToolsetAdapter._serialize_result 的 JSON 失败退化路径（toolset.py 225-226）：
循环引用触发 ValueError、不可序列化键类型触发 TypeError 时应退化为 str(result)。
"""

from __future__ import annotations

from winreverse.soul.toolset import SoulToolsetAdapter


def test_serialize_circular_reference_falls_back_to_str():
    """循环引用使 json.dumps 抛 ValueError，应退化为 str(result) 而非崩溃。"""
    result: dict = {"name": "loop"}
    result["self"] = result
    serialized = SoulToolsetAdapter._serialize_result(result)
    assert serialized == str(result)
    assert "loop" in serialized


def test_serialize_unserializable_key_falls_back_to_str():
    """tuple 键使 json.dumps 抛 TypeError（default 只作用于值不作用于键），退化为 str(result)。"""
    result = {(1, 2): "v"}
    serialized = SoulToolsetAdapter._serialize_result(result)
    assert serialized == str(result)


def test_serialize_normal_result_still_json():
    """对照：普通可序列化结果走 JSON 分支，不得误入退化路径。"""
    result = {"status": "success", "n": 1}
    serialized = SoulToolsetAdapter._serialize_result(result)
    assert serialized.lstrip().startswith("{")
    assert '"status": "success"' in serialized
