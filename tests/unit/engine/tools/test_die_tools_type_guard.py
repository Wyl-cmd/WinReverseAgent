"""被测模块: winreverse.engine.tools.die_tools（DieScanMemoryTool）。

覆盖点（对照 coverage_guest.xml 真机缺口）: die_tools:84 data 参数类型不支持
（str/list/bytes/bytearray 之外）时返回 error 分支；该分支先于 die_api.scan_bytes
调用执行。统一走 execute() 契约入口，不加平台守卫：engine/tools 包 __init__ 聚合
导入触发 die/yara 链 → Linux 下如实报 collection error（基线接受态），待 Windows
实机实跑回填。
"""

from __future__ import annotations

from typing import Any

import pytest

from winreverse.engine.tools.die_tools import DieScanMemoryTool


class TestDieScanMemoryDataTypeGuard:
    """data 参数类型不支持时返回 error，且错误信息含实际类型名。"""

    @pytest.mark.parametrize("bad_data", [123, 3.14, {"raw": 1}, None])
    def test_unsupported_data_type_rejected(self, bad_data: Any) -> None:
        result = DieScanMemoryTool().execute({"data": bad_data})
        assert result["status"] == "error"
        assert "data 参数类型不支持" in result["error_message"]
        assert type(bad_data).__name__ in result["error_message"]
        assert "result" not in result
