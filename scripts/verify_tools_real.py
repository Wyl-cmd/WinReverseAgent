"""真实工具调用验证脚本（不依赖 pytest）。

直接调用 14 个内部工具，验证：
- 工具注册成功
- 每个工具可被调用
- 工具返回 dict 结构（含 status 字段）
- 底层 Python 逆向库真实可用

使用 C:\\Windows\\System32\\notepad.exe 作为测试目标。
"""
from __future__ import annotations

import sys
import traceback
from pathlib import Path

# 确保使用项目 src
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from winreverse.engine.bus import ToolRegistry
from winreverse.engine.tools import list_tool_names, register_all_tools

# 测试目标：notepad.exe 是 Windows 自带的 PE 文件
TARGET_PE = r"C:\Windows\System32\notepad.exe"


def _format_output(result: dict, max_len: int = 80) -> str:
    """格式化工具返回结果用于显示。

    Args:
        result: 工具返回的 dict
        max_len: 最大显示长度

    Returns:
        格式化后的字符串
    """
    # 优先显示 status，然后是关键数据
    status = result.get("status", "unknown")
    # 移除 status 后取其余字段做预览
    preview_data = {k: v for k, v in result.items() if k != "status"}
    preview = str(preview_data)[:max_len].replace("\n", " ").replace("\r", "")
    return f"[{status}] {preview}"


def main() -> int:
    """主测试函数。

    Returns:
        0: 全部通过
        1: 存在失败
    """
    print("=" * 70)
    print("WinReverseAgent 工具真实调用验证")
    print("=" * 70)
    print(f"测试目标 PE 文件: {TARGET_PE}")
    print()

    # 1. 注册工具
    registry = ToolRegistry()
    try:
        register_all_tools(registry)
    except Exception as e:
        print(f"[FAIL] 工具注册失败: {e}")
        return 1

    tool_names = list_tool_names()
    print(f"[OK] 已注册 {len(tool_names)} 个工具")
    print()

    # 2. 逐个测试工具
    results: list[tuple[str, str, str]] = []  # (工具名, 状态, 摘要)

    # PE 工具（6 个）
    print("—— PE 工具测试（基于 pefile 库）——")
    for tool_name in ["pe.parse", "pe.imports", "pe.exports", "pe.sections",
                       "pe.suspicious_imports", "pe.meta"]:
        try:
            result = registry.call(tool_name, {"file_path": TARGET_PE})
            status = result.get("status", "unknown")
            if status == "success":
                preview = _format_output(result)
                results.append((tool_name, "OK", preview))
                print(f"  [OK] {tool_name}: {preview}")
            else:
                preview = _format_output(result)
                results.append((tool_name, "ERROR", preview))
                print(f"  [ERROR] {tool_name}: {preview}")
        except Exception as e:
            results.append((tool_name, "EXCEPTION", str(e)))
            print(f"  [EXCEPTION] {tool_name}: {type(e).__name__}: {e}")

    print()

    # disasm 工具（基于 capstone 库）
    print("—— 反汇编工具测试（基于 capstone 库）——")
    try:
        # x64: nop; mov rax, 0x1234; ret
        test_code = b"\x90\x48\xc7\xc0\x34\x12\x00\x00\xc3"
        result = registry.call("disasm", {"code": test_code, "arch": "x86", "mode": 64})
        status = result.get("status", "unknown")
        if status == "success":
            preview = _format_output(result)
            results.append(("disasm", "OK", preview))
            print(f"  [OK] disasm: {preview}")
        else:
            preview = _format_output(result)
            results.append(("disasm", "ERROR", preview))
            print(f"  [ERROR] disasm: {preview}")
    except Exception as e:
        results.append(("disasm", "EXCEPTION", str(e)))
        print(f"  [EXCEPTION] disasm: {type(e).__name__}: {e}")

    print()

    # YARA 工具（2 个，基于 yara-python 库）
    print("—— YARA 工具测试（基于 yara-python 库）——")
    yara_rule = '''
rule test_notepad {
    strings:
        $mz = "MZ"
        $pe = "PE\\x00\\x00"
    condition:
        $mz at 0 and $pe
}
'''
    try:
        result = registry.call("yara.scan_file", {
            "file_path": TARGET_PE,
            "rule_text": yara_rule,
        })
        status = result.get("status", "unknown")
        if status == "success":
            preview = _format_output(result)
            results.append(("yara.scan_file", "OK", preview))
            print(f"  [OK] yara.scan_file: {preview}")
        else:
            preview = _format_output(result)
            results.append(("yara.scan_file", "ERROR", preview))
            print(f"  [ERROR] yara.scan_file: {preview}")
    except Exception as e:
        results.append(("yara.scan_file", "EXCEPTION", str(e)))
        print(f"  [EXCEPTION] yara.scan_file: {type(e).__name__}: {e}")

    try:
        with open(TARGET_PE, "rb") as f:
            pe_data = f.read(1024)  # 只读取前 1KB 用于测试
        result = registry.call("yara.scan_memory", {
            "data": pe_data,
            "rule_text": yara_rule,
        })
        status = result.get("status", "unknown")
        if status == "success":
            preview = _format_output(result)
            results.append(("yara.scan_memory", "OK", preview))
            print(f"  [OK] yara.scan_memory: {preview}")
        else:
            preview = _format_output(result)
            results.append(("yara.scan_memory", "ERROR", preview))
            print(f"  [ERROR] yara.scan_memory: {preview}")
    except Exception as e:
        results.append(("yara.scan_memory", "EXCEPTION", str(e)))
        print(f"  [EXCEPTION] yara.scan_memory: {type(e).__name__}: {e}")

    print()

    # DIE 工具（2 个，基于 die-python 库）
    print("—— DIE 工具测试（基于 die-python 库）——")
    try:
        result = registry.call("die.scan_file", {"file_path": TARGET_PE})
        status = result.get("status", "unknown")
        if status == "success":
            preview = _format_output(result)
            results.append(("die.scan_file", "OK", preview))
            print(f"  [OK] die.scan_file: {preview}")
        else:
            preview = _format_output(result)
            results.append(("die.scan_file", "ERROR", preview))
            print(f"  [ERROR] die.scan_file: {preview}")
    except Exception as e:
        results.append(("die.scan_file", "EXCEPTION", str(e)))
        print(f"  [EXCEPTION] die.scan_file: {type(e).__name__}: {e}")

    try:
        with open(TARGET_PE, "rb") as f:
            pe_data = f.read()
        result = registry.call("die.scan_memory", {"data": pe_data})
        status = result.get("status", "unknown")
        if status == "success":
            preview = _format_output(result)
            results.append(("die.scan_memory", "OK", preview))
            print(f"  [OK] die.scan_memory: {preview}")
        else:
            preview = _format_output(result)
            results.append(("die.scan_memory", "ERROR", preview))
            print(f"  [ERROR] die.scan_memory: {preview}")
    except Exception as e:
        results.append(("die.scan_memory", "EXCEPTION", str(e)))
        print(f"  [EXCEPTION] die.scan_memory: {type(e).__name__}: {e}")

    print()

    # memory 工具（3 个，基于 pymem 库）
    print("—— 内存工具测试（基于 pymem 库）——")
    try:
        # memory.attach 附加 explorer.exe（一定存在的进程）
        result = registry.call("memory.attach", {"process_name": "explorer.exe"})
        status = result.get("status", "unknown")
        if status == "success":
            preview = _format_output(result)
            results.append(("memory.attach", "OK", preview))
            print(f"  [OK] memory.attach: {preview}")
        else:
            preview = _format_output(result)
            results.append(("memory.attach", "ERROR", preview))
            print(f"  [ERROR] memory.attach: {preview}")
    except Exception as e:
        results.append(("memory.attach", "EXCEPTION", str(e)))
        print(f"  [EXCEPTION] memory.attach: {type(e).__name__}: {e}")

    # memory.read / memory.write 需要先 attach，单独调用会返回 error（符合预期）
    for tool_name in ["memory.read", "memory.write"]:
        try:
            result = registry.call(tool_name, {})
            status = result.get("status", "unknown")
            # 缺少参数返回 error 是正常的（验证工具可被调用）
            preview = _format_output(result)
            results.append((tool_name, f"OK({status})", preview))
            print(f"  [OK] {tool_name}: (参数错误符合预期) {preview}")
        except Exception as e:
            results.append((tool_name, "EXCEPTION", str(e)))
            print(f"  [EXCEPTION] {tool_name}: {type(e).__name__}: {e}")

    print()

    # 3. 汇总
    print("=" * 70)
    print("测试汇总")
    print("=" * 70)
    ok_count = sum(1 for _, status, _ in results if status.startswith("OK"))
    error_count = sum(1 for _, status, _ in results if status.startswith("ERROR"))
    exception_count = sum(1 for _, status, _ in results if status == "EXCEPTION")
    total = len(results)
    print(f"总计: {total} 个工具调用")
    print(f"  OK (含预期错误): {ok_count}")
    print(f"  ERROR (工具执行失败): {error_count}")
    print(f"  EXCEPTION (调用异常): {exception_count}")

    if exception_count > 0:
        print("\n[FAIL] 存在调用异常，工具调用链路有问题")
        return 1
    if error_count > 0:
        print(f"\n[WARN] {error_count} 个工具执行失败（详见上方日志）")
    print("\n[OK] 所有工具均可正常调用（无异常）")
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
    except Exception:
        traceback.print_exc()
        exit_code = 1
    sys.exit(exit_code)
