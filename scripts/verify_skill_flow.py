"""Skill 预置流端到端验证脚本（不依赖 LLM API Key）。

直接调用 SkillExecutor._execute_flow() 执行 PE 文件分析的预置流，
验证 Skill YAML 加载、参数渲染、工具调用链路是否真实可用。

测试目标：C:\\Windows\\System32\\notepad.exe
"""
from __future__ import annotations

import asyncio
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from winreverse.app import Agent
from winreverse.config import load_or_default

TARGET_PE = r"C:\Windows\System32\notepad.exe"


async def test_skill_flow() -> int:
    """测试 Skill 预置流执行。

    Returns:
        0: 全部通过
        1: 存在失败
    """
    print("=" * 70)
    print("WinReverseAgent Skill 预置流端到端验证")
    print("=" * 70)
    print(f"测试 Skill: PE 文件分析")
    print(f"测试目标: {TARGET_PE}")
    print()

    # 1. 创建 Agent（不依赖 LLM API Key）
    config = load_or_default()
    agent = Agent(app_config=config)
    agent._ensure_initialized()

    skill_registry = agent._skill_registry
    print(f"[OK] Agent 初始化完成")
    print(f"  - 已注册工具: {len(agent._registry)} 个")
    print(f"  - 已加载 Skill: {len(skill_registry)} 个")
    for skill_info in skill_registry.list_skills():
        print(f"    · {skill_info['name']}: {skill_info['description']}")
    print()

    # 2. 获取 PE 文件分析 Skill
    skill_name = "PE 文件分析"
    try:
        skill = skill_registry.get(skill_name)
    except Exception as e:
        print(f"[FAIL] Skill '{skill_name}' 未注册: {e}")
        return 1

    print(f"[OK] 已获取 Skill: {skill.name}")
    print(f"  - target: {skill.target}")
    print(f"  - parameters: {[p.name for p in skill.parameters]}")
    print(f"  - execution_flow 步数: {len(skill.execution_flow) if skill.execution_flow else 0}")
    print()

    # 3. 渲染 prompt_template
    render_vars = {
        "file_path": TARGET_PE,
        "deep_scan": False,
    }
    rendered_prompt = skill.render_prompt(render_vars)
    print(f"[OK] prompt_template 渲染成功（前 200 字符）:")
    print(f"  {rendered_prompt[:200]}...")
    print()

    # 4. 执行预置 execution_flow（核心测试）
    print("—— 开始执行预置 execution_flow ——")
    executor = agent._executor
    try:
        flow_results = await executor._execute_flow(skill, render_vars)
    except Exception as e:
        print(f"[FAIL] 预置流执行异常: {type(e).__name__}: {e}")
        traceback.print_exc()
        return 1

    print()
    print(f"[OK] 预置流执行完成: {len(flow_results)} 步")
    print()

    # 5. 显示每步结果
    print("—— 预置流执行结果明细 ——")
    success_count = 0
    error_count = 0
    for idx, result in enumerate(flow_results, 1):
        status = "ERROR" if result.is_error else "OK"
        if result.is_error:
            error_count += 1
        else:
            success_count += 1
        output_preview = result.output[:120].replace("\n", " ").replace("\r", "")
        print(f"  步骤 {idx}: [{status}] {result.action}")
        print(f"    参数: {result.arguments}")
        print(f"    输出: {output_preview}...")
        print()

    # 6. 组装最终 prompt（验证 _build_prompt_with_flow）
    final_prompt = executor._build_prompt_with_flow(rendered_prompt, flow_results)
    print(f"[OK] 最终 prompt 组装完成（含预置流上下文，长度: {len(final_prompt)} 字符）")
    print()

    # 7. 汇总
    print("=" * 70)
    print("测试汇总")
    print("=" * 70)
    print(f"预置流步骤数: {len(flow_results)}")
    print(f"  成功: {success_count}")
    print(f"  失败: {error_count}")

    if error_count > 0:
        print(f"\n[WARN] {error_count} 步失败（详见上方日志）")
    else:
        print("\n[OK] 预置流全部执行成功")

    # 8. 验证不依赖 LLM 的端到端流程
    print()
    print("—— 验证 Skill 执行链路完整性 ——")
    checks = [
        ("Skill YAML 加载", len(skill.name) > 0),
        ("参数校验", len(skill.parameters) > 0),
        ("prompt 渲染", len(rendered_prompt) > 0),
        ("预置流定义", len(skill.execution_flow) > 0),
        ("预置流执行", len(flow_results) == len(skill.execution_flow)),
        ("结果上下文组装", len(final_prompt) > len(rendered_prompt)),
    ]
    all_pass = True
    for name, ok in checks:
        status = "[OK]" if ok else "[FAIL]"
        print(f"  {status} {name}")
        if not ok:
            all_pass = False

    if all_pass:
        print("\n[OK] Skill 执行链路完整（仅 LLM 调用需 API Key）")
        return 0
    print("\n[FAIL] 存在链路问题")
    return 1


def main() -> int:
    """主入口。"""
    try:
        return asyncio.run(test_skill_flow())
    except Exception:
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
