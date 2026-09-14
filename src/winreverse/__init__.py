"""WinReverseAgent — Windows 原生逆向工程 AI Agent。

面向 Windows 平台的取证 / 逆向一体化工具：
- CLI（Typer）+ TUI（Textual）双入口
- 内部工具总线（47 个 ToolInterface）+ Skill 预置执行流
- Android 取证、内存取证、动态行为分析、网络协议分析

版本号统一定义在此处，CLI 的 --version 与 info 命令均读取它。
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
