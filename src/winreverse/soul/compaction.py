"""winreverse.soul.compaction — 会话上下文压缩引擎。

移植自 KXNSv2 soul/compaction.py（同源 kimi-cli Apache-2.0 血统，
kosong API 兼容已验证），本地化改动：
- 命名空间 winreverse.soul.*；常量复用本地 constants.SECURITY_KEYWORDS
- content 提取按 kosong 2.0 的 ContentPart 多态模型（属性/载荷访问）重写，
  替换原 dict/part 双兼容分支
- mypy strict 全量类型标注

分层策略（便宜的先上，贵的兜底）：
1. MicroCompact —— 无 LLM：将较早的（可配置类）工具结果就地替换为占位符
2. SnipCompact —— 无 LLM：按比例裁剪旧消息，工具调用配对保护
3. SimpleCompaction —— 需 LLM：将旧历史打包为单条消息请求总结，
   保留最近 max_preserved_messages 条原文
4. Compactor —— 门面：SIMPLE（保最近 1/3）/ SELECTIVE（旧工具结果截断）
   / LAYERED（增量摘要链，默认）

触发判定 should_auto_compact：token 达到 max_context_size * trigger_ratio，
或 token + reserved_context_size 超限。

参考：kimi-cli soul/compaction.py（Apache-2.0）、实施方案 §8.2.3
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from enum import Enum
from typing import NamedTuple, Protocol, runtime_checkable

from kosong.types import ContentPart, Message, MessageRole, TokenUsage
from winreverse.soul.constants import SECURITY_KEYWORDS

logger = logging.getLogger(__name__)


class CompactionStrategy(str, Enum):
    """压缩策略：simple=保最近 1/3；selective=旧工具结果截断；layered=增量摘要链。"""

    SIMPLE = "simple"
    SELECTIVE = "selective"
    LAYERED = "layered"


class CompactionResult(NamedTuple):
    """一次压缩的结果。

    Attributes:
        messages: 压缩后的消息序列（SYSTEM 摘要在前，保留消息在后）
        original_tokens: 压缩前估算 token 数
        compacted_tokens: 压缩后估算 token 数
        removed_messages: 被移除/合并的消息条数
        strategy_used: 实际使用的策略
        usage: LLM 总结调用的真实用量（无 LLM 压缩时为 None）
    """

    messages: Sequence[Message]
    original_tokens: int
    compacted_tokens: int
    removed_messages: int
    strategy_used: CompactionStrategy
    usage: TokenUsage | None = None

    @property
    def estimated_token_count(self) -> int:
        """压缩后 token 估算：LLM 总结用真实 output 用量，其余走启发式。"""
        if self.usage is not None and len(self.messages) > 0:
            summary_tokens = int(
                getattr(self.usage, "output_tokens", 0) or getattr(self.usage, "output", 0) or 0
            )
            preserved_tokens = estimate_text_tokens(self.messages[1:])
            return summary_tokens + preserved_tokens
        return estimate_text_tokens(self.messages)


# =============================================================================
# token 估算（CJK 感知，tiktoken 可用时精确、不可用时启发式，保证离线可用）
# =============================================================================


def _count_cjk_chars(text: str) -> int:
    """统计 CJK 字符数（汉字 / 假名 / 谚文 / CJK 扩展 A 区）。

    CJK 字符在 BPE 分词下通常 1 字符 ≈ 0.66~2 token，
    与纯 ASCII 的 4 字符 ≈ 1 token 差异显著，需单独计价。
    """
    count = 0
    for ch in text:
        if (
            "\u4e00" <= ch <= "\u9fff"
            or "\u3040" <= ch <= "\u30ff"
            or "\uac00" <= ch <= "\ud7af"
            or 0x3400 <= ord(ch) <= 0x4DBF
        ):
            count += 1
    return count


def _part_to_text(part: ContentPart) -> str:
    """单个 ContentPart 转文本（供压缩输入使用）。

    - text: 原文
    - image_url: 占位说明（data: 不展开内容）
    - video_url / audio_url / 其他媒体: 占位说明
    - think: 思考内容直接丢弃（不进入压缩输入，节省 token）
    """
    dump = part.model_dump()
    part_type = str(dump.get("type", ""))
    if part_type == "text":
        return str(dump.get("text", ""))
    if part_type == "think":
        return ""
    if part_type == "image_url":
        payload = dump.get("image_url") or {}
        url = str(payload.get("url", "")) if isinstance(payload, dict) else ""
        if url.startswith("data:"):
            return "\n[Image attached (base64)]\n"
        return f"\n[Image attached: {url[:200]}]\n"
    if part_type == "video_url":
        return "\n[Video attached]\n"
    if part_type == "audio_url":
        return "\n[Audio attached]\n"
    return f"\n[{part_type or 'media'} content attached]\n"


def _message_text(msg: Message) -> str:
    """将一条消息的全部文本内容拼接出来。"""
    return "".join(_part_to_text(part) for part in msg.content)


def estimate_text_tokens(messages: Sequence[Message]) -> int:
    """启发式 token 估算：ASCII 按 4 字符/token，CJK 按 1.5 字符/token。"""
    total_chars = 0
    cjk_chars = 0
    for msg in messages:
        text = _message_text(msg)
        total_chars += len(text)
        cjk_chars += _count_cjk_chars(text)
    non_cjk_chars = total_chars - cjk_chars
    return (non_cjk_chars // 4) + (cjk_chars * 2 // 3)


def _estimate_message_tokens(messages: list[Message], model: str = "cl100k_base") -> int:
    """消息序列 token 估算：tiktoken 可用时精确计算，否则退回启发式。

    tiktoken 首次使用需联网下载 BPE 词表，离线/隔离环境会抛网络异常，
    统一回退到 estimate_text_tokens 保证离线可用。
    """
    try:
        import tiktoken

        try:
            encoding = tiktoken.encoding_for_model(model)
        except KeyError:
            encoding = tiktoken.get_encoding("cl100k_base")
    except ImportError:
        return estimate_text_tokens(messages)
    except Exception:
        return estimate_text_tokens(messages)

    total = 0
    for msg in messages:
        total += 4  # 每条消息的格式开销
        total += len(encoding.encode(_message_text(msg)))
        if msg.tool_calls:
            for tc in msg.tool_calls:
                name = tc.function.name if tc.function else ""
                total += len(encoding.encode(name))
                args = tc.function.arguments
                if args:
                    total += len(encoding.encode(args))
        if msg.role:
            role_str = msg.role.value if isinstance(msg.role, Enum) else str(msg.role)
            total += len(encoding.encode(role_str))
    return total


def should_auto_compact(
    token_count: int,
    max_context_size: int,
    *,
    trigger_ratio: float = 0.8,
    reserved_context_size: int = 0,
) -> bool:
    """判定是否应触发自动压缩（比例阈值或预留空间超限）。"""
    return (
        token_count >= max_context_size * trigger_ratio
        or token_count + reserved_context_size >= max_context_size
    )


# =============================================================================
# 工具调用配对保护（压缩不拆散 assistant tool_calls 与 tool 结果）
# =============================================================================


def _find_tool_pair_indices(messages: list[Message]) -> dict[int, list[int]]:
    """建立 assistant(tool_calls) 下标 → tool 结果下标列表 的配对映射。"""
    tool_call_to_assistant: dict[str, int] = {}
    for i, msg in enumerate(messages):
        if msg.role == MessageRole.ASSISTANT and msg.tool_calls:
            for tc in msg.tool_calls:
                tool_call_to_assistant[tc.id] = i
    pairs: dict[int, list[int]] = {}
    for j, msg in enumerate(messages):
        if msg.role == MessageRole.TOOL and msg.tool_call_id:
            assistant_idx = tool_call_to_assistant.get(msg.tool_call_id)
            if assistant_idx is not None:
                pairs.setdefault(assistant_idx, []).append(j)
    return pairs


def _protect_tool_pairs(
    old_indices: set[int],
    recent_indices: set[int],
    pair_map: dict[int, list[int]],
) -> tuple[set[int], set[int]]:
    """将被压缩区与保留区拆散的调用对整体挪入保留区（迭代到不动点）。"""
    changed = True
    while changed:
        changed = False
        for assistant_idx, tool_indices in pair_map.items():
            all_indices = {assistant_idx, *tool_indices}
            in_old = all_indices & old_indices
            in_recent = all_indices & recent_indices
            if in_old and in_recent:
                for idx in in_old:
                    old_indices.discard(idx)
                    recent_indices.add(idx)
                changed = True
    return old_indices, recent_indices


# =============================================================================
# LLM Provider 协议（压缩总结用）
# =============================================================================


@runtime_checkable
class CompactionLLMProvider(Protocol):
    """压缩总结所需的 LLM Provider 最小协议。

    仅要求 generate(messages, model) -> 带 .message.content 的结果对象；
    generate_streaming（OpenAI chunk 流式形态）是运行时可选增强，
    由 SimpleCompaction 通过 hasattr 探测分派。
    """

    async def generate(self, messages: list[Message], model: str) -> object: ...


class RuntimeLLMProvider:
    """把 Runtime.llm（generate(messages=, model=) 形态）适配为压缩 Provider。

    只暴露非流式 generate（压缩总结不需要流式输出），
    屏蔽 tools 等压缩用不到的参数。
    """

    def __init__(self, llm: object) -> None:
        self._llm = llm

    async def generate(self, messages: list[Message], model: str) -> object:
        """调用底层 LLM 的 generate(messages=, model=)。"""
        generate_fn = getattr(self._llm, "generate", None)
        if generate_fn is None:
            raise RuntimeError("LLM manager missing generate() method")
        return await generate_fn(messages=messages, model=model)


# =============================================================================
# SimpleCompaction —— LLM 总结式压缩
# =============================================================================


class SimpleCompaction:
    """将旧历史打包为一条压缩请求，由 LLM 总结，保留最近 N 条原文。"""

    class PrepareResult(NamedTuple):
        """prepare 的产物：压缩请求消息 + 原样保留的消息。"""

        compact_message: Message | None
        to_preserve: Sequence[Message]

    def __init__(
        self,
        max_preserved_messages: int = 2,
        llm_provider: CompactionLLMProvider | None = None,
    ) -> None:
        self.max_preserved_messages = max_preserved_messages
        self._llm_provider = llm_provider

    def prepare(
        self, messages: Sequence[Message], *, custom_instruction: str = ""
    ) -> SimpleCompaction.PrepareResult:
        """从尾部向前保留 max_preserved_messages 条 user/assistant 消息，
        其余打包为一条压缩请求消息。"""
        if not messages or self.max_preserved_messages <= 0:
            return self.PrepareResult(compact_message=None, to_preserve=messages)

        history = list(messages)
        preserve_start_index = len(history)
        n_preserved = 0
        for index in range(len(history) - 1, -1, -1):
            role = history[index].role
            role_str = role.value if isinstance(role, Enum) else str(role)
            if role_str in {"user", "assistant"}:
                n_preserved += 1
                if n_preserved == self.max_preserved_messages:
                    preserve_start_index = index
                    break

        if n_preserved < self.max_preserved_messages:
            return self.PrepareResult(compact_message=None, to_preserve=messages)

        to_compact = history[:preserve_start_index]
        to_preserve = history[preserve_start_index:]

        if not to_compact:
            return self.PrepareResult(compact_message=None, to_preserve=to_preserve)

        compact_texts: list[str] = []
        for i, msg in enumerate(to_compact):
            role_str = msg.role.value if isinstance(msg.role, Enum) else str(msg.role)
            text = _message_text(msg)
            compact_texts.append(f"## Message {i + 1}\nRole: {role_str}\nContent:\n{text}")

        prompt_text = "\n".join(compact_texts) + "\nPlease compact the above conversation."
        if custom_instruction:
            prompt_text += f"\n\n**User's Custom Compaction Instruction:**\n{custom_instruction}"

        compact_message = Message(
            role=MessageRole.USER,
            content=[{"type": "text", "text": prompt_text}],
        )
        return self.PrepareResult(compact_message=compact_message, to_preserve=to_preserve)

    async def compact(
        self,
        messages: Sequence[Message],
        *,
        custom_instruction: str = "",
        model: str = "cl100k_base",
    ) -> CompactionResult:
        """执行压缩：有 LLM 时生成总结，无 LLM 或失败时退化为仅保留最近消息。"""
        original_tokens = _estimate_message_tokens(list(messages), model)
        prepared = self.prepare(messages, custom_instruction=custom_instruction)

        if prepared.compact_message is None:
            return CompactionResult(
                messages=prepared.to_preserve,
                original_tokens=original_tokens,
                compacted_tokens=original_tokens,
                removed_messages=0,
                strategy_used=CompactionStrategy.SIMPLE,
                usage=None,
            )

        summary_text: str | None = None
        usage: TokenUsage | None = None
        if self._llm_provider is not None:
            try:
                conversation_text = _message_text(prepared.compact_message)
                prompt_text = (
                    "Summarize the following conversation, preserving all key facts, decisions, "
                    "tool calls and their results, code changes, and important context. "
                    "Be concise but complete. Do not lose any actionable information.\n\n"
                    f"{conversation_text}"
                )
                if custom_instruction:
                    prompt_text += (
                        f"\n\n**User's Custom Compaction Instruction:**\n{custom_instruction}"
                    )
                compact_request = [
                    Message(
                        role=MessageRole.USER,
                        content=[{"type": "text", "text": prompt_text}],
                    )
                ]
                provider = self._llm_provider
                if hasattr(provider, "generate_streaming"):
                    accumulated = ""
                    async for chunk in provider.generate_streaming(compact_request, model):
                        choices = chunk.get("choices", [])
                        if isinstance(choices, list) and choices:
                            delta = choices[0].get("delta", {})
                            if isinstance(delta, dict) and delta.get("content"):
                                accumulated += str(delta["content"])
                    summary_text = accumulated or None
                else:
                    result = await provider.generate(compact_request, model)
                    result_message = getattr(result, "message", None)
                    if result_message is not None:
                        summary_text = _message_text(result_message) or None
                    elif isinstance(result, str):
                        summary_text = result or None
            except Exception as e:
                logger.warning("LLM compression failed, falling back to keep-recent: %s", e)

        if summary_text is not None:
            summary_message = Message(
                role=MessageRole.SYSTEM,
                content=[{"type": "text", "text": f"[Previously compacted]\n{summary_text}"}],
            )
            result_messages: list[Message] = [summary_message, *prepared.to_preserve]
        else:
            result_messages = list(prepared.to_preserve)

        result_tokens = _estimate_message_tokens(result_messages, model)
        return CompactionResult(
            messages=result_messages,
            original_tokens=original_tokens,
            compacted_tokens=result_tokens,
            removed_messages=len(messages) - len(result_messages),
            strategy_used=CompactionStrategy.SIMPLE,
            usage=usage,
        )


# =============================================================================
# AutoCompact —— 带熔断的自动压缩触发器
# =============================================================================


class AutoCompact:
    """自动压缩触发器：连续失败达阈值后熔断（停止触发），避免反复失败拖垮会话。"""

    def __init__(
        self,
        *,
        trigger_ratio: float = 0.8,
        buffer_tokens: int = 13000,
        max_consecutive_failures: int = 3,
    ) -> None:
        self._trigger_ratio = trigger_ratio
        self._buffer_tokens = buffer_tokens
        self._max_consecutive_failures = max_consecutive_failures
        self._consecutive_failures: int = 0

    def should_compact(
        self,
        token_count: int,
        max_context_size: int,
        *,
        reserved_context_size: int = 0,
    ) -> bool:
        """是否触发压缩（熔断打开时永远返回 False）。"""
        if self._consecutive_failures >= self._max_consecutive_failures:
            return False
        return should_auto_compact(
            token_count,
            max_context_size,
            trigger_ratio=self._trigger_ratio,
            reserved_context_size=reserved_context_size,
        )

    def record_success(self) -> None:
        """压缩成功后重置失败计数。"""
        self._consecutive_failures = 0

    def record_failure(self) -> None:
        """压缩失败累计；达到阈值时触发熔断告警。"""
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._max_consecutive_failures:
            logger.warning(
                "AutoCompact circuit breaker tripped after %d consecutive failures",
                self._consecutive_failures,
            )

    @property
    def consecutive_failures(self) -> int:
        """当前连续失败次数。"""
        return self._consecutive_failures

    @property
    def buffer_tokens(self) -> int:
        """预留 token 缓冲（LLM 输出 + 工具结果的增长空间）。"""
        return self._buffer_tokens


# =============================================================================
# MicroCompact —— 无 LLM 的旧工具结果就地清理
# =============================================================================


class MicroCompact:
    """将较早的可压缩工具结果就地替换为占位符（保留最近 keep_recent 条）。"""

    def __init__(
        self,
        *,
        compactable_tools: set[str] | None = None,
        keep_recent: int = 3,
        gap_threshold_minutes: float = 30.0,
        enabled: bool = True,
    ) -> None:
        self._compactable_tools = compactable_tools or set()
        self._keep_recent = keep_recent
        self._gap_threshold_minutes = gap_threshold_minutes
        self._enabled = enabled

    def compact(
        self,
        messages: list[Message],
        *,
        model: str = "cl100k_base",
    ) -> tuple[list[Message], int]:
        """返回 (清理后的消息, 节省的 token 数)。"""
        if not self._enabled:
            return messages, 0

        compactable_ids = self._collect_compactable_tool_ids(messages)
        if not compactable_ids:
            return messages, 0

        keep_recent = max(1, self._keep_recent)
        clear_set = set(compactable_ids[:-keep_recent])

        if not clear_set:
            return messages, 0

        tokens_saved = 0
        result_messages: list[Message] = []
        for msg in messages:
            if msg.role == MessageRole.TOOL and msg.tool_call_id in clear_set:
                text = _message_text(msg)
                tokens_saved += len(text) // 4
                result_messages.append(
                    Message(
                        role=msg.role,
                        content=[{"type": "text", "text": "[Old tool result content cleared]"}],
                        tool_call_id=msg.tool_call_id,
                    )
                )
            else:
                result_messages.append(msg)

        if tokens_saved > 0:
            logger.info(
                "MicroCompact: cleared %d tool results, ~%d tokens saved",
                len(clear_set),
                tokens_saved,
            )

        return result_messages, tokens_saved

    def _collect_compactable_tool_ids(self, messages: list[Message]) -> list[str]:
        """收集可清理的工具调用 id（限定 compactable_tools 白名单内）。"""
        ids: list[str] = []
        for msg in messages:
            if msg.role == MessageRole.ASSISTANT and msg.tool_calls:
                for tc in msg.tool_calls:
                    tc_name = tc.function.name if tc.function else ""
                    if not self._compactable_tools or tc_name in self._compactable_tools:
                        ids.append(tc.id)
        return ids


# =============================================================================
# SnipCompact —— 按比例裁剪（配对保护，无 LLM）
# =============================================================================


class SnipCompact:
    """保留最近 max_snip_ratio 比例的消息，其余整体移除（系统消息始终保留）。"""

    def __init__(
        self,
        *,
        max_snip_ratio: float = 0.5,
        enabled: bool = True,
    ) -> None:
        self._max_snip_ratio = max_snip_ratio
        self._enabled = enabled

    def compact(
        self,
        messages: list[Message],
        *,
        model: str = "cl100k_base",
    ) -> tuple[list[Message], int]:
        """返回 (裁剪后的消息, 释放的 token 数)。"""
        if self._enabled is False or not messages:
            return messages, 0

        total_tokens = _estimate_message_tokens(messages, model)
        if total_tokens == 0:
            return messages, 0

        system_messages = [m for m in messages if m.role == MessageRole.SYSTEM]
        non_system = [m for m in messages if m.role != MessageRole.SYSTEM]

        max_keep = int(len(messages) * self._max_snip_ratio)
        if max_keep >= len(non_system):
            return messages, 0

        pair_map = _find_tool_pair_indices(non_system)
        recent_indices = set(range(len(non_system) - max_keep, len(non_system)))
        old_indices = set(range(len(non_system) - max_keep))
        old_indices, recent_indices = _protect_tool_pairs(old_indices, recent_indices, pair_map)

        kept = [non_system[i] for i in sorted(recent_indices)]
        result_messages = system_messages + kept
        result_tokens = _estimate_message_tokens(result_messages, model)
        tokens_freed = total_tokens - result_tokens

        if tokens_freed > 0:
            logger.info(
                "SnipCompact: removed %d messages, ~%d tokens freed",
                len(non_system) - len(kept),
                tokens_freed,
            )

        return result_messages, tokens_freed


# =============================================================================
# Compactor —— 策略门面
# =============================================================================

# 摘要链中单条消息的最大截取长度
_SUMMARY_MSG_LIMIT = 500
# 含安全关键词的工具结果放宽到该长度（证据细节不能丢）
_SUMMARY_SECURITY_LIMIT = 800
# 压缩摘要总量上限（字符）
_MAX_SUMMARY_CHARS = 16000
# SELECTIVE 策略下旧工具结果的首尾保留长度
_TRUNCATE_KEEP = 250


def _is_security_content(text: str) -> bool:
    """内容是否包含安全取证关键词（决定摘要放行长度）。"""
    lowered = text.lower()
    return any(kw in lowered for kw in SECURITY_KEYWORDS)


class Compactor:
    """压缩门面：按策略组织 Micro/Snip/Simple 三层能力。

    - SIMPLE: 保留最近 1/3 消息，其余丢弃（配对保护）
    - SELECTIVE: 同 SIMPLE，但旧区工具结果做首尾截断保留（保留证据线索）
    - LAYERED（默认）: 旧区折叠为增量摘要链（[Previously compacted] + [Newly compacted]），
      含安全关键词的工具结果放宽截取长度
    """

    def __init__(
        self,
        strategy: CompactionStrategy = CompactionStrategy.LAYERED,
        max_tokens: int = 100000,
        llm_provider: CompactionLLMProvider | None = None,
    ) -> None:
        self._strategy = strategy
        self._max_tokens = max_tokens
        self._llm_provider = llm_provider
        self._simple = SimpleCompaction(llm_provider=llm_provider)
        self._auto = AutoCompact()
        self._micro = MicroCompact()
        self._snip = SnipCompact()

    @property
    def max_tokens(self) -> int:
        """配置的上下文窗口上限。"""
        return self._max_tokens

    @property
    def has_llm(self) -> bool:
        """是否配置了 LLM Provider（决定能否做总结式压缩）。"""
        return self._llm_provider is not None

    @property
    def auto_compact(self) -> AutoCompact:
        """自动压缩触发器（含熔断状态）。"""
        return self._auto

    @property
    def micro_compact(self) -> MicroCompact:
        """微压缩器（旧工具结果清理）。"""
        return self._micro

    @property
    def snip_compact(self) -> SnipCompact:
        """裁剪器（按比例移除旧消息）。"""
        return self._snip

    def compact(
        self,
        messages: list[Message],
        model: str,
        max_tokens: int | None = None,
    ) -> tuple[list[Message], CompactionResult]:
        """按当前策略压缩消息序列（无需 LLM，确定性执行）。"""
        effective_max = max_tokens or self._max_tokens
        original_tokens = _estimate_message_tokens(messages, model)

        system_messages = [m for m in messages if m.role == MessageRole.SYSTEM]
        non_system = [m for m in messages if m.role != MessageRole.SYSTEM]

        if self._strategy == CompactionStrategy.SIMPLE:
            result_messages = self._compact_simple(non_system, system_messages)
        elif self._strategy == CompactionStrategy.SELECTIVE:
            result_messages = self._compactive_selective(non_system, system_messages)
        else:
            result_messages = self._compact_layered(messages, non_system, system_messages)

        result_tokens = _estimate_message_tokens(result_messages, model)
        _ = effective_max  # 保留参数供未来按窗口大小动态选策略
        return result_messages, CompactionResult(
            messages=result_messages,
            original_tokens=original_tokens,
            compacted_tokens=result_tokens,
            removed_messages=len(messages) - len(result_messages),
            strategy_used=self._strategy,
        )

    def _keep_split(self, non_system: list[Message]) -> tuple[set[int], set[int], int] | None:
        """计算保留区/压缩区下标（保留最近 1/3，最少 2 条），无需压缩返回 None。"""
        keep_recent = max(2, len(non_system) // 3)
        if len(non_system) <= keep_recent:
            return None
        split_point = len(non_system) - keep_recent
        old_indices = set(range(split_point))
        recent_indices = set(range(split_point, len(non_system)))
        pair_map = _find_tool_pair_indices(non_system)
        old_indices, recent_indices = _protect_tool_pairs(old_indices, recent_indices, pair_map)
        return old_indices, recent_indices, split_point

    def _compact_simple(
        self, non_system: list[Message], system_messages: list[Message]
    ) -> list[Message]:
        """SIMPLE：保留最近 1/3，其余丢弃。"""
        split = self._keep_split(non_system)
        if split is None:
            # 无需压缩时必须原样返回全部消息（含 system），不得丢弃系统提示
            return [*system_messages, *non_system]
        _old, recent_indices, _split_point = split
        kept = [non_system[i] for i in sorted(recent_indices)]
        return system_messages + kept

    def _compactive_selective(
        self, non_system: list[Message], system_messages: list[Message]
    ) -> list[Message]:
        """SELECTIVE：旧区工具结果首尾截断保留，普通旧消息丢弃。"""
        split = self._keep_split(non_system)
        if split is None:
            # 无需压缩时必须原样返回全部消息（含 system），不得丢弃系统提示
            return [*system_messages, *non_system]
        _old_indices, recent_indices, _split_point = split
        result_messages: list[Message] = list(system_messages)
        for i, msg in enumerate(non_system):
            if i in recent_indices:
                result_messages.append(msg)
            elif msg.role == MessageRole.TOOL:
                text = _message_text(msg)
                if len(text) > _TRUNCATE_KEEP * 2:
                    compressed = (
                        text[:_TRUNCATE_KEEP] + "\n...[truncated]...\n" + text[-_TRUNCATE_KEEP:]
                    )
                    result_messages.append(
                        Message(
                            role=msg.role,
                            content=[{"type": "text", "text": compressed}],
                            tool_call_id=msg.tool_call_id,
                        )
                    )
                else:
                    result_messages.append(msg)
            # 旧区的 user/assistant 消息丢弃（已含在 recent 或被摘要取代）
        return result_messages

    def _compact_layered(
        self,
        messages: list[Message],
        non_system: list[Message],
        system_messages: list[Message],
    ) -> list[Message]:
        """LAYERED：旧区折叠为增量摘要链，保持既有 [Previously compacted] 前缀衔接。"""
        # 分离历史摘要与干净消息（摘要链递进：旧摘要收缩 + 新摘要追加）
        prior: str | None = None
        messages_clean: list[Message] = []
        for msg in messages:
            text = _message_text(msg)
            if msg.role == MessageRole.SYSTEM and text.startswith("[Previously compacted]"):
                prior = text
            else:
                messages_clean.append(msg)

        clean_system = [m for m in messages_clean if m.role == MessageRole.SYSTEM]
        clean_non_system = [m for m in messages_clean if m.role != MessageRole.SYSTEM]

        keep_recent = max(4, len(clean_non_system) // 2)
        if len(clean_non_system) <= keep_recent:
            return messages

        pair_map = _find_tool_pair_indices(clean_non_system)
        split_point = len(clean_non_system) - keep_recent
        old_indices = set(range(split_point))
        recent_indices = set(range(split_point, len(clean_non_system)))
        old_indices, recent_indices = _protect_tool_pairs(old_indices, recent_indices, pair_map)

        old_messages = [clean_non_system[i] for i in sorted(old_indices)]
        recent_messages = [clean_non_system[i] for i in sorted(recent_indices)]

        summary_parts: list[str] = []
        for msg in old_messages:
            text = _message_text(msg)
            if not text:
                continue
            role_str = msg.role.value if isinstance(msg.role, Enum) else str(msg.role)
            is_tool_result = msg.role == MessageRole.TOOL
            limit = (
                _SUMMARY_SECURITY_LIMIT
                if is_tool_result and _is_security_content(text)
                else _SUMMARY_MSG_LIMIT
            )
            summary_parts.append(f"[{role_str}]: {text[:limit]}")

        if not summary_parts:
            # 旧区被配对保护掏空（或全部为空内容）：无可摘要内容，注入空摘要
            # 反而使结果多于输入（removed_messages 为负），按无需压缩原样返回
            return messages

        new_summary = "\n".join(summary_parts)
        if len(new_summary) > _MAX_SUMMARY_CHARS:
            new_summary = new_summary[:_MAX_SUMMARY_CHARS]

        if prior:
            prior_budget = _MAX_SUMMARY_CHARS // 3
            prior_text = prior
            if prior_text.startswith("[Previously compacted]"):
                prior_text = prior_text[len("[Previously compacted]") :].strip()
            if len(prior_text) > prior_budget:
                prior_text = prior_text[:prior_budget] + "\n...[older summary truncated]..."
            new_budget = max(_MAX_SUMMARY_CHARS - len(prior_text) - 50, 1000)
            if len(new_summary) > new_budget:
                new_summary = new_summary[:new_budget] + "\n...[newer summary truncated]..."
            summary_content = (
                f"[Previously compacted]\n{prior_text}\n\n[Newly compacted]\n{new_summary}"
            )
        else:
            summary_content = f"[Previously compacted]\n{new_summary}"

        summary_message = Message(
            role=MessageRole.SYSTEM,
            content=[{"type": "text", "text": summary_content}],
        )
        return [*clean_system, summary_message, *recent_messages]

    async def compact_with_llm(
        self,
        messages: list[Message],
        model: str,
        max_tokens: int | None = None,
        *,
        custom_instruction: str = "",
    ) -> CompactionResult:
        """LLM 总结式压缩（SimpleCompaction），供 /compact 等显式触发。"""
        _ = max_tokens
        return await self._simple.compact(
            messages,
            custom_instruction=custom_instruction,
            model=model,
        )

    def estimate_tokens(self, messages: list[Message], model: str) -> int:
        """消息序列 token 估算。"""
        return _estimate_message_tokens(messages, model)
