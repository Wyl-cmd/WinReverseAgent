"""测试模块：winreverse.llm_runtime

覆盖点：LLMAdapter 的 kosong↔OpenAI 双向格式转换（消息/工具/工具调用）、
finish_reason 映射、generate 的错误分类（401/404/连接/通用）与成功路径。
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from kosong.types import (
    Message,
    MessageRole,
    TextPart,
    Tool,
    ToolCall,
    ToolParameter,
)
from winreverse.config import LLMConfig
from winreverse.llm_runtime import LLMAdapter, LLMError


@pytest.fixture
def adapter() -> LLMAdapter:
    """指向本地假端点的适配器（构造不发网络请求）。"""
    config = LLMConfig(
        model="test-model",
        api_key=" test-key ",
        base_url=" http://127.0.0.1:9999/v1 ",
        max_tokens=100,
        temperature=0.5,
    )
    return LLMAdapter(config)


def _make_user_msg() -> Message:
    return Message(role=MessageRole.USER, content=[TextPart(text="分析样本")])


class TestConversionProperties:
    """元信息与纯文本转换。"""

    def test_provider_and_config(self, adapter: LLMAdapter) -> None:
        assert adapter.provider == "openai"
        assert adapter.config.model == "test-model"

    def test_parts_to_text_joins_and_skips_non_text(self) -> None:
        content = [
            SimpleNamespace(thinking="内部推理"),  # 无 text 属性 → 跳过
            TextPart(text="结论一。"),
            TextPart(text="结论二。"),
        ]
        assert LLMAdapter._parts_to_text(content) == "结论一。结论二。"

    def test_parts_to_text_empty(self) -> None:
        assert LLMAdapter._parts_to_text(None) == ""
        assert LLMAdapter._parts_to_text([]) == ""


class TestToOpenaiMessages:
    """kosong 消息 → OpenAI chat 格式。"""

    def test_user_message(self, adapter: LLMAdapter) -> None:
        result = adapter._to_openai_messages([_make_user_msg()])
        assert result == [{"role": "user", "content": "分析样本"}]

    def test_assistant_with_tool_calls(self, adapter: LLMAdapter) -> None:
        msg = Message(
            role=MessageRole.ASSISTANT,
            content=[TextPart(text="我来解析 PE")],
            tool_calls=[
                ToolCall(
                    id="call_1",
                    function=ToolCall.FunctionBody(name="pe.parse", arguments='{"a":1}'),
                ),
                ToolCall(
                    id="call_2",
                    function=ToolCall.FunctionBody(name="die.scan", arguments=None),
                ),
            ],
        )
        entry = adapter._to_openai_messages([msg])[0]
        assert entry["role"] == "assistant"
        assert entry["content"] == "我来解析 PE"
        assert entry["tool_calls"] == [
            {
                "id": "call_1",
                "type": "function",
                "function": {"name": "pe.parse", "arguments": '{"a":1}'},
            },
            {
                "id": "call_2",
                "type": "function",
                "function": {"name": "die.scan", "arguments": "{}"},  # None 归一为 "{}"
            },
        ]

    def test_tool_message_empty_content_gets_placeholder(self, adapter: LLMAdapter) -> None:
        """OpenAI 协议 tool 消息 content 不能为空。"""
        msg = Message(role=MessageRole.TOOL, content=[], tool_call_id="call_1")
        entry = adapter._to_openai_messages([msg])[0]
        assert entry["tool_call_id"] == "call_1"
        assert entry["content"] == "(empty tool result)"

    def test_tool_message_keeps_text(self, adapter: LLMAdapter) -> None:
        msg = Message(
            role=MessageRole.TOOL,
            content=[TextPart(text="sections: 5")],
            tool_call_id="call_9",
        )
        entry = adapter._to_openai_messages([msg])[0]
        assert entry["content"] == "sections: 5"


class TestToolToOpenai:
    """kosong Tool → OpenAI function 定义。"""

    def test_parameters_built_into_schema(self) -> None:
        tool = Tool(
            name="memory.attach",
            description="附加进程",
            parameters=[
                ToolParameter(name="process", type="string", description="进程名", required=True),
                ToolParameter(name="mode", type="string", required=False, enum=["fast", "deep"]),
            ],
        )
        spec = LLMAdapter._tool_to_openai(tool)
        assert spec["type"] == "function"
        assert spec["function"]["name"] == "memory.attach"
        schema = spec["function"]["parameters"]
        assert schema["type"] == "object"
        assert schema["required"] == ["process"]
        assert schema["properties"]["process"] == {
            "type": "string",
            "description": "进程名",
        }
        assert schema["properties"]["mode"]["enum"] == ["fast", "deep"]

    def test_explicit_schema_passthrough(self) -> None:
        schema = {"type": "object", "properties": {"x": {"type": "number"}}}
        tool = Tool(name="t", description="d", parameters_schema=schema)
        assert LLMAdapter._tool_to_openai(tool)["function"]["parameters"] == schema


class TestStopReasonMapping:
    """finish_reason → Soul stop_reason。"""

    @pytest.mark.parametrize(
        ("finish_reason", "expected"),
        [
            ("tool_calls", "tool_use"),
            ("length", "max_tokens"),
            ("stop", "stop"),
            (None, "stop"),
        ],
    )
    def test_mapping(self, finish_reason, expected: str) -> None:
        assert LLMAdapter._map_stop_reason(finish_reason) == expected


class TestGenerateErrors:
    """generate：错误分类与前置校验。"""

    @pytest.mark.asyncio
    async def test_no_model_raises(self) -> None:
        adapter = LLMAdapter(LLMConfig(model="", api_key="k"))
        with pytest.raises(LLMError, match="未配置模型名"):
            await adapter.generate([_make_user_msg()])

    async def _generate_with_failure(self, adapter: LLMAdapter, exc: Exception) -> LLMError:
        adapter._client.chat.completions.create = AsyncMock(side_effect=exc)
        with pytest.raises(LLMError) as exc_info:
            await adapter.generate([_make_user_msg()])
        return exc_info.value

    @pytest.mark.asyncio
    async def test_401_maps_to_auth_hint(self, adapter: LLMAdapter) -> None:
        err = await self._generate_with_failure(
            adapter, RuntimeError("Error code: 401 - Unauthorized")
        )
        assert "认证失败" in str(err)
        assert "api_key" in str(err)

    @pytest.mark.asyncio
    async def test_404_maps_to_endpoint_hint(self, adapter: LLMAdapter) -> None:
        err = await self._generate_with_failure(
            adapter, RuntimeError("Error code: 404 - Not Found")
        )
        assert "404" in str(err)
        assert "test-model" in str(err)  # 提示里带上当前模型名

    @pytest.mark.asyncio
    async def test_connection_error_maps_to_base_url_hint(self, adapter: LLMAdapter) -> None:
        err = await self._generate_with_failure(
            adapter, RuntimeError("Connection error while calling endpoint")
        )
        assert "无法连接 LLM 端点" in str(err)
        assert "http://127.0.0.1:9999/v1" in str(err)  # base_url 已去空白并回显

    @pytest.mark.asyncio
    async def test_generic_error_truncated(self, adapter: LLMAdapter) -> None:
        err = await self._generate_with_failure(adapter, RuntimeError("x" * 2000))
        msg = str(err)
        assert msg.startswith("LLM 调用失败")
        assert len(msg) < 600  # 超长错误被截断

    @pytest.mark.asyncio
    async def test_empty_choices_raises(self, adapter: LLMAdapter) -> None:
        response = SimpleNamespace(id="resp-1", choices=[], usage=None)
        adapter._client.chat.completions.create = AsyncMock(return_value=response)
        with pytest.raises(LLMError, match="空 choices"):
            await adapter.generate([_make_user_msg()])


class TestGenerateSuccess:
    """generate：成功路径的请求组装与结果还原。"""

    @pytest.mark.asyncio
    async def test_success_with_tools_and_usage(self, adapter: LLMAdapter) -> None:
        message = SimpleNamespace(
            content="附加进程完成",
            tool_calls=[
                SimpleNamespace(
                    id="call_1",
                    function=SimpleNamespace(name="memory.attach", arguments='{"process":"m.exe"}'),
                )
            ],
        )
        response = SimpleNamespace(
            id="resp-42",
            choices=[SimpleNamespace(message=message, finish_reason="tool_calls")],
            usage=SimpleNamespace(prompt_tokens=120, completion_tokens=30),
        )
        create = AsyncMock(return_value=response)
        adapter._client.chat.completions.create = create

        tools = [
            Tool(
                name="memory.attach",
                description="附加进程",
                parameters=[ToolParameter(name="process", type="string")],
            )
        ]
        result = await adapter.generate(
            [_make_user_msg()], tools=tools, max_tokens=256, temperature=0.2
        )

        # 请求参数：模型/消息转换/max_tokens/temperature 覆盖/工具定义
        kwargs = create.await_args.kwargs
        assert kwargs["model"] == "test-model"
        assert kwargs["messages"] == [{"role": "user", "content": "分析样本"}]
        assert kwargs["max_tokens"] == 256
        assert kwargs["temperature"] == 0.2
        assert kwargs["tools"][0]["function"]["name"] == "memory.attach"

        # 响应还原：assistant 消息带工具调用、usage 累计、stop_reason 映射
        assert result.id == "resp-42"
        assert result.stop_reason == "tool_use"
        assert result.message.role == MessageRole.ASSISTANT
        assert result.message.content[0].text == "附加进程完成"
        assert result.message.tool_calls is not None
        assert result.message.tool_calls[0].function.name == "memory.attach"
        assert result.usage is not None
        assert result.usage.input_tokens == 120  # Usage 契约字段（input_other 是错误的类型）
        assert result.usage.output_tokens == 30
        assert result.usage.total == 150

    @pytest.mark.asyncio
    async def test_no_tools_omits_tools_key(self, adapter: LLMAdapter) -> None:
        response = SimpleNamespace(
            id="r",
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="ok", tool_calls=None), finish_reason="stop"
                )
            ],
            usage=None,
        )
        create = AsyncMock(return_value=response)
        adapter._client.chat.completions.create = create

        result = await adapter.generate([_make_user_msg()])

        assert "tools" not in create.await_args.kwargs
        assert result.stop_reason == "stop"
        assert result.usage is None
        assert result.message.tool_calls is None
