from __future__ import annotations

from abc import ABC
from enum import Enum
from typing import Any, ClassVar, Literal, cast

from typing_extensions import override

from pydantic import BaseModel, Field, GetCoreSchemaHandler, field_serializer, field_validator
from pydantic_core import core_schema


JsonType = None | int | float | str | bool | list[Any] | dict[str, Any]


class MergeableMixin:
    def merge_in_place(self, other: Any) -> bool:
        return False


class ContentPart(BaseModel, ABC, MergeableMixin):
    __content_part_registry: ClassVar[dict[str, type["ContentPart"]]] = {}

    type: str

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        type_value = getattr(cls, "type", None)
        if type_value is None or not isinstance(type_value, str):
            raise ValueError(
                f"ContentPart subclass {cls.__name__} must have a `type` field of type `str`"
            )
        cls.__content_part_registry[type_value] = cls

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        if cls.__name__ == "ContentPart":

            def validate_content_part(value: Any) -> Any:
                if hasattr(value, "__class__") and issubclass(value.__class__, cls):
                    return value
                if isinstance(value, dict) and "type" in value:
                    type_value: Any | None = cast(dict[str, Any], value).get("type")
                    if not isinstance(type_value, str):
                        raise ValueError(f"Cannot validate {value} as ContentPart")
                    target_class = cls.__content_part_registry[type_value]
                    return target_class.model_validate(value)
                raise ValueError(f"Cannot validate {value} as ContentPart")

            return core_schema.no_info_plain_validator_function(validate_content_part)
        return handler(source_type)


class TextPart(ContentPart):
    type: str = "text"
    text: str

    @override
    def merge_in_place(self, other: Any) -> bool:
        if not isinstance(other, TextPart):
            return False
        self.text += other.text
        return True


class ThinkPart(ContentPart):
    type: str = "think"
    think: str
    encrypted: str | None = None

    @override
    def merge_in_place(self, other: Any) -> bool:
        if not isinstance(other, ThinkPart):
            return False
        if self.encrypted:
            return False
        self.think += other.think
        if other.encrypted:
            self.encrypted = other.encrypted
        return True


class ImageURLPart(ContentPart):
    class ImageURL(BaseModel):
        url: str
        id: str | None = None

    type: str = "image_url"
    image_url: ImageURL


class AudioURLPart(ContentPart):
    class AudioURL(BaseModel):
        url: str
        id: str | None = None

    type: str = "audio_url"
    audio_url: AudioURL


class VideoURLPart(ContentPart):
    class VideoURL(BaseModel):
        url: str
        id: str | None = None

    type: str = "video_url"
    video_url: VideoURL


class ToolCall(BaseModel, MergeableMixin):
    class FunctionBody(BaseModel):
        name: str
        arguments: str | None

    type: Literal["function"] = "function"

    id: str
    function: FunctionBody
    extras: dict[str, JsonType] | None = None

    @override
    def merge_in_place(self, other: Any) -> bool:
        if not isinstance(other, ToolCallPart):
            return False
        if self.function.arguments is None:
            self.function.arguments = other.arguments_part
        else:
            self.function.arguments += other.arguments_part or ""
        return True


class ToolCallPart(BaseModel, MergeableMixin):
    arguments_part: str | None = None

    @override
    def merge_in_place(self, other: Any) -> bool:
        if not isinstance(other, ToolCallPart):
            return False
        if self.arguments_part is None:
            self.arguments_part = other.arguments_part
        else:
            self.arguments_part += other.arguments_part or ""
        return True


Role = Literal["system", "user", "assistant", "tool"]


class MessageRole(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class Message(BaseModel):
    role: Role
    name: str | None = None
    content: list[ContentPart]
    tool_calls: list[ToolCall] | None = None
    tool_call_id: str | None = None
    partial: bool | None = None
    reasoning_content: str | None = None

    @field_serializer("content")
    def _serialize_content(self, content: list[ContentPart]) -> str | list[dict[str, Any]] | None:
        if len(content) == 1 and isinstance(content[0], TextPart):
            return content[0].text
        return [part.model_dump() for part in content]

    @field_validator("content", mode="before")
    @classmethod
    def _coerce_none_content(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, str):
            return [TextPart(text=value)]
        return value

    def __init__(
        self,
        *,
        role: Role,
        content: list[ContentPart] | ContentPart | str,
        tool_calls: list[ToolCall] | None = None,
        tool_call_id: str | None = None,
        **data: Any,
    ) -> None:
        if isinstance(content, str):
            content = [TextPart(text=content)]
        elif isinstance(content, ContentPart):
            content = [content]
        super().__init__(
            role=role,
            content=content,
            tool_calls=tool_calls,
            tool_call_id=tool_call_id,
            **data,
        )

    def extract_text(self, sep: str = "") -> str:
        return sep.join(part.text for part in self.content if isinstance(part, TextPart))


class ToolParameter(BaseModel):
    name: str
    type: str = "string"
    description: str | None = None
    required: bool = True
    enum: list[str] | None = None


class Tool(BaseModel):
    name: str
    description: str
    parameters: list[ToolParameter] = Field(default_factory=list)
    parameters_schema: dict[str, Any] | None = None


class ToolResult(BaseModel):
    tool_call_id: str
    content: str
    is_error: bool = False


class Usage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens


class TokenUsage(BaseModel):
    input_other: int
    output: int
    input_cache_read: int = 0
    input_cache_creation: int = 0

    @property
    def total(self) -> int:
        return self.input + self.output

    @property
    def input(self) -> int:
        return self.input_other + self.input_cache_read + self.input_cache_creation


StreamedMessagePart = ContentPart | ToolCall | ToolCallPart


class GenerateResult(BaseModel):
    id: str | None = None
    message: Message
    usage: Usage | None = None
    stop_reason: str = "stop"
    raw_response: dict[str, Any] | None = None
