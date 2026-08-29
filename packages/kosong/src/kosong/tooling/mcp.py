from __future__ import annotations

import base64
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

MCP_MAX_OUTPUT_CHARS = 100_000


def convert_mcp_text_content(text: str, *, char_budget: int = MCP_MAX_OUTPUT_CHARS) -> str:
    if len(text) <= char_budget:
        return text
    truncated = text[:char_budget]
    return truncated + f"\n\n[Output truncated: exceeded {char_budget} character limit.]"


def convert_mcp_image_content(
    data: str | bytes,
    mime_type: str = "image/png",
) -> dict[str, Any]:
    if isinstance(data, bytes):
        encoded = base64.b64encode(data).decode("ascii")
    else:
        encoded = data
    return {
        "type": "image",
        "source": {
            "type": "base64",
            "media_type": mime_type,
            "data": encoded,
        },
    }


def convert_mcp_resource_content(resource: dict[str, Any]) -> str:
    text = resource.get("text")
    if isinstance(text, str):
        return text
    blob = resource.get("blob")
    if isinstance(blob, str):
        try:
            decoded = base64.b64decode(blob).decode("utf-8", errors="replace")
            return decoded
        except Exception:
            return f"[Binary resource: {resource.get('mimeType', 'unknown')}]"
    uri = resource.get("uri", "")
    return f"[Resource: {uri}]"


def convert_mcp_result(result: Any, *, char_budget: int = MCP_MAX_OUTPUT_CHARS) -> str:
    if result is None:
        return ""
    if isinstance(result, str):
        return convert_mcp_text_content(result, char_budget=char_budget)
    if hasattr(result, "content") and isinstance(result.content, list):
        return _convert_content_list(result.content, char_budget=char_budget)
    if isinstance(result, list):
        return _convert_content_list(result, char_budget=char_budget)
    if isinstance(result, dict):
        return _convert_dict_result(result, char_budget=char_budget)
    return convert_mcp_text_content(str(result), char_budget=char_budget)


def _convert_content_list(
    content: list[Any],
    *,
    char_budget: int = MCP_MAX_OUTPUT_CHARS,
) -> str:
    texts: list[str] = []
    remaining_budget = char_budget
    truncated = False

    for part in content:
        text = _convert_single_content(part)
        if len(text) > remaining_budget:
            text = text[:remaining_budget]
            truncated = True
        remaining_budget -= len(text)
        texts.append(text)
        if remaining_budget <= 0:
            truncated = True
            break

    if truncated:
        texts.append(f"\n\n[Output truncated: exceeded {char_budget} character limit.]")
    return "\n".join(texts)


def _convert_single_content(part: Any) -> str:
    if isinstance(part, str):
        return part
    if isinstance(part, dict):
        content_type = part.get("type", "")
        if content_type == "text":
            return part.get("text", "")
        if content_type == "image":
            mime = part.get("mimeType", part.get("mime_type", "image/png"))
            return f"[Image: {mime}]"
        if content_type == "resource":
            return convert_mcp_resource_content(part)
        return json.dumps(part, default=str, ensure_ascii=False)
    if hasattr(part, "type"):
        part_type = getattr(part, "type", "")
        if part_type == "text":
            return getattr(part, "text", "")
        if part_type == "image":
            return "[Image]"
        if part_type == "resource":
            return convert_mcp_resource_content({
                "text": getattr(part, "text", None),
                "blob": getattr(part, "blob", None),
                "uri": getattr(part, "uri", ""),
                "mimeType": getattr(part, "mimeType", "unknown"),
            })
    return str(part)


def _convert_dict_result(result: dict[str, Any], *, char_budget: int = MCP_MAX_OUTPUT_CHARS) -> str:
    content = result.get("content")
    if isinstance(content, list):
        return _convert_content_list(content, char_budget=char_budget)
    return convert_mcp_text_content(
        json.dumps(result, default=str, ensure_ascii=False),
        char_budget=char_budget,
    )


def mcp_tool_to_kosong_tool(
    name: str,
    description: str,
    input_schema: dict[str, Any],
    *,
    server_name: str | None = None,
) -> dict[str, Any]:
    from kosong.types import Tool, ToolParameter

    parameters: list[ToolParameter] = []
    properties = input_schema.get("properties", {})
    required_fields = set(input_schema.get("required", []))
    type_map = {
        "string": "string",
        "integer": "integer",
        "number": "number",
        "boolean": "boolean",
        "array": "array",
        "object": "object",
    }

    for param_name, param_schema in properties.items():
        param_type = type_map.get(param_schema.get("type", "string"), "string")
        param_desc = param_schema.get("description")
        is_required = param_name in required_fields
        parameters.append(ToolParameter(
            name=param_name,
            type=param_type,
            description=param_desc,
            required=is_required,
        ))

    prefixed_name = f"mcp__{name}" if server_name is None else f"mcp__{name}"
    prefixed_desc = f"[MCP:{server_name}] {description}" if server_name else description

    return {
        "name": prefixed_name,
        "description": prefixed_desc,
        "parameters": parameters,
        "input_schema": input_schema,
    }
