"""Dotted-path access into the JSON form of an AgentEvent."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any


def resolve(doc: Any, path: str) -> list[Any]:
    """Return every value at ``path``. A segment ending in ``[]`` fans out over a list:
    ``payload.tools[].provider.mcp_server`` yields one value per tool. Keys may contain dots
    themselves (labels such as ``openclaw.tool_kind``): ``labels.openclaw.tool_kind`` finds them.
    Missing keys and nulls are dropped, so the result may be empty."""
    return [v for v in _walk([doc], path.split(".")) if v is not None]


def _walk(items: list[Any], segments: list[str]) -> list[Any]:
    if not segments:
        return items
    out: list[Any] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        for n in range(1, len(segments) + 1):  # "a", then "a.b", ... for dotted keys
            segment = ".".join(segments[:n])
            fan_out = segment.endswith("[]")
            key = segment[:-2] if fan_out else segment
            if key not in item:
                continue
            value = item[key]
            if fan_out:
                out.extend(_walk(value if isinstance(value, list) else [], segments[n:]))
            else:
                out.extend(_walk([value], segments[n:]))
    return out


def first(doc: Any, path: str) -> str:
    values = resolve(doc, path)
    return scalar(values[0]) if values else ""


def scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def string_leaves(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from string_leaves(v)
    elif isinstance(value, list):
        for v in value:
            yield from string_leaves(v)


def condition_holds(doc: Any, condition: dict[str, tuple[str, ...]]) -> bool:
    return all(any(scalar(v) in allowed for v in resolve(doc, path)) for path, allowed in condition.items())
