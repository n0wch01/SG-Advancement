"""Dotted-path access into the JSON form of an AgentEvent."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any


def resolve(doc: Any, path: str) -> list[Any]:
    """Return every value at ``path``. A segment ending in ``[]`` fans out over a list:
    ``payload.tools[].provider.mcp_server`` yields one value per tool. Missing keys and nulls
    are dropped, so the result may be empty."""
    current = [doc]
    for segment in path.split("."):
        fan_out = segment.endswith("[]")
        key = segment[:-2] if fan_out else segment
        nxt: list[Any] = []
        for item in current:
            if not isinstance(item, dict) or key not in item:
                continue
            value = item[key]
            if fan_out:
                if isinstance(value, list):
                    nxt.extend(value)
            else:
                nxt.append(value)
        current = nxt
    return [v for v in current if v is not None]


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
