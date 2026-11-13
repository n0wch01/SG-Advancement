"""Endpoint sensor core (M4). Installs without the ``server`` extra.

Names are imported lazily: the Claude Code hook (``sensor.hook``) starts once per tool call and must
not pay for pydantic and the detection engine unless it needs them (M6)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__all__ = [
    "Credentials",
    "NoPolicy",
    "NotEnrolled",
    "Sensor",
    "SensorError",
    "SensorHome",
    "SyncStatus",
    "enroll",
]

if TYPE_CHECKING:
    from .core import NoPolicy, NotEnrolled, Sensor, SensorError, SyncStatus, enroll
    from .state import Credentials, SensorHome


def __getattr__(name: str) -> Any:
    if name in ("Credentials", "SensorHome"):
        from . import state

        return getattr(state, name)
    if name in __all__:
        from . import core

        return getattr(core, name)
    raise AttributeError(name)
