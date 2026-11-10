"""Agent adapters. Each one turns agent-native activity into AgentEvents."""

from .base import Adapter
from .replay import ReplayAdapter

__all__ = ["Adapter", "ReplayAdapter"]
