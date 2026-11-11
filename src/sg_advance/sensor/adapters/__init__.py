"""Agent adapters. Each one turns agent-native activity into AgentEvents.

``openclaw`` needs the optional ``websockets`` dependency (``sg-advance[openclaw]``), so it
is imported explicitly by whoever uses it, not re-exported here.
"""

from .base import Adapter, AdapterContext
from .replay import ReplayAdapter

__all__ = ["Adapter", "AdapterContext", "ReplayAdapter"]
