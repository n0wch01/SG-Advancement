"""Local detection: declarative rules evaluated over AgentEvent streams."""

from .engine import Engine, Hit, Verdict, rule_titles
from .rules import Rule, RuleLoadError, RuleSet

__all__ = ["Engine", "Hit", "Rule", "RuleLoadError", "RuleSet", "Verdict", "rule_titles"]
