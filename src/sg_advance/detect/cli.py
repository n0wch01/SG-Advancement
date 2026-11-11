"""sga-detect: replay AgentEvent JSONL through the rules and explain every hit.

uv run sga-detect examples/events/*.jsonl
uv run sga-detect events.jsonl --rule sensitive-file-access --all
uv run sga-detect events.jsonl --json > findings.jsonl
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from pathlib import Path

from ..schema import AgentEvent
from .engine import Engine, Verdict
from .rules import RuleLoadError, RuleSet

DEFAULT_RULES = Path(os.environ.get("SGA_RULES_DIR", "rules"))


def load_events(paths: list[Path]) -> list[AgentEvent]:
    events: list[AgentEvent] = []
    for p in paths:
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                events.append(AgentEvent.model_validate_json(line))
            except ValueError as e:
                raise SystemExit(f"{p}:{n}: invalid AgentEvent: {e}") from e
    return sorted(events, key=lambda e: e.ts)  # stable: same-ts events keep file order


def _describe(ev: AgentEvent) -> str:
    p = ev.payload
    detail = getattr(p, "tool", None) or getattr(p, "host", None) or ""
    return f"{ev.kind.value}{' ' + detail if detail else ''}"


def print_verdict(v: Verdict, show_all: bool) -> None:
    ev = v.event
    if not v.hits and not show_all:
        return
    who = f"{ev.principal.user_id}@{ev.endpoint.device_id} {ev.agent.type.value}/{ev.agent.session_id}"
    marker = v.action.value.upper() if v.hits else "allow"
    print(f"{ev.ts:%Y-%m-%d %H:%M:%S}  {who}  {_describe(ev)}  → {marker}")
    for h in v.hits:
        dup = "" if h.reported else "  (dup, not reported)"
        print(f"    [{h.rule.severity.value:>8}] {h.rule.id} ({h.rule.response.value}){dup}")
        print(f"               {h.explanation}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sga-detect", description=__doc__.split("\n\n")[0])
    ap.add_argument("events", nargs="+", type=Path, help="AgentEvent JSONL files")
    ap.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="rule dir or file (default: rules/)")
    ap.add_argument("--rule", action="append", default=[], help="only evaluate these rule ids")
    ap.add_argument("--all", action="store_true", help="also print events without hits")
    ap.add_argument("--json", action="store_true", help="print Finding JSON lines instead")
    args = ap.parse_args(argv)

    try:
        ruleset = RuleSet.load(args.rules)
    except RuleLoadError as e:
        print(f"rule error: {e}", file=sys.stderr)
        return 2
    if args.rule:
        unknown = set(args.rule) - {r.id for r in ruleset.rules}
        if unknown:
            print(f"unknown rule ids: {sorted(unknown)}", file=sys.stderr)
            return 2
        ruleset = RuleSet([r for r in ruleset.rules if r.id in args.rule], ruleset.sources)

    verdicts = Engine(ruleset).replay(load_events(args.events))

    if args.json:
        for v in verdicts:
            for f in v.findings:
                print(f.model_dump_json())
        return 0

    for v in verdicts:
        print_verdict(v, args.all)
    hits = Counter(h.rule.id for v in verdicts for h in v.hits)
    print(
        f"\n{len(verdicts)} events, {sum(len(v.findings) for v in verdicts)} findings, "
        f"{len(ruleset.enabled)} rules enabled"
    )
    for rid, n in hits.most_common():
        print(f"  {n:4d}  {rid}  ({ruleset.sources.get(rid, '?')})")
    silent = [r.id for r in ruleset.enabled if r.id not in hits]
    if silent:
        print(f"  never hit: {', '.join(silent)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
