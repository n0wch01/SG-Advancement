"""Scenario demo: replay an attack story step by step and show what the local engine decides.

    uv run python demo/demo_runner.py --list
    uv run python demo/demo_runner.py S2
    uv run python demo/demo_runner.py all --pause 0

Self-contained: nothing outside demo/ imports this, so ``rm -rf demo`` removes the feature.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agent_sentinel.detect import Engine, RuleSet, Verdict
from agent_sentinel.schema import ResponseAction
from agent_sentinel.shorthand import build_event

DEMO_DIR = Path(__file__).resolve().parent
SCENARIO_DIR = DEMO_DIR / "scenarios"
RULES_DIR = DEMO_DIR.parent / "rules"


# ── scenario model ──────────────────────────────────────────────────────────


@dataclass
class Step:
    say: str
    event: dict[str, Any]
    at: float | None = None
    expect_action: ResponseAction | None = None
    expect_rules: tuple[str, ...] = ()


@dataclass
class Scenario:
    id: str
    title: str
    summary: str
    actor: dict[str, Any]
    steps: list[Step]
    path: Path


def _parse_expect(raw: Any) -> tuple[ResponseAction | None, tuple[str, ...]]:
    if raw is None:
        return None, ()
    if isinstance(raw, str):
        return ResponseAction(raw), ()
    return (ResponseAction(raw["action"]) if "action" in raw else None), tuple(raw.get("rules", ()))


def load_scenario(path: Path) -> Scenario:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    steps = []
    for s in doc["steps"]:
        action, rules = _parse_expect(s.get("expect"))
        steps.append(Step(s["say"], s["event"], s.get("at"), action, rules))
    return Scenario(doc["id"], doc["title"], doc.get("summary", ""), doc.get("actor", {}), steps, path)


def load_all() -> list[Scenario]:
    return [load_scenario(p) for p in sorted(SCENARIO_DIR.glob("*.yaml"))]


def find(scenario_id: str) -> Scenario:
    for sc in load_all():
        if sc.id.lower() == scenario_id.lower():
            return sc
    raise SystemExit(f"unknown scenario {scenario_id!r}; try --list")


# ── run ─────────────────────────────────────────────────────────────────────


@dataclass
class StepResult:
    step: Step
    verdict: Verdict
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def run(sc: Scenario, rules: RuleSet) -> list[StepResult]:
    engine = Engine(rules)
    out = []
    for i, step in enumerate(sc.steps):
        spec = dict(step.event)
        if step.at is not None:
            spec["at"] = step.at
        verdict = engine.process(build_event(spec, defaults=sc.actor, index=i))
        res = StepResult(step, verdict)
        if step.expect_action is not None and verdict.action is not step.expect_action:
            res.problems.append(f"expected {step.expect_action.value}, got {verdict.action.value}")
        missing = set(step.expect_rules) - set(verdict.rule_ids)
        if missing:
            res.problems.append(f"expected rules did not hit: {sorted(missing)}")
        out.append(res)
    return out


# ── presentation ────────────────────────────────────────────────────────────


class _Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text


_ACTION_COLOR = {"allow": "32", "alert": "33", "require_approval": "33"}  # others: red


def _event_label(spec: dict[str, Any]) -> str:
    detail = spec.get("tool") or spec.get("host") or ""
    return f"{spec['kind']}{' ' + detail if detail else ''}"


def present(sc: Scenario, results: list[StepResult], *, pause: float, style: _Style) -> None:
    print(style(f"━━ {sc.id} · {sc.title}", "1"))
    if sc.summary:
        print(f"   {sc.summary.strip()}")
    who = ", ".join(f"{k}={v}" for k, v in sc.actor.items())
    if who:
        print(style(f"   actor: {who}", "2"))
    print()
    for n, res in enumerate(results, 1):
        if pause and n > 1:
            time.sleep(pause)
        v = res.verdict
        action = v.action.value
        mark = style("✓", "32") if res.ok else style("✗", "31")
        if res.step.expect_action is None and not res.step.expect_rules:
            mark = " "
        print(f"[{n}/{len(results)}] {res.step.say}")
        verdict = style(action.upper(), _ACTION_COLOR.get(action, "31;1"))
        print(f"      {_event_label(res.step.event):<40} → {verdict} {mark}")
        for h in v.hits:
            note = "" if h.reported else style("  (같은 세션에서 이미 보고됨)", "2")
            print(f"        ● {h.rule.severity.value:<8} {h.rule.id}{note}")
            print(style(f"          {h.explanation}", "2"))
        for p in res.problems:
            print(style(f"        ! {p}", "31"))
    failed = [r for r in results if not r.ok]
    findings = sum(len(r.verdict.findings) for r in results)
    status = style("PASS", "32;1") if not failed else style(f"FAIL ({len(failed)} steps)", "31;1")
    print(f"\n   {status} · findings {findings}\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Replay an attack scenario through the local engine")
    ap.add_argument("scenario", nargs="?", help="scenario id (S1, S2, ...) or 'all'")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--rules", type=Path, default=RULES_DIR)
    ap.add_argument(
        "--pause",
        type=float,
        default=0.8 if sys.stdout.isatty() else 0.0,
        help="seconds between steps (default 0.8 on a terminal)",
    )
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args(argv)

    if args.list or not args.scenario:
        for sc in load_all():
            print(f"{sc.id:<5} {sc.title}  ({len(sc.steps)} steps, {sc.path.name})")
        return 0

    style = _Style(sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ)
    rules = RuleSet.load(args.rules)
    scenarios = load_all() if args.scenario == "all" else [find(args.scenario)]
    ok = True
    for sc in scenarios:
        results = run(sc, rules)
        present(sc, results, pause=args.pause, style=style)
        ok &= all(r.ok for r in results)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
