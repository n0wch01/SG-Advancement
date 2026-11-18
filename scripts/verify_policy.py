"""Verify a policy change before it reaches anyone (docs/verification.md, layer 4).

    uv run python scripts/verify_policy.py                                   # cases, diff, evaluation
    uv run python scripts/verify_policy.py --db data/archive-2026-11-15.db    # + replay of real activity
    uv run --extra classifier python scripts/verify_policy.py --model data/models/protectai-v2

Runs, in order, against ``rules/`` (the change) and a baseline (``HEAD`` by default):

1. the rules load (schema, regexes, candidate tags);
2. ``tests/rule_cases``: every rule's positive and negative cases;
3. what changed against the baseline: added, removed, disabled, a weaker response or severity (a person
   reads them), and a changed rule whose ``version`` was not raised (a failure: raise it);
4. ``scripts/evaluate.py``: the evaluation set judged at each enforcement point (must all pass);
5. with ``--db``: ``scripts/replay_history.py``, real recorded activity, new and lost hits per rule;
6. with ``--model``: ``scripts/eval_classifier.py``, the classifier's catch and false-positive rates.

Exit 1 when a check fails. Then the change goes out through a staged rollout (docs/policy.md): canary
devices first (``sga-server policy stage``), everyone after (``promote``); this script prints the commands.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from replay_history import rules_at  # noqa: E402
from sg_advance.detect import RuleSet  # noqa: E402
from sg_advance.detect.rules import Rule, RuleLoadError  # noqa: E402
from sg_advance.schema import ResponseAction  # noqa: E402
from sg_advance.schema.labels import unknown_in_rules  # noqa: E402

_RANK = {a: i for i, a in enumerate(ResponseAction)}
_SEVERITY = {s: i for i, s in enumerate(["info", "low", "medium", "high", "critical"])}


@dataclass(frozen=True)
class Change:
    rule_id: str
    what: str  # added | removed | disabled | enabled | weaker response | stronger response | ...
    detail: str = ""
    review: bool = False  # a person must look before it ships
    fails: bool = False  # it cannot ship as it is (user decision 2026-11-17: same version, new behaviour)


def compare(base: list[Rule], cur: list[Rule]) -> list[Change]:
    """What a rule change does to enforcement, weakest-first findings marked for review."""
    old = {r.id: r for r in base}
    new = {r.id: r for r in cur}
    out: list[Change] = []
    for rid in sorted(new.keys() - old.keys()):
        r = new[rid]
        out.append(Change(rid, "added", f"{r.severity} · {r.response.value}"))
    for rid in sorted(old.keys() - new.keys()):
        out.append(Change(rid, "removed", "no longer detected or enforced", review=True))
    for rid in sorted(old.keys() & new.keys()):
        a, b = old[rid], new[rid]
        if a.model_dump(mode="json") == b.model_dump(mode="json"):
            continue
        if a.enabled != b.enabled:
            out.append(Change(rid, "disabled" if a.enabled else "enabled", review=a.enabled))
        if a.response != b.response:
            weaker = _RANK[b.response] < _RANK[a.response]
            out.append(Change(rid, "weaker response" if weaker else "stronger response",
                              f"{a.response.value} → {b.response.value}", review=weaker))  # fmt: skip
        if a.severity != b.severity:
            lower = _SEVERITY[b.severity.value] < _SEVERITY[a.severity.value]
            out.append(Change(rid, "lower severity" if lower else "higher severity",
                              f"{a.severity.value} → {b.severity.value}", review=lower))  # fmt: skip
        if a.version == b.version:
            same = f"version {a.version}: old and new behaviour would be recorded with one rule_version"
            out.append(Change(rid, "changed without a new version", same, review=True, fails=True))
        elif not any(c.rule_id == rid for c in out):
            out.append(Change(rid, "changed", f"version {a.version} → {b.version}"))
    return out


@dataclass
class Step:
    name: str
    status: str  # PASS | FAIL | REVIEW | SKIP
    note: str = ""


def run(cmd: list[str]) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.returncode, p.stdout + p.stderr


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rules", type=Path, default=ROOT / "rules", help="the change (default rules/)")
    ap.add_argument("--baseline", default="HEAD", help="git ref or rule dir to compare with (default HEAD)")
    ap.add_argument("--db", type=Path, help="a COPY of the control plane database to replay")
    ap.add_argument("--model", type=Path, help="classifier model dir to measure")
    ap.add_argument("--injecagent", type=Path, help="InjecAgent data dir for the classifier measurement")
    args = ap.parse_args(argv)
    py = sys.executable
    steps: list[Step] = []

    # 1. load
    try:
        current = RuleSet.load(args.rules)
        with tempfile.TemporaryDirectory() as tmp:
            baseline = RuleSet.load(rules_at(args.baseline, Path(tmp)))
    except (RuleLoadError, subprocess.CalledProcessError) as e:
        print(f"rules do not load: {e}", file=sys.stderr)
        return 1
    unknown = unknown_in_rules([r.model_dump(mode="json") for r in current.rules])
    note = f"{len(current.rules)} rules ({len(current.enabled)} enabled)"
    if unknown:  # schema/labels.py: a label no code writes can never match
        listed = "; ".join(f"{rid}: {', '.join(sorted(m))}" for rid, m in unknown.items())
        note += f"; unregistered labels: {listed}"
    steps.append(Step("1 rules load", "FAIL" if unknown else "PASS", note))

    # 2. rule cases
    code, out = run([py, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider",
                     "tests/test_rule_cases.py"])  # fmt: skip
    progress = re.compile(r"[.FEsx]+\s*\[\s*\d+%\]")
    dots = "".join(line.split("[")[0] for line in out.splitlines() if progress.fullmatch(line))
    note = f"{dots.count('.')} passed" + (f", {dots.count('F') + dots.count('E')} failed" if code else "")
    steps.append(Step("2 rule cases", "PASS" if code == 0 else "FAIL", note))
    if code:
        print(out)

    # 3. diff against the baseline
    changes = compare(baseline.rules, current.rules)
    flagged = [c for c in changes if c.review]
    failing = [c for c in changes if c.fails]
    note = f"{len(changes)} changed vs {args.baseline}" + (f", {len(flagged)} to review" if flagged else "")
    if failing:  # records of the old and new behaviour would carry one rule_version: raise the version
        note += f"; raise the version of: {', '.join(sorted({c.rule_id for c in failing}))}"
    status = "FAIL" if failing else "REVIEW" if flagged else "PASS"
    steps.append(Step("3 change review", status, note))

    # 4. evaluation set
    code, out = run([py, "scripts/evaluate.py"])
    m = re.search(r"\*\*(\d+)/(\d+)\*\*", out)
    note = f"{m[1]}/{m[2]} as designed" if m else ""
    steps.append(Step("4 evaluation set", "PASS" if code == 0 else "FAIL", note))
    if code:
        print(out)

    # 5. replay of real activity
    if args.db:
        code, out = run([py, "scripts/replay_history.py", str(args.db), "--baseline", args.baseline,
                         "--rules", str(args.rules)])  # fmt: skip
        m = re.search(r"Changed by the rule edit: (\d+) new hits, (\d+) no longer hit", out)
        if code or not m:
            steps.append(Step("5 replay", "FAIL", out.strip().splitlines()[-1] if out.strip() else ""))
        else:
            moved = int(m[1]) + int(m[2])
            note = f"{m[1]} new hits, {m[2]} no longer hit"
            steps.append(Step("5 replay", "REVIEW" if moved else "PASS", note))
            if moved:
                print(out[out.index("## Changed by the rule edit") :])
    else:
        steps.append(Step("5 replay", "SKIP", "no --db (a copy of the control plane database)"))

    # 6. classifier
    if args.model:
        cmd = [py, "scripts/eval_classifier.py", "--model", str(args.model)]
        if args.injecagent:
            cmd += ["--injecagent", str(args.injecagent)]
        code, out = run(cmd)
        steps.append(Step("6 classifier", "PASS" if code == 0 else "FAIL", "measured; read the table below"))
        print(out)
    else:
        steps.append(Step("6 classifier", "SKIP", "no --model"))

    if changes:
        print("## Rule changes\n")
        for c in changes:
            mark = "REVIEW " if c.review else ""
            print(f"- {mark}{c.rule_id}: {c.what}" + (f" ({c.detail})" if c.detail else ""))
        print()
    print("## Verification\n")
    for s in steps:
        print(f"{s.status:<7} {s.name:<18} {s.note}")
    failed = any(s.status == "FAIL" for s in steps)
    print()
    if failed:
        print("Not ready: fix the failures above.")
        return 1
    if any(s.status == "REVIEW" for s in steps):
        print("Ready only after a person has read the REVIEW items (the user tunes rules: explain FP/FN).")
    print("Roll out (docs/policy.md):")
    who = '--by <you> --reason "<why>"'
    print(f"  sga-server policy stage <canary devices> {who}   # canaries first")
    print("  sga-server policy rollout                          # who has which version")
    print(f"  sga-server policy promote {who} [--from <ISO>]     # everyone (optionally from a signed time)")
    print(f"  sga-server policy discard {who}                    # or take it back")
    return 0


if __name__ == "__main__":
    sys.exit(main())
