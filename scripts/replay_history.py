"""Replay real recorded activity (a control plane database) through the rules: what fires, and what a
rule change would change.

For rule tuning on real work, not only the cases we wrote: edit rules/, replay, see which recorded
events now hit or no longer hit, label the hits as true or false positives once, and get per-rule
precision every run after that.

    # copy the database out of the control plane first (data/ and *.db are git-ignored)
    docker compose cp control-plane:/data/archive-2026-11-15/sga.db data/archive-2026-11-15.db

    uv run python scripts/replay_history.py data/archive-2026-11-15.db
    uv run python scripts/replay_history.py data/archive-2026-11-15.db --device my-mac --since 2026-11-01
    uv run python scripts/replay_history.py data/archive-2026-11-15.db --review data/review.csv
    uv run python scripts/replay_history.py data/archive-2026-11-15.db --baseline none \
        --rule destructive-shell-command

Rules: ``rules/`` (``--rules``) against the committed rules (``--baseline``, a git ref, default HEAD, or a
directory; ``none`` to skip). Same events, same engine; only the rules differ, so the difference is the
rule change alone.

``--review FILE``: a CSV with one row per *case* a person would notice under the current rules (a rule
and what it hit: the command, the host, the snapshot value; repeats counted in ``count``) and an empty
``label`` column. Write ``tp`` (a real risk the rule should catch) or ``fp`` (normal work it should not
catch) and keep the file: the next run keeps those labels for the same rule and case and prints
precision per rule (over cases). Cases that are new since the labels were written show up unlabeled.

What a replay can and cannot say (limitations, also printed):
- Labels the sensor attached at the time (input source, lineage, attended, posture) are replayed as
  recorded; live sets the sensor kept (trusted skills, blocked people, elevated-risk people) are empty.
- Only what the sensor sent exists: secrets are masked, and text the sensor shortened stays shortened.
- Recorded traffic includes our own demo attacks and test sessions: filter them out (--device,
  --exclude-device, --exclude-session, --since) before calling a hit a false positive.
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from sg_advance.detect import Engine, RuleSet
from sg_advance.detect.rules import RuleLoadError
from sg_advance.schema import AgentEvent, ResponseAction
from sg_advance.sensor import actions

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ["rule_id", "severity", "response", "case", "count", "devices", "sessions", "first", "last",
          "example_event_id", "label", "note"]  # fmt: skip
LABELS = ("tp", "fp")
# A person is interrupted by each of these when the rule enforces; a state snapshot only by its finding.
ACTIONS = {"tool.call", "tool.result", "net.egress", "prompt.user"}


@dataclass
class Filters:
    devices: list[str] = field(default_factory=list)
    exclude_devices: list[str] = field(default_factory=list)
    exclude_sessions: list[str] = field(default_factory=list)
    since: datetime | None = None
    until: datetime | None = None

    def keep(self, ev: AgentEvent) -> bool:
        dev, sid = ev.endpoint.device_id, ev.agent.session_id
        return (
            (not self.devices or dev in self.devices)
            and dev not in self.exclude_devices
            and not any(s in sid for s in self.exclude_sessions)
            and (self.since is None or ev.ts >= self.since)
            and (self.until is None or ev.ts < self.until)
        )


def renormalized(ev: AgentEvent) -> AgentEvent:
    """Replace recorded action labels with those today's sensor would write (sensor/actions.py).
    Events recorded before 2026-11-17 carry none, so structure-reading rules would only see raw text."""
    if ev.kind.value != "tool.call":
        return ev
    kept = {k: v for k, v in ev.labels.items() if k not in actions.LABELS}
    return ev.model_copy(update={"labels": kept | actions.labels_for(ev)})


def load(db: Path, filters: Filters, normalize: bool = False) -> tuple[list[AgentEvent], int]:
    """Recorded events in time order, and how many rows could not be read as a current AgentEvent."""
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)  # never write to the evidence
    try:
        rows = con.execute("SELECT doc FROM events ORDER BY ts, rowid").fetchall()
    finally:
        con.close()
    events: list[AgentEvent] = []
    bad = 0
    for (doc,) in rows:
        try:
            ev = AgentEvent.model_validate(json.loads(doc) if isinstance(doc, str) else doc)
        except ValueError:
            bad += 1
            continue
        if filters.keep(ev):
            events.append(renormalized(ev) if normalize else ev)
    return sorted(events, key=lambda e: e.ts), bad


def rules_at(ref_or_dir: str, tmp: Path) -> Path:
    """A rule directory: as given, or the ``rules/`` tree of a git ref written to ``tmp``."""
    if Path(ref_or_dir).is_dir():
        return Path(ref_or_dir)
    names = subprocess.run(["git", "-C", str(ROOT), "ls-tree", "--name-only", ref_or_dir, "rules/"],
                           capture_output=True, text=True, check=True).stdout.split()  # fmt: skip
    for name in names:
        blob = subprocess.run(["git", "-C", str(ROOT), "show", f"{ref_or_dir}:{name}"],
                              capture_output=True, check=True).stdout  # fmt: skip
        (tmp / Path(name).name).write_bytes(blob)
    return tmp


def describe(ev: AgentEvent) -> str:
    p = ev.payload.model_dump(mode="json")
    kind = p.get("kind", "")
    if kind == "tool.call":
        args = p.get("arguments")
        command = args.get("command") if isinstance(args, dict) else None
        text = command if isinstance(command, str) else json.dumps(args, ensure_ascii=False)
        return f"{p.get('tool')} {clip(text)}"
    if kind == "tool.result":
        return f"{p.get('tool')} result {clip(str(p.get('output_preview') or ''))}"
    if kind in ("prompt.user", "message.assistant"):
        return f"{kind} {clip(str(p.get('text') or p.get('text_preview') or ''))}"
    if kind == "net.egress":
        return f"egress {p.get('method') or ''} {p.get('host') or ''}".strip()
    return str(kind)


def clip(text: str, n: int = 140) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= n else flat[: n - 1] + "…"


Hits = dict[tuple[str, str], dict[str, str]]  # (event_id, rule_id) -> what was hit
Run = tuple[Hits, Counter[str], set[tuple[str, str]]]
Labels = dict[tuple[str, str], tuple[str, str]]  # (rule_id, case) -> (label, note)


def run(rules: RuleSet, events: Iterable[AgentEvent]) -> Run:
    """Every (event, rule) hit; findings each rule would report (session dedup applied); and the hits a
    person would notice: a reported finding, or every action held, asked about or blocked (an enforcing
    rule interrupts each call, repeats included). A *case* is what the hit was about (the command, the
    host, the snapshot's matched value): the same case repeated is one thing to judge."""
    hits: Hits = {}
    reported: Counter[str] = Counter()
    noticed: set[tuple[str, str]] = set()
    for v in Engine(rules).replay(events):
        ev = v.event
        for h in v.hits:
            reported[h.rule.id] += h.reported
            enforcing = h.rule.response not in (ResponseAction.ALLOW, ResponseAction.ALERT)
            if h.reported or (enforcing and ev.kind.value in ACTIONS):
                noticed.add((ev.event_id, h.rule.id))
            what = describe(ev)
            case = what if ev.kind.value in ACTIONS else f"{what} · {clip(h.explanation, 120)}"
            hits[(ev.event_id, h.rule.id)] = {
                "event_id": ev.event_id, "rule_id": h.rule.id, "ts": f"{ev.ts:%Y-%m-%d %H:%M:%S}",
                "device": ev.endpoint.device_id, "session": ev.agent.session_id,
                "severity": h.rule.severity.value, "response": h.rule.response.value, "case": case,
            }  # fmt: skip
    return hits, reported, noticed


def cases(hits: Hits, keys: Iterable[tuple[str, str]]) -> dict[tuple[str, str], list[dict[str, str]]]:
    out: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for key in keys:
        row = hits[key]
        out[(row["rule_id"], row["case"])].append(row)
    return out


def read_labels(path: Path) -> Labels:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8-sig", newline="") as f:
        return {(r["rule_id"], r["case"]): ((r.get("label") or "").strip().lower(), r.get("note") or "")
                for r in csv.DictReader(f)}  # fmt: skip


def write_review(path: Path, grouped: dict[tuple[str, str], list[dict[str, str]]], labels: Labels) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as f:  # BOM: Excel opens Korean text right
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for key, rows in sorted(grouped.items(), key=lambda kv: (kv[0][0], -len(kv[1]), kv[0][1])):
            label, note = labels.get(key, ("", ""))
            w.writerow({
                "rule_id": key[0], "severity": rows[0]["severity"], "response": rows[0]["response"],
                "case": key[1], "count": len(rows), "devices": " ".join(sorted({r["device"] for r in rows})),
                "sessions": len({r["session"] for r in rows}), "first": min(r["ts"] for r in rows),
                "last": max(r["ts"] for r in rows), "example_event_id": rows[0]["event_id"],
                "label": label, "note": note,
            })  # fmt: skip


def report(events: list[AgentEvent], bad: int, cur: Run, base: Run | None, labels: Labels,
           examples: int) -> None:  # fmt: skip
    hits, reported, noticed = cur
    print(f"# Replay: {len(events)} events" + (f" ({bad} unreadable rows skipped)" if bad else ""))
    if events:
        print(f"  {events[0].ts:%Y-%m-%d %H:%M} .. {events[-1].ts:%Y-%m-%d %H:%M}")
    per_dev = Counter((e.endpoint.device_id, e.agent.type.value) for e in events)
    for (dev, agent), n in sorted(per_dev.items()):
        print(f"  {dev:<16} {agent:<12} {n:>7} events")
    tool_calls = sum(1 for e in events if e.kind.value == "tool.call")
    withheld = sum(1 for e in events if getattr(e.payload, "withheld", False))
    print(f"  tool calls: {tool_calls}")
    if withheld:
        print(f"  prompts kept on the device (only their length was sent): {withheld}"
              " - a new prompt rule cannot be judged on these")  # fmt: skip

    by_rule: dict[str, list[str]] = defaultdict(list)
    for eid, rid in hits:
        by_rule[rid].append(eid)
    base_by_rule: dict[str, list[str]] = defaultdict(list)
    if base:
        for eid, rid in base[0]:
            base_by_rule[rid].append(eid)

    print("\n## Hits per rule (events hit / findings reported after session dedup)")
    head = f"  {'rule':<46} {'events':>7} {'finds':>6}"
    head += f" {'before':>7} {'Δ':>5}" if base else ""
    head += f"  {'cases':>5} {'tp':>3} {'fp':>3} {'unl':>4} {'precision':>9}" if labels else ""
    grouped = cases(hits, noticed)
    print(head)
    for rid in sorted(set(by_rule) | set(base_by_rule), key=lambda r: (-len(by_rule.get(r, [])), r)):
        n = len(by_rule.get(rid, []))
        line = f"  {rid:<46} {n:>7} {reported.get(rid, 0):>6}"
        if base:
            b = len(base_by_rule.get(rid, []))
            line += f" {b:>7} {n - b:>+5}"
        if labels:
            mine = [key for key in grouped if key[0] == rid]  # the review file's rows for this rule
            got = Counter(labels.get(key, ("", ""))[0] for key in mine)
            tp, fp = got["tp"], got["fp"]
            unl = len(mine) - tp - fp
            prec = f"{tp / (tp + fp):.0%}" if tp + fp else "-"
            line += f"  {len(mine):>5} {tp:>3} {fp:>3} {unl:>4} {prec:>9}"
        print(line)
    if not hits:
        print("  (no rule hit)")

    if base:
        new = set(hits) - set(base[0])
        gone = set(base[0]) - set(hits)
        print(f"\n## Changed by the rule edit: {len(new)} new hits, {len(gone)} no longer hit")
        for title, keys, src in (("New hits", new, hits), ("No longer hit", gone, base[0])):
            if not keys:
                continue
            print(f"\n### {title} (same case counted once)")
            shown: Counter[str] = Counter()
            for (rid, case), rows in sorted(cases(src, keys).items(), key=lambda kv: (kv[0][0], -len(kv[1]))):
                shown[rid] += 1
                if shown[rid] <= examples:
                    times = f" ×{len(rows)}" if len(rows) > 1 else ""
                    print(f"  [{rid}]  {case}{times}  ({rows[0]['device']}, {min(r['ts'] for r in rows)})")
            for rid, n in sorted(shown.items()):
                if n > examples:
                    print(f"  … {rid}: {n - examples} more cases")

    print("\nLimits: live sensor sets (trusted skills, blocked or elevated-risk people) are empty here;"
          " masked secrets stay masked; demo and test sessions are included unless filtered.")  # fmt: skip


def parse_time(text: str) -> datetime:
    t = datetime.fromisoformat(text)
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("db", type=Path, help="control plane SQLite database (a copy; opened read-only)")
    ap.add_argument("--rules", type=Path, default=ROOT / "rules", help="rules to try (default: rules/)")
    ap.add_argument("--baseline", default="HEAD", help="git ref or rule dir to compare with; 'none' to skip")
    ap.add_argument("--rule", action="append", default=[], help="only these rule ids")
    ap.add_argument("--device", action="append", default=[], help="only these devices")
    ap.add_argument("--exclude-device", action="append", default=[], help="leave out these devices")
    ap.add_argument(
        "--exclude-session", action="append", default=[], help="leave out sessions whose id contains this"
    )
    ap.add_argument("--since", type=parse_time, help="from this time (ISO, UTC if no zone)")
    ap.add_argument("--until", type=parse_time, help="before this time")
    ap.add_argument("--review", type=Path, help="CSV of hits to label tp/fp (labels in it are kept)")
    ap.add_argument("--examples", type=int, default=5, help="changed hits to print per rule (default 5)")
    ap.add_argument(
        "--normalize", action="store_true",
        help="recompute the sensor's action labels (sga_act_*) for each recorded call",
    )
    args = ap.parse_args(argv)

    if not args.db.is_file():
        print(f"no database at {args.db}", file=sys.stderr)
        return 2
    filters = Filters(args.device, args.exclude_device, args.exclude_session, args.since, args.until)
    with tempfile.TemporaryDirectory() as tmp:
        try:
            current = RuleSet.load(args.rules)
            baseline = None if args.baseline == "none" else RuleSet.load(rules_at(args.baseline, Path(tmp)))
        except (RuleLoadError, subprocess.CalledProcessError) as e:
            print(f"rule error: {e}", file=sys.stderr)
            return 2
    if args.rule:
        unknown = set(args.rule) - {r.id for r in current.rules}
        if unknown:
            print(f"unknown rule ids: {sorted(unknown)}", file=sys.stderr)
            return 2
        current = RuleSet([r for r in current.rules if r.id in args.rule], current.sources)
        if baseline is not None:
            baseline = RuleSet([r for r in baseline.rules if r.id in args.rule], baseline.sources)

    events, bad = load(args.db, filters, args.normalize)
    cur = run(current, events)
    base = run(baseline, events) if baseline is not None else None
    labels = read_labels(args.review) if args.review else {}
    labels = {k: v for k, v in labels.items() if v[0] in LABELS}
    report(events, bad, cur, base, labels, args.examples)
    if args.review:
        grouped = cases(cur[0], cur[2])
        write_review(args.review, grouped, read_labels(args.review))
        print(f"\nReview file: {args.review} ({len(grouped)} cases a person would notice; label tp or fp)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
