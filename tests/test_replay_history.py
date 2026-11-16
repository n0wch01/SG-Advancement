"""scripts/replay_history.py: recorded activity from a control plane database, replayed through the rules."""

from __future__ import annotations

import csv
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

from sg_advance.shorthand import build_event

ROOT = Path(__file__).resolve().parents[1]


def _replay():
    path = ROOT / "scripts" / "replay_history.py"
    spec = importlib.util.spec_from_file_location("sga_replay_history", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _db(path: Path, specs: list[tuple[str, dict]]) -> Path:
    """The control plane's events table (only the columns the replay reads), one row per event."""
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE events (event_id TEXT PRIMARY KEY, device_id TEXT, ts TEXT, doc JSON)")
    for n, (device, spec) in enumerate(specs):
        ev = build_event(spec, defaults={"agent": "claude_code"}, index=n)
        ev = ev.model_copy(update={"endpoint": ev.endpoint.model_copy(update={"device_id": device})})
        doc = json.dumps(ev.model_dump(mode="json"))
        con.execute("INSERT INTO events VALUES (?, ?, ?, ?)", (ev.event_id, device, ev.ts.isoformat(), doc))
    con.commit()
    con.close()
    return path


RULE = "destructive-shell-command"


def bash(command: str) -> dict:
    return {"kind": "tool.call", "tool": "Bash", "arguments": {"command": command}}


def _rules(tmp: Path, keep_destructive: bool) -> Path:
    """A copy of rules/; optionally with destructive-shell-command switched off (a rule edit)."""
    out = tmp / ("rules-on" if keep_destructive else "rules-off")
    out.mkdir()
    for f in (ROOT / "rules").glob("*.yaml"):
        text = f.read_text(encoding="utf-8")
        if not keep_destructive:
            rule = "- id: destructive-shell-command\n"
            text = text.replace(rule, rule + "    enabled: false\n")
        (out / f.name).write_text(text, encoding="utf-8")
    return out


def test_hits_per_rule_and_device_filter(tmp_path, capsys) -> None:
    db = _db(tmp_path / "sga.db", [("my-mac", bash("rm -rf ~/projects")), ("my-mac", bash("ls -la")),
                                    ("carol-pc", bash("rm -rf /srv/demo"))])  # fmt: skip
    assert _replay().main([str(db), "--baseline", "none"]) == 0
    out = capsys.readouterr().out
    assert "3 events" in out and "destructive-shell-command" in out
    _replay().main([str(db), "--baseline", "none", "--device", "my-mac"])
    out = capsys.readouterr().out
    assert "2 events" in out and "carol-pc" not in out


def test_a_rule_edit_shows_what_no_longer_hits(tmp_path, capsys) -> None:
    db = _db(tmp_path / "sga.db", [("my-mac", bash("rm -rf ~/projects"))])
    before = _rules(tmp_path, keep_destructive=True)
    after = _rules(tmp_path, keep_destructive=False)
    _replay().main([str(db), "--rules", str(after), "--baseline", str(before)])
    out = capsys.readouterr().out
    assert "0 new hits, 1 no longer hit" in out
    assert "[destructive-shell-command]  Bash rm -rf ~/projects  (my-mac" in out


def test_labels_are_kept_and_give_precision(tmp_path, capsys) -> None:
    db = _db(tmp_path / "sga.db", [("my-mac", bash("rm -rf ~/projects")), ("my-mac", bash("rm -rf ./build")),
                                    ("my-mac", bash("rm -rf ./build"))])  # fmt: skip
    review = tmp_path / "review.csv"
    _replay().main([str(db), "--baseline", "none", "--rule", RULE, "--review", str(review)])
    with review.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    # the same command twice is one case to judge, with how often it interrupted the person
    counts = sorted((r["case"], r["count"]) for r in rows)
    assert counts == [("Bash rm -rf ./build", "2"), ("Bash rm -rf ~/projects", "1")]
    assert all(r["label"] == "" for r in rows)
    for r in rows:  # the person labels: deleting the project is the risk; a build folder is normal work
        r["label"], r["note"] = ("tp", "") if "projects" in r["case"] else ("fp", "빌드 폴더 정리")
    with review.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    capsys.readouterr()
    _replay().main([str(db), "--baseline", "none", "--rule", RULE, "--review", str(review)])
    out = capsys.readouterr().out
    assert "50%" in out  # 1 tp case, 1 fp case
    with review.open(encoding="utf-8-sig", newline="") as f:
        kept = {r["case"]: (r["label"], r["note"]) for r in csv.DictReader(f)}
    assert kept["Bash rm -rf ./build"] == ("fp", "빌드 폴더 정리")


def test_the_database_is_opened_read_only(tmp_path) -> None:
    db = _db(tmp_path / "sga.db", [("my-mac", bash("ls"))])
    before = db.read_bytes()
    _replay().main([str(db), "--baseline", "none"])
    assert db.read_bytes() == before


def test_a_missing_database_is_an_error(tmp_path, capsys) -> None:
    assert _replay().main([str(tmp_path / "nope.db")]) == 2
