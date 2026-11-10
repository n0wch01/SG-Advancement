"""Export JSON Schema files for the wire models into schemas/.

The console (TypeScript) and non-Python sensors consume these files.

    uv run python scripts/export_schema.py          # write
    uv run python scripts/export_schema.py --check  # fail if committed files are stale
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_sentinel.schema import AgentEvent, Finding

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "schemas"
MODELS = {
    "agent-event.v1.json": AgentEvent,
    "finding.v1.json": Finding,
}


def render() -> dict[str, str]:
    return {
        name: json.dumps(model.model_json_schema(), indent=2, ensure_ascii=False) + "\n"
        for name, model in MODELS.items()
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    stale = []
    for name, text in render().items():
        path = OUT_DIR / name
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                stale.append(name)
        else:
            OUT_DIR.mkdir(exist_ok=True)
            path.write_text(text, encoding="utf-8")
            print(f"wrote {path.relative_to(ROOT)}")
    if stale:
        print(f"stale schema files: {stale} — run scripts/export_schema.py", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
