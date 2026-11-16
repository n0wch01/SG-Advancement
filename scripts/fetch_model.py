"""Fetch a pinned injection classifier into a model directory and write its ``sga-model.json``.

    uv run python scripts/fetch_model.py protectai-v2 data/models/protectai-v2
    uv run python scripts/fetch_model.py protectai-v2 ~/.sg-advance/models/injection   # for the daemon

Every file comes from a fixed repository revision. Files with a known SHA-256 (the model weights, as the
hub publishes them) must match it; the rest are hashed on first fetch and pinned in the manifest, which
the sensor checks before every load (sensor/onnx_classifier.py). Files already present and matching are
not downloaded again. A gated model needs ``HF_TOKEN`` in the environment (never on the command line).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.request
from pathlib import Path

HUB = "https://huggingface.co"
MODELS = {
    # Apache-2.0, English. Weights SHA-256 = the hub's LFS id for onnx/model.onnx at this revision.
    "protectai-v2": {
        "name": "protectai/deberta-v3-base-prompt-injection-v2",
        "revision": "90c9989b1a342275dd0d1a95aad283c04e075671",
        "files": {
            "model.onnx": (
                "onnx/model.onnx",
                "f0ea7f239f765aedbde7c9e163a7cb38a79c5b8853d3f76db5152172047b228c",
            ),
            "tokenizer.json": ("onnx/tokenizer.json", None),
            "config.json": ("onnx/config.json", None),
            "LICENSE": ("LICENSE", None),
        },
        "model": "model.onnx",
        "tokenizer": "tokenizer.json",
        "positive_index": 1,  # config.json id2label: 0 SAFE, 1 INJECTION
        "max_tokens": 512,
        "license": "apache-2.0",
    },
}


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "sg-advance-fetch-model"})
    if token := os.environ.get("HF_TOKEN"):
        req.add_header("Authorization", f"Bearer {token}")
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(req, timeout=60) as r, tmp.open("wb") as f:  # noqa: S310  # fixed https host
        while block := r.read(1 << 20):
            f.write(block)
    tmp.replace(dest)


def fetch(key: str, out: Path) -> dict:
    spec = MODELS[key]
    out.mkdir(parents=True, exist_ok=True)
    pinned: dict[str, str] = {}
    for local, (remote, expected) in spec["files"].items():
        dest = out / local
        if not (dest.is_file() and (expected is None or sha256_of(dest) == expected)):
            print(f"  fetching {remote}")
            download(f"{HUB}/{spec['name']}/resolve/{spec['revision']}/{remote}", dest)
        digest = sha256_of(dest)
        if expected is not None and digest != expected:
            dest.unlink()
            raise SystemExit(f"{local}: SHA-256 {digest} does not match the published {expected}; removed")
        pinned[local] = digest
    manifest = {k: spec[k] for k in ("name", "revision", "model", "tokenizer", "positive_index", "max_tokens",
                                     "license")} | {"files": pinned}  # fmt: skip
    (out / "sga-model.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("model", choices=sorted(MODELS))
    ap.add_argument("out", type=Path, help="model directory to create or check")
    args = ap.parse_args(argv)
    m = fetch(args.model, args.out.expanduser())
    print(f"{m['name']}@{m['revision'][:7]} in {args.out} ({len(m['files'])} files pinned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
