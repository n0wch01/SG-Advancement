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
    # Llama 4 Community License (gated: the stored Hugging Face login is used). Multilingual (mDeBERTa).
    # No official ONNX: model.onnx is converted from the official weights by scripts/convert_prompt_guard.py
    # (weights SHA-256 checked there, scores proven unchanged); remote None = produced locally, then pinned.
    "prompt-guard-2-86m": {
        "name": "meta-llama/Llama-Prompt-Guard-2-86M",
        "revision": "a8ded8e697ce7c355e395a0df51f94adb4a2fd27",
        "files": {
            "model.onnx": (None, None),
            "tokenizer.json": (
                "tokenizer.json",
                "3e7e96867c2acdd575f0862c74822e05d1d15b93d9d9a4a2144b1ce83ae3339f",
            ),
            "config.json": ("config.json", None),
            "LICENSE": ("LICENSE", None),
            "USE_POLICY.md": ("USE_POLICY.md", None),
        },
        "model": "model.onnx",
        "tokenizer": "tokenizer.json",
        "positive_index": 1,  # LABEL_1 = malicious (model card)
        "max_tokens": 512,
        "license": "llama4 (Built with Llama)",
        "converted_from": {
            "file": "model.safetensors",
            "sha256": "e72017dbbe89c1232dcbc4a74ce0c389db5b468c42afd05850347b2a8c5f6b09",
        },
    },
}


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def stored_token() -> str | None:
    """The Hugging Face login already on this machine (``hf auth login``), if any. Never printed."""
    try:
        from huggingface_hub import get_token
    except ImportError:
        return None
    return get_token()


def download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "sg-advance-fetch-model"})
    if token := os.environ.get("HF_TOKEN") or stored_token():
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
        if remote is None:
            if not dest.is_file():
                raise SystemExit(f"{local} is made locally: run scripts/convert_prompt_guard.py {out} first")
        elif not (dest.is_file() and (expected is None or sha256_of(dest) == expected)):
            print(f"  fetching {remote}")
            download(f"{HUB}/{spec['name']}/resolve/{spec['revision']}/{remote}", dest)
        digest = sha256_of(dest)
        if expected is not None and digest != expected:
            dest.unlink()
            raise SystemExit(f"{local}: SHA-256 {digest} does not match the published {expected}; removed")
        pinned[local] = digest
    keys = ("name", "revision", "model", "tokenizer", "positive_index", "max_tokens", "license",
            "converted_from")  # fmt: skip
    manifest = {k: spec[k] for k in keys if k in spec} | {"files": pinned}
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
