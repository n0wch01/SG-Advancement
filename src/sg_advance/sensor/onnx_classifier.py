"""ONNX prompt-injection classifier for the sensor daemon (docs/classifier.md 9). Needs the ``classifier``
extra (onnxruntime, tokenizers), imported inside ``OnnxClassifier`` so the manifest check works without it.

A model directory holds the files and ``sga-model.json``: where they came from (repository, pinned revision)
and the SHA-256 of each file (``scripts/fetch_model.py`` writes it). A model is supply chain too: every
file is checked before loading, and a mismatch means the model is not used (the rules alone decide).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

MANIFEST = "sga-model.json"
WINDOW_OVERLAP = 64  # tokens shared by two windows, so an instruction split by a window edge is seen whole


class ModelError(Exception):
    """The model directory cannot be trusted or used (missing file, hash mismatch, bad manifest)."""


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def verify(model_dir: Path) -> dict[str, Any]:
    """The manifest, after checking every file it lists against its SHA-256."""
    try:
        manifest = json.loads((model_dir / MANIFEST).read_text(encoding="utf-8"))
        files: dict[str, str] = manifest["files"]
        for key in ("name", "revision", "model", "tokenizer", "positive_index", "max_tokens"):
            manifest[key]  # noqa: B018  # present, or KeyError below
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise ModelError(f"bad manifest: {type(e).__name__}") from e
    for name, digest in files.items():
        path = model_dir / name
        if not path.is_file():
            raise ModelError(f"missing {name}")
        if sha256_of(path) != digest:
            raise ModelError(f"hash mismatch: {name}")
    for key in ("model", "tokenizer"):
        if manifest[key] not in files:
            raise ModelError(f"{key} file is not hash-pinned")
    return manifest


class OnnxClassifier:
    """``score(text)``: the probability that the text carries instructions aimed at the AI agent. A text
    longer than the model's window is scored window by window (token windows, overlapping) and the worst
    window counts, so nothing past the model's limit goes unread."""

    def __init__(self, model_dir: Path, threads: int | None = None) -> None:
        m = verify(model_dir)  # before the runtime: a rejected model is reported as such, extra or not
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self.np = np
        self.name = f"{m['name']}@{str(m['revision'])[:7]}"
        self.positive = int(m["positive_index"])
        self.window = int(m["max_tokens"]) - 2  # room for [CLS] and [SEP]
        self.tokenizer = Tokenizer.from_file(str(model_dir / m["tokenizer"]))
        self.tokenizer.no_truncation()
        self.tokenizer.no_padding()
        self.cls = self.tokenizer.token_to_id("[CLS]")
        self.sep = self.tokenizer.token_to_id("[SEP]")
        if self.cls is None or self.sep is None:
            raise ModelError("tokenizer has no [CLS]/[SEP]")
        opts = ort.SessionOptions()
        # ~0.3 s per 512-token window with 4 threads on an M3 (2 threads: ~0.4 s): enough for a tool result,
        # still a helper on someone's laptop, not a server.
        opts.intra_op_num_threads = threads or min(4, max(1, (os.cpu_count() or 2) // 2))
        model = str(model_dir / m["model"])
        self.session = ort.InferenceSession(model, opts, providers=["CPUExecutionProvider"])
        self.inputs = {i.name for i in self.session.get_inputs()}

    def windows(self, text: str) -> list[list[int]]:
        ids = self.tokenizer.encode(text, add_special_tokens=False).ids
        step = self.window - WINDOW_OVERLAP
        starts = range(0, max(len(ids) - WINDOW_OVERLAP, 1), step)
        return [[self.cls, *ids[s : s + self.window], self.sep] for s in starts]

    def score(self, text: str) -> float:
        np = self.np
        worst = 0.0
        for ids in self.windows(text):
            feeds = {
                "input_ids": np.array([ids], dtype=np.int64),
                "attention_mask": np.ones((1, len(ids)), dtype=np.int64),
                "token_type_ids": np.zeros((1, len(ids)), dtype=np.int64),
            }
            logits = self.session.run(None, {k: v for k, v in feeds.items() if k in self.inputs})[0][0]
            e = np.exp(logits - logits.max())
            worst = max(worst, float(e[self.positive] / e.sum()))
        return worst
