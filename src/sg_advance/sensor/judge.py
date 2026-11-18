"""Second stage of the rule → classifier cascade (docs/classifier.md): does an external tool result carry
instructions aimed at the AI agent?

Only tool results a ``stage:candidate`` rule marked reach the classifier. Its answer is a set of labels
(``sga_judge_*``); the signed rules decide what to do with them, and nothing here can relax enforcement.
Only the sensor daemon classifies (the per-call hook process never does), and since 2026-11-17 the model runs
in a worker process the daemon waits on for at most the time budget (sensor/classifier_worker.py).

Standard library only: the model runtime is an optional extra loaded behind ``Classifier``. Without it
the judge answers ``unavailable`` with the reason, and the rules alone decide (docs/classifier.md 6).
"""

from __future__ import annotations

import ast
import json
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

# Score bands (the classifier's probability that a chunk carries injected instructions). The verdict, not
# the score, is what rules match on. Changing a band is a code change, reviewed like a rule change.
# 0.85 (2026-11-16, user decision; was 0.9): on InjecAgent it has the same false positives as 0.9 (15/85)
# and catches 3 points more hidden instructions (582 vs 550 of 1,054); docs/evaluation-threshold.md.
MALICIOUS_AT = 0.85
UNSURE_AT = 0.5

CHUNK_CHARS = 2000  # roughly a classifier's 512-token window
CHUNK_OVERLAP = 200  # an instruction split across two chunks is still seen whole in one
MAX_CHUNKS = 64  # ~128 KB of text per result
BUDGET_SECONDS = 2.0  # per result; a tool result must not stall the agent for long

# Copied onto the event's findings too (the console's queues sort findings by verdict).
FINDING_LABELS = ("sga_judge_injection", "sga_judge_score", "sga_judge_model")
LABELS = ("sga_candidate", "sga_judge_injection", "sga_judge_score", "sga_judge_model", "sga_judge_chunks",
          "sga_judge_reason")  # fmt: skip


class ClassifierUnavailable(Exception):
    """No working model right now (worker down, restarting, or it reported an error); the reason is kept."""


class Classifier(Protocol):
    """One loaded model: ``name`` (model and version, recorded with every verdict) and ``score``."""

    name: str

    def score(self, text: str) -> float:
        """Probability (0..1) that this chunk carries instructions aimed at the AI agent."""
        ...


@dataclass(frozen=True)
class Judgement:
    verdict: str  # malicious | unsure | benign | unavailable
    score: float | None
    model: str
    scanned: int
    total: int
    reason: str = ""

    def labels(self) -> dict[str, str]:
        out = {
            "sga_judge_injection": self.verdict,
            "sga_judge_model": self.model,
            "sga_judge_chunks": f"{self.scanned}/{self.total}",
        }
        if self.score is not None:
            out["sga_judge_score"] = f"{self.score:.3f}"
        if self.reason:
            out["sga_judge_reason"] = self.reason[:200]
        return out


def chunks(text: str, size: int = CHUNK_CHARS, overlap: int = CHUNK_OVERLAP) -> list[str]:
    if not text:
        return []
    step = size - overlap
    return [text[i : i + size] for i in range(0, max(len(text) - overlap, 1), step)]


RECORD_MERGE = 300  # short plain-text paragraphs may share one score
STRUCTURED_MAX = 200_000  # characters a result may have to be read as JSON / a Python literal


def _structured(text: str) -> object | None:
    head = text.lstrip()[:1]
    if head not in ("{", "[") or len(text) > STRUCTURED_MAX:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        pass
    try:
        return ast.literal_eval(text)  # tool output printed as a Python dict (literals only, never code)
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return None


def _largest_list(value: object, depth: int = 0) -> list | None:
    if depth > 6:
        return None
    best: list | None = value if isinstance(value, list) and len(value) >= 2 else None
    children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
    for child in children:
        found = _largest_list(child, depth + 1)
        if found is not None and (best is None or len(found) > len(best)):
            best = found
    return best


def records(text: str, max_records: int = MAX_CHUNKS) -> list[str]:
    """A tool result split into the records it is made of, each scored on its own (2026-11-17,
    docs/classifier.md 13): benign records glued into one window score as an attack (0.90-0.97 measured),
    and an attacker usually controls one record (one mail, one review, one page section). Structured output:
    metadata first, followed by the items of its largest list; plain text: paragraphs. Identical records
    need only one score. Too many distinct records fall back to the original overlapping windows instead
    of consuming the scan allowance on tiny items. Long records are chunked as before."""
    data = _structured(text)
    parts: list[str]
    if data is not None and (items := _largest_list(data)) is not None:
        rest = json.dumps(_without(data, items), ensure_ascii=False, default=str)
        parts = [rest] if rest not in ("null", "[]", "{}") else []
        parts.extend(json.dumps(item, ensure_ascii=False, default=str) for item in items)
    else:
        parts = _merge_short(para.strip() for para in re.split(r"\n\s*\n", text) if para.strip())
    parts = list(dict.fromkeys(parts))
    if len(parts) > max_records:
        return chunks(text)
    out: list[str] = []
    for part in parts:
        out.extend(chunks(part) if len(part) > CHUNK_CHARS else [part])
    return out


def _merge_short(parts: Iterable[str]) -> list[str]:
    out: list[str] = []
    for part in parts:
        if out and len(out[-1]) + len(part) + 2 <= RECORD_MERGE:
            out[-1] += "\n\n" + part
        else:
            out.append(part)
    return out


def _without(value: object, target: list) -> object:
    if value is target:
        return None
    if isinstance(value, dict):
        return {k: _without(v, target) for k, v in value.items() if v is not target}
    if isinstance(value, list):
        return [_without(v, target) for v in value]
    return value


def verdict_for(score: float) -> str:
    return "malicious" if score >= MALICIOUS_AT else "unsure" if score >= UNSURE_AT else "benign"


class InjectionJudge:
    """Scores a text chunk by chunk and keeps the worst. Stops early at the first malicious chunk.
    Fails toward attention: a result it could not finish (too many chunks, out of time) and found
    nothing in is ``unsure``, never ``benign``."""

    def __init__(
        self,
        classifier: Classifier | None,
        unavailable_reason: str = "no classifier installed",
        max_chunks: int = MAX_CHUNKS,
        budget: float = BUDGET_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        by_record: bool = True,
    ) -> None:
        self.classifier = classifier
        # records() instead of fixed windows (on since 2026-11-17, user decision: glued benign records scored
        # as attacks in 72% of long results; per record, attacks score as they do alone; classifier.md 13)
        self.by_record = by_record
        self.unavailable_reason = unavailable_reason
        self.max_chunks = max_chunks
        self.budget = budget
        self.clock = clock

    @property
    def model(self) -> str:
        return self.classifier.name if self.classifier is not None else "none"

    def judge(self, text: str) -> Judgement:
        parts = records(text, max_records=self.max_chunks) if self.by_record else chunks(text)
        if self.classifier is None:
            return Judgement("unavailable", None, self.model, 0, len(parts), self.unavailable_reason)
        start = self.clock()
        worst = 0.0
        scanned = 0
        reason = ""
        for part in parts:
            if scanned >= self.max_chunks:
                reason = "chunk limit"
                break
            left = self.budget - (self.clock() - start)
            if scanned and left <= 0:
                reason = "time budget"
                break
            try:
                # A worker is told how long it may take; an in-process model is checked between chunks.
                within = getattr(self.classifier, "score_within", None)
                score = within(part, max(left, 0.05)) if within else self.classifier.score(part)
                worst = max(worst, float(score))
            except TimeoutError:
                reason = "time budget"
                break
            except Exception as e:  # the model's failure is recorded, never raised into the hook path
                why = str(e)[:200] if isinstance(e, ClassifierUnavailable) else f"error: {type(e).__name__}"
                return Judgement("unavailable", None, self.model, scanned, len(parts), why)
            scanned += 1
            if worst >= MALICIOUS_AT:
                break
        verdict = verdict_for(worst)
        if reason and verdict == "benign":
            verdict = "unsure"  # the unread rest may hold what we look for
        return Judgement(verdict, worst, self.model, scanned, len(parts), reason)


def load_judge(model_dir: Path | None) -> InjectionJudge:
    """A judge with the ONNX model in this process (sensor/onnx_classifier.py), or none: for scripts and
    measurements. Every way the model can be missing is recorded as the reason, and the rules alone decide."""
    if model_dir is None or not model_dir.is_dir():
        return InjectionJudge(None)
    from .classifier_worker import load_error

    try:
        from .onnx_classifier import OnnxClassifier  # standard library until a model loads

        return InjectionJudge(OnnxClassifier(model_dir))
    except Exception as e:  # noqa: BLE001  # a broken runtime or file: recorded, the caller keeps running
        return InjectionJudge(None, load_error(e))


def load_worker_judge(model_dir: Path | None, budget: float = BUDGET_SECONDS) -> InjectionJudge:
    """The daemon's judge: the same model in a worker process (sensor/classifier_worker.py), so a slow or
    broken model costs one verdict, never the daemon or the hooks waiting on it."""
    if model_dir is None or not model_dir.is_dir():
        return InjectionJudge(None)
    from .classifier_worker import WorkerClassifier

    worker = WorkerClassifier(model_dir)
    try:
        worker.start()
    except ClassifierUnavailable as e:
        return InjectionJudge(None, str(e))
    return InjectionJudge(worker, budget=budget)
