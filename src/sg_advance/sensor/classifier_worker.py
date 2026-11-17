"""The injection classifier in its own process (docs/classifier.md 11, 2026-11-17).

Inside the daemon the model cost the daemon ~1.5 GB and, worse, a slow or hung model stalled every hook
waiting on the daemon (the hook gives up after 3 s and fails closed: a false block). In a worker:

- the daemon waits at most the judge's time budget for an answer. Past it the result is ``unsure`` and
  the worker's late answer is thrown away; a worker that stays busy too long is killed and restarted;
- a crashed or killed worker costs one ``unavailable`` verdict, not the daemon;
- the model's memory and CPU belong to a separate, lower-priority process, and the daemon itself stays
  small;
- the worker verifies the pinned model files itself (sensor/onnx_classifier.py) before loading.

Protocol, one ASCII JSON object per line: the worker first prints ``{"ready": "<model>"}`` or
``{"error": "<reason>"}``; then each ``{"id": n, "text": "..."}`` gets ``{"id": n, "score": p}`` or
``{"id": n, "error": "..."}``. It exits when its stdin closes, so it never outlives the daemon.

Daemon side: standard library only (the runtime is imported by the worker process).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, TextIO

from .judge import ClassifierUnavailable

START_SECONDS = 60.0  # loading the model (fp32: ~1.4 s on an M3) on a slow laptop
HUNG_SECONDS = 30.0  # one request still unanswered after this: the worker is killed and restarted
RESTART_BACKOFF = 60.0  # after a failed start, don't try again for this long (each try costs a load)


def load_error(e: BaseException) -> str:
    """The same reasons ``judge.load_judge`` records, whichever process loaded the model."""
    from .onnx_classifier import ModelError

    if isinstance(e, ModelError):
        return f"model rejected: {e}"
    if isinstance(e, ImportError):
        return "classifier extra not installed (sg-advance[classifier])"
    return f"model failed to load: {type(e).__name__}"


class WorkerClassifier:
    """A ``Classifier`` whose model runs in ``python -m sg_advance.sensor.classifier_worker``. Used from one
    thread (the daemon's event loop); ``score_within`` never waits longer than it is told to."""

    def __init__(
        self,
        model_dir: Path,
        *,
        threads: int | None = None,
        start_seconds: float = START_SECONDS,
        hung_seconds: float = HUNG_SECONDS,
        restart_backoff: float = RESTART_BACKOFF,
        command: list[str] | None = None,
        clock: Any = time.monotonic,
    ) -> None:
        self.model_dir = model_dir
        self.command = command or [sys.executable, "-m", __name__, str(model_dir)]
        if threads and command is None:
            self.command += ["--threads", str(threads)]
        self.start_seconds = start_seconds
        self.hung_seconds = hung_seconds
        self.restart_backoff = restart_backoff
        self.clock = clock
        self.name = "none"
        self._proc: subprocess.Popen[str] | None = None
        self._lines: queue.Queue[str | None] = queue.Queue()
        self._next = 0
        self._outstanding: dict[int, float] = {}  # request id -> when it was sent (answers not yet read)
        self._failed_at: float | None = None
        self._last_error = ""

    # ── process ─────────────────────────────────────────────────────────────

    @property
    def alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @property
    def pid(self) -> int | None:
        return self._proc.pid if self.alive else None  # type: ignore[union-attr]

    def start(self) -> None:
        """Start the worker and wait for the model to load. Raises ``ClassifierUnavailable`` with the
        reason the worker gave (or why it gave none)."""
        self.close()
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # Windows: no console window
        try:
            proc = subprocess.Popen(  # noqa: S603  # our own module, run by this Python
                self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, encoding="ascii", errors="replace", bufsize=1, creationflags=flags,
            )  # fmt: skip
        except OSError as e:
            raise self._fail(f"worker failed to start: {type(e).__name__}") from e
        lines: queue.Queue[str | None] = queue.Queue()
        pump = threading.Thread(target=_pump, args=(proc.stdout, lines), daemon=True, name="sga-classifier")
        pump.start()
        self._proc, self._lines, self._outstanding = proc, lines, {}
        try:
            first = lines.get(timeout=self.start_seconds)
        except queue.Empty:
            self.close()
            raise self._fail("model did not load in time") from None
        doc = _parse(first)
        if doc is None or "ready" not in doc:
            reason = str(doc.get("error")) if doc else "worker exited before loading the model"
            self.close()
            raise self._fail(reason)
        self.name = str(doc["ready"])
        self._failed_at = None

    def close(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        with contextlib.suppress(OSError):
            proc.stdin.close()  # type: ignore[union-attr]  # the worker exits on EOF
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=2)

    def _fail(self, reason: str) -> ClassifierUnavailable:
        self._failed_at = self.clock()
        self._last_error = reason
        return ClassifierUnavailable(reason)

    def _drain(self) -> None:
        """Read late answers already waiting, so a request answered long ago is not taken for a hang."""
        while True:
            try:
                line = self._lines.get_nowait()
            except queue.Empty:
                return
            doc = _parse(line)
            if doc is None:
                self.close()
                return
            self._outstanding.pop(doc.get("id"), None)  # type: ignore[arg-type]

    def _ensure(self) -> None:
        self._drain()
        if self._outstanding and self.clock() - min(self._outstanding.values()) > self.hung_seconds:
            self.close()  # still busy with something long given up on: start clean
        if self.alive:
            return
        if self._failed_at is not None and self.clock() - self._failed_at < self.restart_backoff:
            raise ClassifierUnavailable(f"worker down: {self._last_error}")
        self.start()

    # ── scoring ─────────────────────────────────────────────────────────────

    def score(self, text: str) -> float:
        return self.score_within(text, self.hung_seconds)

    def score_within(self, text: str, seconds: float) -> float:
        """The model's score for ``text``, or ``TimeoutError`` after ``seconds`` (the worker's answer, when
        it comes, is discarded). ``ClassifierUnavailable`` when there is no working worker."""
        self._ensure()
        self._next += 1
        rid = self._next
        sent = self.clock()
        try:
            self._proc.stdin.write(json.dumps({"id": rid, "text": text}) + "\n")  # type: ignore[union-attr]
            self._proc.stdin.flush()  # type: ignore[union-attr]
        except (OSError, ValueError) as e:
            self.close()
            raise self._fail("worker exited") from e
        self._outstanding[rid] = sent
        deadline = sent + seconds
        while True:
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise TimeoutError("classifier time budget")
            try:
                line = self._lines.get(timeout=remaining)
            except queue.Empty:
                raise TimeoutError("classifier time budget") from None
            doc = _parse(line)
            if doc is None:  # EOF: the worker died (crash, out of memory, killed)
                self.close()
                raise self._fail("worker exited")
            self._outstanding.pop(doc.get("id"), None)  # type: ignore[arg-type]
            if doc.get("id") != rid:
                continue  # a late answer to a request already given up on
            if "error" in doc:
                raise ClassifierUnavailable(str(doc["error"]))
            return float(doc["score"])


def _pump(stream: TextIO, lines: queue.Queue[str | None]) -> None:
    with contextlib.suppress(OSError, ValueError):
        for line in stream:
            lines.put(line)
    lines.put(None)


def _parse(line: str | None) -> dict[str, Any] | None:
    if line is None:
        return None
    try:
        doc = json.loads(line)
    except json.JSONDecodeError:
        return {"error": "worker sent something unreadable"}
    return doc if isinstance(doc, dict) else {"error": "worker sent something unreadable"}


# ── worker process ──────────────────────────────────────────────────────────


def _lower_priority() -> None:
    """A helper on someone's laptop: the person's own apps come first."""
    if hasattr(os, "nice"):
        with contextlib.suppress(OSError):
            os.nice(10)
    elif sys.platform == "win32":
        import ctypes

        below_normal = 0x00004000
        handle = ctypes.windll.kernel32.GetCurrentProcess()  # type: ignore[attr-defined]
        ctypes.windll.kernel32.SetPriorityClass(handle, below_normal)  # type: ignore[attr-defined]


def _emit(doc: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(doc) + "\n")
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sga-classifier", description="SG-Advance injection classifier worker")
    p.add_argument("model_dir", type=Path)
    p.add_argument("--threads", type=int, default=None)
    args = p.parse_args(argv)
    _lower_priority()
    try:
        from .onnx_classifier import OnnxClassifier

        clf = OnnxClassifier(args.model_dir, threads=args.threads)
    except Exception as e:  # noqa: BLE001  # every reason goes back to the daemon, which keeps running
        _emit({"error": load_error(e)})
        return 1
    _emit({"ready": clf.name})
    for line in sys.stdin:
        try:
            req = json.loads(line)
            rid, text = req["id"], str(req["text"])
        except (ValueError, KeyError, TypeError):
            _emit({"id": None, "error": "bad request"})
            continue
        try:
            _emit({"id": rid, "score": float(clf.score(text))})
        except Exception as e:  # noqa: BLE001
            _emit({"id": rid, "error": f"error: {type(e).__name__}"})
    return 0


if __name__ == "__main__":
    sys.exit(main())
