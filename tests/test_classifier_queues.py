"""The console's queues over the classifier's work (docs/classifier.md 5, decision 2026-11-16): by default
security sees everything except what the classifier judged benign and nothing enforced; what was actually
withheld is always visible; benign verdicts are a separate queue to sample (the classifier's misses);
the classifier's failures are their own queue. End to end: sensor with a fake model → control plane."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from conftest import CP_ADMIN
from sg_advance.sensor import Sensor
from sg_advance.sensor.judge import InjectionJudge
from test_classifier_cascade import INJECTED, PARAPHRASED, FakeClassifier, read


def queue(cp: TestClient, name: str) -> list[tuple[str, str | None, bool]]:
    rows = cp.get("/v1/admin/findings", params={"queue": name}, headers=CP_ADMIN).json()
    return sorted((f["rule_id"], f["labels"].get("sga_judge_injection"), f["response"]["enforced"])
                  for f in rows)  # fmt: skip


def judged_events(cp: TestClient, verdict: str) -> list[dict[str, Any]]:
    return cp.get("/v1/admin/events", params={"judge": verdict}, headers=CP_ADMIN).json()


def test_queues_split_the_classifiers_work(enrolled: Sensor, cp: TestClient) -> None:
    enrolled.judge = InjectionJudge(FakeClassifier())
    read(enrolled, 1, PARAPHRASED)  # classifier: malicious → withheld
    read(enrolled, 2, INJECTED)  # signature rule withholds; classifier (fooled): benign
    read(enrolled, 3, "Terraform guide. The IPv4 of the mirror is 203.0.113.7.")  # alert only; benign
    read(enrolled, 4, "How to reset a workspace.")  # benign, no finding at all
    assert enrolled.flush().ok

    review = queue(cp, "review")
    assert ("injection-classifier-confirmed", "malicious", True) in review
    assert ("vigil-instruction-bypass", "benign", True) in review  # enforced: always visible
    assert not [r for r in review if r[1] == "benign" and not r[2]]  # benign + unenforced: hidden here

    assert ("vigil-instruction-bypass", "benign", True) in queue(cp, "enforced")
    assert queue(cp, "benign") == [("vigil-ipv4", "benign", False)]
    assert queue(cp, "failed") == []

    # Sampling the classifier's misses: every external result it judged benign, findings or not.
    sampled = {e["payload"]["output_preview"][:12] for e in judged_events(cp, "benign")}
    assert sampled == {INJECTED[:12], "Terraform gu", "How to reset"}


def test_a_failed_classifier_has_its_own_queue(enrolled: Sensor, cp: TestClient) -> None:
    enrolled.judge = InjectionJudge(FakeClassifier(fail=True))
    read(enrolled, 1, INJECTED)
    assert enrolled.flush().ok
    assert queue(cp, "failed") == [("vigil-instruction-bypass", "unavailable", True)]
    assert ("vigil-instruction-bypass", "unavailable", True) in queue(cp, "review")


def test_findings_without_a_verdict_stay_in_review(enrolled: Sensor, cp: TestClient) -> None:
    """Everything the classifier does not look at (exfiltration, destructive commands…) is as before."""
    from sg_advance.sensor.adapters import AdapterContext
    from sg_advance.sensor.plugin_api import CLAUDE_CODE_HOOK, judge_event
    from test_external_input import pre

    ctx = AdapterContext(enrolled, "bob", "pc")
    judge_event(ctx, pre("Bash", 1, command="rm -rf ~/projects"), CLAUDE_CODE_HOOK)
    assert enrolled.flush().ok
    assert [r[0] for r in queue(cp, "review")] == ["destructive-shell-command"]
    assert queue(cp, "benign") == []
