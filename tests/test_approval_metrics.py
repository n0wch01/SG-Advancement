"""Approval-fatigue metrics (2026-11-13, KISA ZT guide C2; 금융보안원 ⑭)."""

from __future__ import annotations

from conftest import CP_ADMIN
from sg_advance.sensor import Sensor
from sg_advance.sensor.state import now_utc
from sg_advance.shorthand import build_event


def resolved(user: str, decision: str, wait_ms: int, rules: list[str], tool: str = "exec"):
    approved = decision.startswith("allow")
    spec = {
        "kind": "approval.resolved", "user": user, "call_id": f"c-{user}-{wait_ms}-{decision}", "tool": tool,
        "decision": decision, "approved": approved, "rule_ids": rules, "max_severity": "high",
        "wait_ms": wait_ms,
    }  # fmt: skip
    return build_event(spec, t0=now_utc())


def test_metrics_show_waits_rejections_fast_approvals_and_automation_candidates(enrolled: Sensor, cp) -> None:
    # alice approves the same SQL prompt six times within a second or two: rubber-stamping.
    for i in range(6):
        enrolled.process(resolved("alice", "allow-once", 1000 + i, ["destructive-sql"]))
    enrolled.process(resolved("bob", "allow-once", 40_000, ["destructive-cloud-command"]))
    enrolled.process(resolved("bob", "deny", 20_000, ["destructive-cloud-command"]))
    enrolled.flush()
    m = cp.get("/v1/admin/approvals/metrics", headers=CP_ADMIN).json()
    u = m["user"]
    assert u["requests"] == 8 and u["approved"] == 7 and u["denied"] == 1
    assert u["rejection_rate"] == round(1 / 8, 3)
    assert u["fast_approvals"] == 6 and u["fast_approval_rate"] == round(6 / 7, 3)
    top = m["repeated"][0]
    assert top["rule_ids"] == ["destructive-sql"] and top["requests"] == 6 and top["automation_candidate"]
    assert not any(t["automation_candidate"] for t in m["repeated"][1:])
    people = {p["user_id"]: p for p in m["people"]}
    assert people["alice"]["busiest_day"] == 6 and people["alice"]["fast_approval_rate"] == 1.0
    assert m["security"]["requests"] == 0
