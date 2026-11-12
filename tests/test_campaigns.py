"""Campaign detection (M11): the same rule + indicator for 3+ distinct people within 24 hours becomes
one central finding (server/campaigns.py). Findings come from the real rules via the engine."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from conftest import CP_ADMIN
from sg_advance.detect import Engine, RuleSet
from sg_advance.schema import Finding
from sg_advance.server.campaigns import RULE_ID
from sg_advance.shorthand import T0, build_event

RULES = RuleSet.load(Path(__file__).resolve().parents[1] / "rules")


def findings_for(
    spec: dict[str, Any], *, user: str, dev: str, hours: float = 0, **defaults: Any
) -> list[Finding]:
    ev = build_event(spec, defaults={"user": user, "device": dev, **defaults}, t0=T0 + timedelta(hours=hours))
    return Engine(RULES).process(ev).findings


def egress(host: str) -> dict[str, Any]:
    return {
        "kind": "net.egress",
        "method": "POST",
        "url": f"http://{host}/up",
        "host": host,
        "destination": "external",
    }


class Fleet:
    """Devices enrolled on first use; each sends findings as itself."""

    def __init__(self, cp: TestClient) -> None:
        self.cp = cp
        self.headers: dict[str, dict[str, str]] = {}

    def send(self, dev: str, findings: list[Finding]) -> None:
        if dev not in self.headers:
            token = self.cp.post("/v1/admin/enrollment-tokens", json={}, headers=CP_ADMIN).json()["token"]
            r = self.cp.post(
                "/v1/enroll", json={"device_id": dev}, headers={"Authorization": f"Bearer {token}"}
            )
            self.headers[dev] = {"Authorization": f"Bearer {r.json()['device_token']}"}
        body = {"findings": [f.model_dump(mode="json") for f in findings]}
        r = self.cp.post("/v1/findings", json=body, headers=self.headers[dev])
        assert r.status_code == 200, r.text

    def hit(
        self, user: str, dev: str, host: str = "exfil-sink.internet-sim", hours: float = 0
    ) -> list[Finding]:
        fs = findings_for(egress(host), user=user, dev=dev, hours=hours, sensor="egress_proxy")
        assert [f.rule_id for f in fs] == ["egress-unapproved-host"]
        self.send(dev, fs)
        return fs

    def campaigns(self) -> list[dict[str, Any]]:
        return self.cp.get("/v1/admin/findings", params={"rule_id": RULE_ID}, headers=CP_ADMIN).json()


def test_three_people_make_one_campaign(cp: TestClient) -> None:
    fleet = Fleet(cp)
    fleet.hit("alice@corp.test", "pc-a")
    fleet.hit("alice@corp.test", "pc-a2", hours=1)  # same person on another device: still one person
    fleet.hit("bob@corp.test", "pc-b", hours=2, host="Exfil-Sink.internet-sim")  # same host, other case
    assert fleet.campaigns() == []
    third = fleet.hit("carol@corp.test", "pc-c", hours=3)

    [c] = fleet.campaigns()
    assert c["detector"] == "central" and c["severity"] == "high" and c["category"] == "data_exfiltration"
    assert c["labels"]["source_rule"] == "egress-unapproved-host"
    assert c["labels"]["indicator"] == "exfil-sink.internet-sim"
    assert c["labels"]["people"] == "alice@corp.test,bob@corp.test,carol@corp.test"
    assert c["labels"]["people_count"] == "3" and len(c["labels"]["findings"].split(",")) == 4
    assert c["principal"]["user_id"] == "carol@corp.test" and c["endpoint"]["device_id"] == "pc-c"
    assert len(c["evidence_event_ids"]) == 4

    # A fourth person within the window joins the same campaign; no second finding.
    fleet.hit("dave@corp.test", "pc-d", hours=5)
    assert len(fleet.campaigns()) == 1
    detail = cp.get(f"/v1/admin/findings/{c['finding_id']}", headers=CP_ADMIN).json()
    assert {m["principal"]["user_id"] for m in detail["campaign_members"]} == {
        "alice@corp.test",
        "bob@corp.test",
        "carol@corp.test",
        "dave@corp.test",
    }
    member = cp.get(f"/v1/admin/findings/{third[0].finding_id}", headers=CP_ADMIN).json()
    assert [x["finding_id"] for x in member["campaigns"]] == [c["finding_id"]]


def test_window_indicator_and_people_must_line_up(cp: TestClient) -> None:
    fleet = Fleet(cp)
    fleet.hit("alice@corp.test", "pc-a")
    fleet.hit("bob@corp.test", "pc-b", hours=2)
    fleet.hit("carol@corp.test", "pc-c", hours=25)  # alice is outside 24h of carol
    fleet.hit("unknown", "pc-u", hours=25.5)  # not a person
    fleet.hit("carol@corp.test", "pc-c", hours=26, host="other.example")  # different indicator
    assert fleet.campaigns() == []
    # Rules without the campaign tag carry no indicator: three people deleting rows is not a campaign.
    for user, dev in [("alice@corp.test", "pc-a"), ("bob@corp.test", "pc-b"), ("carol@corp.test", "pc-c")]:
        sql = {"kind": "tool.call", "tool": "exec", "arguments": {"command": "psql -c 'DELETE FROM t;'"}}
        fs = findings_for(sql, user=user, dev=dev, hours=27)
        assert fs and all("indicator" not in f.labels for f in fs)
        fleet.send(dev, fs)
    assert fleet.campaigns() == []


def test_a_sensor_cannot_forge_a_central_finding(cp: TestClient) -> None:
    fleet = Fleet(cp)
    [f] = findings_for(egress("x.example"), user="alice@corp.test", dev="pc-a", sensor="egress_proxy")
    fleet.send("pc-a", [f.model_copy(update={"detector": "central"})])
    [stored] = cp.get("/v1/admin/findings", params={"rule_id": f.rule_id}, headers=CP_ADMIN).json()
    assert stored["detector"] == "local"
