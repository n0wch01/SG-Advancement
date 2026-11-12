import { describe, expect, it } from "vitest";

import {
  activeBlocks,
  campaignPeople,
  agentPosture,
  reasonText,
  responseChoices,
  sessionTree,
  shortSession,
  timelineHref,
  approvalsHref,
  approverText,
  clip,
  eventSummary,
  findingsHref,
  parseHash,
  relativeTime,
  responseText,
  severityRank,
  sinceFor,
  waitText,
} from "./format";
import type { AgentEvent, Finding } from "./types";

function ev(payload: Record<string, unknown>): AgentEvent {
  return {
    event_id: "e1",
    ts: "2026-11-12T08:00:00Z",
    endpoint: { device_id: "d" },
    principal: { user_id: "u" },
    agent: { type: "openclaw", session_id: "s" },
    source: { sensor: "x" },
    payload: payload as AgentEvent["payload"],
    labels: {},
  };
}

describe("format", () => {
  it("ranks severities", () => {
    expect(severityRank("critical")).toBeGreaterThan(severityRank("high"));
    expect(severityRank("low")).toBeGreaterThan(severityRank("info"));
  });

  it("describes the response and whether it was enforced", () => {
    expect(responseText(null)).toBe("알림");
    expect(responseText({ action: "block", enforced: true })).toBe("차단 (집행됨)");
    expect(responseText({ action: "abort_session", enforced: false })).toBe("실행 중단 (집행 안 됨)");
  });

  it("never shows withheld chat text, only its length", () => {
    expect(eventSummary(ev({ kind: "prompt.user", withheld: true, text_chars: 13 }))).toBe("사용자: (원문 미전송 · 13자)");
    expect(eventSummary(ev({ kind: "prompt.user", text: "read  the\nREADME" }))).toBe("사용자: read the README");
  });

  it("summarizes tool calls, installs and egress", () => {
    expect(eventSummary(ev({ kind: "tool.call", tool: "exec", arguments: { command: "ls" } }))).toBe(
      'exec {"command":"ls"}',
    );
    expect(eventSummary(ev({ kind: "install.snapshot", product: "openclaw", instance: "/h/.openclaw", managed: false }))).toBe(
      "openclaw 설치 /h/.openclaw · 비관리",
    );
    expect(eventSummary(ev({ kind: "net.egress", method: "CONNECT", host: "wttr.in" }))).toBe("외부 통신 CONNECT wttr.in");
    expect(eventSummary(ev({ kind: "something.new" }))).toBe("something.new");
  });

  it("clips long text", () => {
    expect(clip("a".repeat(10), 5)).toBe("aaaa…");
  });

  it("parses hash routes", () => {
    expect(parseHash("")).toEqual({ page: "overview" });
    expect(parseHash("#/findings?min_severity=high&user_id=carol%40corp.test")).toEqual({
      page: "findings",
      query: { min_severity: "high", user_id: "carol@corp.test" },
    });
    expect(parseHash("#/findings/abc123")).toEqual({ page: "finding", id: "abc123" });
    expect(findingsHref({ rule_id: "r1", user_id: undefined })).toBe("#/findings?rule_id=r1");
  });

  it("routes the approval audit", () => {
    expect(parseHash("#/approvals?approved=true")).toEqual({ page: "approvals", query: { approved: "true" } });
    expect(approvalsHref({ approved: "true", user_id: "" })).toBe("#/approvals?approved=true");
  });

  it("says who approved and how we know", () => {
    expect(approverText({ approver: "secops@corp.test", approver_source: "audit_proxy", user_id: "alice@corp.test" })).toEqual({
      who: "secops@corp.test",
      how: "감사 프록시로 확인",
      other: true,
    });
    expect(approverText({ approver: null, approver_source: null, user_id: "a" }).who).toBe("기록 없음");
    expect(approverText({ approver: "a", approver_source: "agent", user_id: "a" }).other).toBe(false);
    expect(waitText(850)).toBe("850ms");
    expect(waitText(75_000)).toBe("1분 15초");
  });

  it("summarizes an agent's posture", () => {
    const p = agentPosture({
      tools: [{}, {}],
      skills: [
        { name: "github", source: "openclaw-bundled" },
        { name: "deploy-notes", source: "openclaw-workspace", integrity: "verified" },
        { name: "new", source: "openclaw-managed", integrity: "unknown" },
        { name: "bad", source: "openclaw-workspace", integrity: "mismatch" },
      ],
      model_runtimes: [{ source: "model" }, { source: "implicit" }],
      sessions: [{ binding: "current" }, { binding: "stale" }, { binding: "unpinned" }],
    });
    expect(p).toEqual({
      tools: 2,
      skills: 4,
      unverifiedSkills: ["new"],
      tamperedSkills: ["bad"],
      unpinnedModels: 1,
      sessions: 3,
      staleSessions: 1,
    });
    expect(parseHash("#/inventory")).toEqual({ page: "inventory" });
    expect(agentPosture({ tools: [] })).toMatchObject({ unpinnedModels: null, sessions: null });
    expect(reasonText("guard plugin missing")).toBe("실행 전 판정 플러그인 없음");
    expect(reasonText("no SG-Advance sensor watches this config")).toBe("SG-Advance 센서가 감시하지 않음");
    expect(reasonText("something new")).toBe("something new");
  });

  it("orders sessions as a delegation tree", () => {
    const n = (session_id: string, parent_session_id: string | null) => ({ session_id, parent_session_id });
    const tree = sessionTree([n("child", "root"), n("other", null), n("root", null), n("grand", "child"), n("orphan", "gone")]);
    expect(tree.map((t) => `${t.depth}:${t.node.session_id}`)).toEqual(["0:other", "0:root", "1:child", "2:grand", "0:orphan"]);
    expect(shortSession("agent:main:subagent:f65ab953")).toBe("subagent:f65ab953");
    expect(timelineHref({ session_id: "a:b" })).toBe("#/timeline?session_id=a%3Ab");
    expect(parseHash("#/timeline?user_id=x")).toEqual({ page: "timeline", query: { user_id: "x" } });
  });

  it("offers only stricter responses to a team", () => {
    expect(responseChoices("common", "block")[0]).toBe("allow");
    expect(responseChoices("data-team", "require_approval")).toEqual(["require_approval", "block", "abort_session", "quarantine"]);
    expect(parseHash("#/policy?scope=data-team")).toEqual({ page: "policy", query: { scope: "data-team" } });
  });

  it("works out what is blocked right now", () => {
    const a = (action: string, target: string, created_at: string, status = "done") => ({ device_id: "gw", action, target, created_at, status });
    const blocks = activeBlocks([
      a("block_session", "s1", "2026-11-12T01:00:00Z"),
      a("unblock_session", "s1", "2026-11-12T02:00:00Z"),
      a("block_user", "mallory", "2026-11-12T03:00:00Z", "pending"),
      a("block_session", "s2", "2026-11-12T04:00:00Z", "failed"),
      a("abort_session", "s3", "2026-11-12T05:00:00Z"),
    ]);
    expect(blocks.map((b) => b.target)).toEqual(["mallory"]);
    expect(parseHash("#/actions")).toEqual({ page: "actions" });
  });

  it("groups campaign members by person", () => {
    const f = (user: string, device: string, ts: string) =>
      ({ finding_id: `${user}-${ts}`, ts, principal: { user_id: user }, endpoint: { device_id: device } }) as Finding;
    const people = campaignPeople([
      f("bob", "pc-b", "2026-11-12T02:00:00Z"),
      f("alice", "pc-a", "2026-11-12T01:00:00Z"),
      f("alice", "pc-a2", "2026-11-12T03:00:00Z"),
      f("unknown", "pc-u", "2026-11-12T04:00:00Z"),
    ]);
    expect(people.map((p) => [p.user_id, p.devices, p.findings.length])).toEqual([
      ["alice", ["pc-a", "pc-a2"], 2],
      ["bob", ["pc-b"], 1],
    ]);
  });

  it("computes time ranges", () => {
    const now = new Date("2026-11-12T12:00:00Z");
    expect(sinceFor("24h", now)).toBe("2026-11-11T12:00:00.000Z");
    expect(sinceFor("all", now)).toBeNull();
    expect(relativeTime("2026-11-12T11:58:00Z", now)).toBe("2분 전");
  });
});
