import { describe, expect, it } from "vitest";

import { clip, eventSummary, findingsHref, parseHash, relativeTime, responseText, severityRank, sinceFor } from "./format";
import type { AgentEvent } from "./types";

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

  it("computes time ranges", () => {
    const now = new Date("2026-11-12T12:00:00Z");
    expect(sinceFor("24h", now)).toBe("2026-11-11T12:00:00.000Z");
    expect(sinceFor("all", now)).toBeNull();
    expect(relativeTime("2026-11-12T11:58:00Z", now)).toBe("2분 전");
  });
});
