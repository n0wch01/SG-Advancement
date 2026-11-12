// Pure helpers: labels, time, event one-liners, hash routes. Kept free of React for unit tests.

import type { AgentEvent, Severity } from "./types";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "긴급",
  high: "높음",
  medium: "보통",
  low: "낮음",
  info: "정보",
};

export function severityRank(s: Severity): number {
  return SEVERITIES.length - SEVERITIES.indexOf(s); // critical 5 … info 1
}

export const ACTION_LABEL: Record<string, string> = {
  allow: "허용",
  alert: "알림",
  require_approval: "승인 요청",
  block: "차단",
  abort_session: "실행 중단",
  quarantine: "격리",
};

export function responseText(r: { action: string; enforced: boolean } | null | undefined): string {
  if (!r) return "알림";
  const label = ACTION_LABEL[r.action] ?? r.action;
  if (r.action === "alert" || r.action === "allow") return label;
  return r.enforced ? `${label} (집행됨)` : `${label} (집행 안 됨)`;
}

export function clip(text: string, max = 120): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

export function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export function relativeTime(iso: string, now: Date = new Date()): string {
  const sec = Math.round((now.getTime() - new Date(iso).getTime()) / 1000);
  if (Number.isNaN(sec)) return iso;
  if (sec < 60) return "방금";
  if (sec < 3600) return `${Math.floor(sec / 60)}분 전`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}시간 전`;
  return `${Math.floor(sec / 86400)}일 전`;
}

function str(v: unknown): string {
  return typeof v === "string" ? v : v === undefined || v === null ? "" : JSON.stringify(v);
}

function chatText(p: Record<string, unknown>): string {
  if (p.withheld) return `(원문 미전송 · ${str(p.text_chars) || "?"}자)`;
  return clip(str(p.text));
}

/** One line describing an event for timelines and evidence lists. */
export function eventSummary(e: AgentEvent): string {
  const p = e.payload as Record<string, unknown>;
  switch (p.kind) {
    case "tool.call":
      return `${str(p.tool)} ${clip(str(p.arguments), 100)}`.trim();
    case "tool.result":
      return `${str(p.tool) || "툴"} 결과 ${p.ok === false ? "실패" : "성공"}${p.output_preview ? ` · ${clip(str(p.output_preview), 80)}` : ""}`;
    case "prompt.user":
      return `사용자: ${chatText(p)}`;
    case "message.assistant":
      return `에이전트: ${chatText(p)}`;
    case "session.start":
      return "대화 시작";
    case "session.end":
      return "대화 종료";
    case "net.egress":
      return `외부 통신 ${str(p.method)} ${str(p.host)}`.trim();
    case "llm.call":
      return `모델 호출 ${str(p.provider)}/${str(p.model)}`;
    case "inventory.snapshot": {
      const tools = Array.isArray(p.tools) ? p.tools.length : 0;
      const skills = Array.isArray(p.skills) ? p.skills.length : 0;
      return `에이전트 ${str(p.agent_id) || "-"} 인벤토리 (툴 ${tools}, 스킬 ${skills})`;
    }
    case "install.snapshot":
      return `${str(p.product)} 설치 ${str(p.instance)} · ${p.present === false ? "사라짐" : p.managed ? "관리됨" : "비관리"}`;
    case "config.snapshot": {
      const changed = Array.isArray(p.changed) ? p.changed.join(", ") : "";
      return `설정 ${changed ? `변경: ${changed}` : "스냅샷"}`;
    }
    case "integrity.report":
      return `코드 무결성 보고 ${str(p.version)}`.trim();
    case "approval.resolved":
      return `승인 응답 ${str(p.decision)} · ${str(p.tool)}`;
    case "operator.action":
      return `제어 동작 ${str(p.action)}${p.ok === false ? " (거부됨)" : ""}`;
    case "sensor.health":
      return `${str(p.component)} ${str(p.status)}`;
    default:
      return str(p.kind);
  }
}

export type Route =
  | { page: "overview" }
  | { page: "findings"; query: Record<string, string> }
  | { page: "finding"; id: string };

export function parseHash(hash: string): Route {
  const [path, qs = ""] = hash.replace(/^#/, "").split("?", 2);
  const parts = path.split("/").filter(Boolean);
  if (parts[0] === "findings" && parts[1]) return { page: "finding", id: decodeURIComponent(parts[1]) };
  if (parts[0] === "findings") return { page: "findings", query: Object.fromEntries(new URLSearchParams(qs)) };
  return { page: "overview" };
}

export function findingsHref(query: Record<string, string | undefined> = {}): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) if (v) p.set(k, v);
  const s = p.toString();
  return `#/findings${s ? `?${s}` : ""}`;
}

export function sinceFor(range: string, now: Date = new Date()): string | null {
  const hours: Record<string, number> = { "24h": 24, "7d": 24 * 7, "30d": 24 * 30 };
  const h = hours[range];
  return h ? new Date(now.getTime() - h * 3600_000).toISOString() : null;
}
