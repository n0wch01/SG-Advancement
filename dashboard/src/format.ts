// Pure helpers: labels, time, event one-liners, hash routes. Kept free of React for unit tests.

import type { AgentEvent, Finding, Severity } from "./types";

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
  security_approval: "보안팀 승인",
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

export const DECISION_LABEL: Record<string, string> = {
  "allow-once": "이번만 허용",
  "allow-always": "항상 허용",
  deny: "거절",
  timeout: "시간 초과",
  cancelled: "취소",
};

/** Who pressed approve, and how sure we are about it (team gateway: the audit proxy saw it). */
export function approverText(a: { approver: string | null; approver_source: string | null; user_id: string }): {
  who: string;
  how: string;
  other: boolean;
} {
  if (!a.approver) return { who: "기록 없음", how: "감사 프록시를 거치지 않은 응답", other: false };
  const how = a.approver_source === "audit_proxy" ? "감사 프록시로 확인" : "에이전트가 보고";
  return { who: a.approver, how, other: a.approver !== a.user_id };
}

export function waitText(ms: number | null): string {
  if (ms === null || ms === undefined) return "-";
  if (ms < 1000) return `${ms}ms`;
  const s = Math.round(ms / 1000);
  return s < 60 ? `${s}초` : `${Math.floor(s / 60)}분 ${s % 60}초`;
}

export type Route =
  | { page: "overview" }
  | { page: "findings"; query: Record<string, string> }
  | { page: "finding"; id: string }
  | { page: "approvals"; query: Record<string, string> }
  | { page: "inventory" }
  | { page: "timeline"; query: Record<string, string> }
  | { page: "policy"; query: Record<string, string> }
  | { page: "actions" }
  | { page: "security" };

export function parseHash(hash: string): Route {
  const [path, qs = ""] = hash.replace(/^#/, "").split("?", 2);
  const parts = path.split("/").filter(Boolean);
  if (parts[0] === "findings" && parts[1]) return { page: "finding", id: decodeURIComponent(parts[1]) };
  if (parts[0] === "findings") return { page: "findings", query: Object.fromEntries(new URLSearchParams(qs)) };
  if (parts[0] === "inventory") return { page: "inventory" };
  if (parts[0] === "actions") return { page: "actions" };
  if (parts[0] === "security") return { page: "security" };
  if (parts[0] === "policy") return { page: "policy", query: Object.fromEntries(new URLSearchParams(qs)) };
  if (parts[0] === "timeline") return { page: "timeline", query: Object.fromEntries(new URLSearchParams(qs)) };
  if (parts[0] === "approvals") return { page: "approvals", query: Object.fromEntries(new URLSearchParams(qs)) };
  return { page: "overview" };
}

function href(path: string, query: Record<string, string | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) if (v) p.set(k, v);
  const s = p.toString();
  return `#/${path}${s ? `?${s}` : ""}`;
}

export function findingsHref(query: Record<string, string | undefined> = {}): string {
  return href("findings", query);
}

export function timelineHref(query: Record<string, string | undefined> = {}): string {
  return href("timeline", query);
}

export function approvalsHref(query: Record<string, string | undefined> = {}): string {
  return href("approvals", query);
}

export function sinceFor(range: string, now: Date = new Date()): string | null {
  const hours: Record<string, number> = { "24h": 24, "7d": 24 * 7, "30d": 24 * 30 };
  const h = hours[range];
  return h ? new Date(now.getTime() - h * 3600_000).toISOString() : null;
}

type Row = Record<string, unknown>;

function rows(v: unknown): Row[] {
  return Array.isArray(v) ? (v.filter((x) => x && typeof x === "object") as Row[]) : [];
}

/** The parts of an agent inventory snapshot security looks at first. */
export function agentPosture(p: Row): {
  tools: number;
  skills: number;
  unverifiedSkills: string[];
  tamperedSkills: string[];
  unpinnedModels: number | null;
  sessions: number | null;
  staleSessions: number;
} {
  const skills = rows(p.skills);
  const local = skills.filter((s) => s.source !== "openclaw-bundled" && s.source !== "openclaw-extra");
  const sessions = rows(p.sessions);
  const models = rows(p.model_runtimes);
  return {
    tools: rows(p.tools).length,
    skills: skills.length,
    unverifiedSkills: local.filter((s) => s.integrity !== "verified" && s.integrity !== "mismatch").map((s) => String(s.name)),
    tamperedSkills: skills.filter((s) => s.integrity === "mismatch").map((s) => String(s.name)),
    // null: the sensor did not report it (gateway without models.list / sessions.list), not "all fine"
    unpinnedModels: models.length ? models.filter((m) => m.source === "implicit").length : null,
    sessions: Array.isArray(p.sessions) && (sessions.length || models.length) ? sessions.length : null,
    staleSessions: sessions.filter((s) => s.binding === "stale").length,
  };
}

const REASON_LABEL: Record<string, string> = {
  "not configured": "설정된 적 없음",
  "config unreadable": "설정 파일을 읽을 수 없음",
  "no SG-Advance sensor watches this config": "SG-Advance 센서가 감시하지 않음",
};

/** Sensor-side unmanaged reasons (English, stable strings) in Korean. */
export function reasonText(reason: string): string {
  const guard = /^guard plugin (\w+)$/.exec(reason);
  if (guard) return `실행 전 판정 플러그인 ${GUARD_LABEL[guard[1]] ?? guard[1]}`;
  return REASON_LABEL[reason] ?? reason;
}

export const GUARD_LABEL: Record<string, string> = { enabled: "켜짐", disabled: "꺼짐", missing: "없음" };

/** "agent:main:subagent:f65ab953" → "subagent:f65ab953" (the agent prefix repeats everywhere). */
export function shortSession(id: string): string {
  const parts = id.split(":");
  return parts.length > 2 ? parts.slice(-2).join(":") : id;
}

/** Sessions in tree order (each parent followed by the sessions it delegated to), with depth. */
export function sessionTree<T extends { session_id: string; parent_session_id: string | null }>(
  nodes: T[],
): { node: T; depth: number }[] {
  const ids = new Set(nodes.map((n) => n.session_id));
  const kids = new Map<string, T[]>();
  const roots: T[] = [];
  for (const n of nodes) {
    if (n.parent_session_id && ids.has(n.parent_session_id) && n.parent_session_id !== n.session_id) {
      kids.set(n.parent_session_id, [...(kids.get(n.parent_session_id) ?? []), n]);
    } else roots.push(n);
  }
  const out: { node: T; depth: number }[] = [];
  const seen = new Set<string>();
  const walk = (n: T, depth: number) => {
    if (seen.has(n.session_id)) return;
    seen.add(n.session_id);
    out.push({ node: n, depth });
    for (const k of kids.get(n.session_id) ?? []) walk(k, depth + 1);
  };
  roots.forEach((r) => walk(r, 0));
  return out;
}

export const RESPONSES = ["allow", "alert", "require_approval", "security_approval", "block", "abort_session", "quarantine"];

/** Responses a scope may pick: anything for common, the current one or stricter for a group. */
export function responseChoices(scope: string, current: string): string[] {
  if (scope === "common") return RESPONSES;
  const i = RESPONSES.indexOf(current);
  return RESPONSES.slice(i < 0 ? 0 : i);
}

export const CHANGE_LABEL: Record<string, string> = {
  "override.set": "룰 변경",
  "override.clear": "변경 취소",
  "group.create": "팀 생성",
  "device.assign": "장비 배정",
};

export const REMOTE_ACTION_LABEL: Record<string, string> = {
  block_session: "대화 차단",
  unblock_session: "대화 차단 해제",
  block_user: "사람 차단",
  unblock_user: "사람 차단 해제",
  abort_session: "실행 중단",
  disable_plugin: "플러그인 격리",
  disable_skill: "스킬 격리",
};

export const ACTION_STATUS_LABEL: Record<string, string> = {
  pending: "대기",
  delivered: "센서가 받음",
  done: "완료",
  failed: "실패",
};

/** What is blocked right now: the latest successful block/unblock per device and target wins. */
export function activeBlocks<T extends { device_id: string; action: string; target: string; status: string; created_at: string }>(
  actions: T[],
): T[] {
  const latest = new Map<string, T>();
  const pairs: Record<string, string> = { block_session: "session", unblock_session: "session", block_user: "user", unblock_user: "user" };
  for (const a of [...actions].sort((x, y) => x.created_at.localeCompare(y.created_at))) {
    const kind = pairs[a.action];
    if (!kind || a.status === "failed") continue;
    latest.set(`${a.device_id}|${kind}|${a.target}`, a);
  }
  return [...latest.values()].filter((a) => a.action.startsWith("block_"));
}

// Campaign detection (M11): the control plane's own finding when one rule + indicator reaches 3+ people.
export const CAMPAIGN_RULE = "multi-user-campaign";

export interface CampaignPerson {
  user_id: string;
  devices: string[];
  findings: Finding[]; // oldest first
}

/** Members of a campaign grouped by person, earliest person first; "unknown" is not a person. */
export function campaignPeople(members: Finding[]): CampaignPerson[] {
  const by = new Map<string, CampaignPerson>();
  for (const f of [...members].sort((a, b) => a.ts.localeCompare(b.ts))) {
    const user = f.principal.user_id;
    if (!user || user === "unknown") continue;
    const p = by.get(user) ?? { user_id: user, devices: [], findings: [] };
    if (!p.devices.includes(f.endpoint.device_id)) p.devices.push(f.endpoint.device_id);
    p.findings.push(f);
    by.set(user, p);
  }
  return [...by.values()];
}

// Security approval queue (M11): a held tool call waits for security; nobody decides in time → denied.
export const SECURITY_STATUS_LABEL: Record<string, string> = {
  pending: "결정 대기",
  approved: "승인",
  denied: "거부",
  expired: "시간 초과",
};

export const SECURITY_OUTCOME_LABEL: Record<string, string> = {
  allowed: "실행됨",
  denied: "막힘(거부)",
  timeout: "막힘(시간 초과)",
  cancelled: "취소됨(실행 중단)",
  unreachable: "막힘(관제 서버 연결 실패)",
};

/** Time left to decide, as "4:59"; "0:00" once it is over. */
export function remainingText(expiresAt: string, now: Date = new Date()): string {
  const left = Math.max(0, Math.floor((new Date(expiresAt).getTime() - now.getTime()) / 1000));
  return `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
}
