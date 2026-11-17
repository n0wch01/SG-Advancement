// Pure helpers: labels, time, event one-liners, hash routes. Kept free of React for unit tests.

import type { AgentEvent, Approval, Finding, Severity } from "./types";

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

// Four decisions people read (2026-11-16, user decision): allow, deny, approve, mask. The seven actions
// stay as how it is done, shown after the decision: who approves, what is stopped.
export const VERDICT_LABEL: Record<string, string> = { allow: "허용", deny: "거부", approve: "승인", mask: "가림" };
const DECISION_OF_STAGE: Record<string, string> = {
  detected: "allow", approval_requested: "approve", held: "approve", blocked: "deny",
  result_withheld: "mask", session_aborted: "deny", quarantined: "deny",
};
const HOW_OF_STAGE: Record<string, string> = {
  approval_requested: "사용자", held: "보안팀", session_aborted: "대화 중단", quarantined: "격리",
};

export const ACTION_LABEL: Record<string, string> = {
  allow: "허용",
  alert: "허용 · 경보",
  require_approval: "승인 · 사용자",
  block: "거부",
  abort_session: "거부 · 대화 중단",
  quarantine: "거부 · 격리",
};

export const STAGE_LABEL: Record<string, string> = {
  detected: "탐지",
  approval_requested: "승인 요청",
  held: "실행 보류",
  blocked: "차단",
  result_withheld: "결과 가림",
  session_aborted: "세션 중단",
  quarantined: "격리",
};

export const CONFIRMATION_LABEL: Record<string, string> = {
  confirmed: "실제 적용 확인",
  unconfirmed: "적용 미확인",
  contradicted: "적용 안 됨(실행됨)",
  failed: "적용 실패",
};

// Decision stage and whether it was really applied are shown separately (CLAUDE.md, 2026-11-13).
// Records from before the outcome model have no stage: shown the old way.
export function responseText(
  r: { action: string; enforced: boolean; stage?: string | null; confirmation?: string | null; decision?: string | null } | null | undefined,
): string {
  if (!r) return ACTION_LABEL.alert;
  if (r.stage) {
    const decision = VERDICT_LABEL[r.decision ?? DECISION_OF_STAGE[r.stage] ?? ""] ?? r.stage;
    const how = r.stage === "detected" ? (r.action === "alert" ? "경보" : undefined) : HOW_OF_STAGE[r.stage];
    const conf = r.confirmation ? CONFIRMATION_LABEL[r.confirmation] : undefined;
    return [decision, how, conf].filter(Boolean).join(" · ");
  }
  const label = ACTION_LABEL[r.action] ?? r.action;
  if (r.action === "alert" || r.action === "allow") return label;
  return r.enforced ? `${label} (집행됨)` : `${label} (집행 안 됨)`;
}

/** The agent as people name it: product and configured agent ("claude_code · fixer"). */
export function agentName(a: { type: string; agent_id?: string | null }): string {
  return a.agent_id ? `${a.type} · ${a.agent_id}` : a.type;
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
  | { page: "overview"; query?: Record<string, string> }
  | { page: "findings"; query: Record<string, string> }
  | { page: "finding"; id: string; query?: Record<string, string> }
  | { page: "approvals"; query: Record<string, string> }
  | { page: "inventory" }
  | { page: "timeline"; query: Record<string, string> }
  | { page: "policy"; query: Record<string, string> }
  | { page: "actions" };

export function parseHash(hash: string): Route {
  const [path, qs = ""] = hash.replace(/^#/, "").split("?", 2);
  const parts = path.split("/").filter(Boolean);
  const query = Object.fromEntries(new URLSearchParams(qs));
  const context = qs ? { query } : {};
  if (parts[0] === "findings" && parts[1]) return { page: "finding", id: decodeURIComponent(parts[1]), ...context };
  if (parts[0] === "findings") return { page: "findings", query: Object.fromEntries(new URLSearchParams(qs)) };
  if (parts[0] === "inventory") return { page: "inventory" };
  if (parts[0] === "actions") return { page: "actions" };
  if (parts[0] === "policy") return { page: "policy", query: Object.fromEntries(new URLSearchParams(qs)) };
  if (parts[0] === "timeline") return { page: "timeline", query: Object.fromEntries(new URLSearchParams(qs)) };
  if (parts[0] === "approvals") return { page: "approvals", query: Object.fromEntries(new URLSearchParams(qs)) };
  return { page: "overview", ...context };
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

export const TIME_RANGES = [["24h", "24시간"], ["7d", "7일"], ["30d", "30일"], ["all", "전체"]] as const;
export type TimeRange = typeof TIME_RANGES[number][0];
export const FINDING_FILTERS = ["range", "since", "severity", "min_severity", "rule_id", "user_id", "queue"] as const;

// The console's queues over the injection classifier's work (docs/classifier.md 5, 2026-11-16). "review" is
// the default: everything except findings the classifier judged benign that were not enforced.
export const QUEUES = [
  ["review", "확인 필요"],
  ["enforced", "집행됨"],
  ["benign", "분류기가 정상으로 본 것"],
  ["failed", "분류 실패"],
  ["all", "전체"],
] as const;
export type Queue = typeof QUEUES[number][0];

export function findingQueue(query: Record<string, string | undefined>): Queue {
  return QUEUES.some(([key]) => key === query.queue) ? query.queue as Queue : "review";
}

const JUDGE_LABEL: Record<string, [string, "bad" | "warn" | "neutral"]> = {
  malicious: ["인젝션", "bad"],
  unsure: ["불확실", "warn"],
  benign: ["정상", "neutral"],
  unavailable: ["판정 실패", "warn"],
};

/** The classifier's verdict as a word and a tone (labels.sga_judge_*), or null when it did not judge. */
export function judgeText(labels: Record<string, string> | undefined): { text: string; tone: string } | null {
  const verdict = labels?.sga_judge_injection;
  if (!verdict) return null;
  const [word, tone] = JUDGE_LABEL[verdict] ?? [verdict, "neutral"];
  const score = labels?.sga_judge_score ? ` ${Number(labels.sga_judge_score).toFixed(2)}` : "";
  return { text: `분류기: ${word}${score}`, tone };
}

export function timeRange(value: string | undefined, fallback: TimeRange = "all"): TimeRange {
  return TIME_RANGES.some(([key]) => key === value) ? value as TimeRange : fallback;
}

export function rangeQuery(range: TimeRange, since: string | null = sinceFor(range)): Record<string, string> {
  return since && range !== "all" ? { range, since } : { range };
}

/** Keep route context out of API requests and use a stable key for cached lists. */
export function findingFilters(query: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(FINDING_FILTERS.filter((key) => query[key]).map((key) => [key, query[key]!]));
}

export function overviewHref(query: Record<string, string | undefined> = {}): string {
  return href("", query);
}

export function findingHref(id: string, query: Record<string, string | undefined> = {}): string {
  return href(`findings/${encodeURIComponent(id)}`, query);
}

export function findingBackHref(query: Record<string, string>): string {
  return query.from === "overview" ? overviewHref({ range: query.range }) : findingsHref(findingFilters(query));
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

// The security pre-approval hold was removed 2026-11-17: not offered as a response any more.
export const RESPONSES = ["allow", "alert", "require_approval", "block", "abort_session", "quarantine"];

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

// Phase 2 (docs/lineage.md): a transfer block read as one flow — the read the data came from, the
// call that tried to send it, the rule that decided, and what actually happened.
export const LINEAGE_SINK = "lineage:sink";

export interface FlowStep {
  key: "source" | "transfer" | "policy" | "result";
  title: string;
  lines: string[];
  eventId?: string;
}

export function lineageFlow(
  f: Pick<Finding, "tags" | "labels" | "rule_id" | "rule_version" | "explanation" | "response" | "evidence_event_ids">,
  evidence: AgentEvent[],
): FlowStep[] | null {
  if (!f.tags.includes(LINEAGE_SINK)) return null;
  const sources = (f.labels.sga_lineage_sources ?? "").split(",").filter(Boolean);
  const byId = new Map(evidence.map((e) => [e.event_id, e]));
  const steps: FlowStep[] = [];
  for (const id of sources) {
    const e = byId.get(id);
    const provider = (e?.payload.provider ?? {}) as { mcp_server?: string };
    steps.push({
      key: "source",
      title: "1. 보호 데이터 조회 (출처)",
      eventId: id,
      lines: e
        ? [
            `${formatTime(e.ts)} · ${String(e.payload.tool ?? "?")}${provider.mcp_server ? ` (MCP ${provider.mcp_server})` : ""}`,
            `보호 컬럼: ${f.labels.sga_lineage_fields || "?"}`,
          ]
        : [`출처 이벤트 ${id.slice(0, 8)}… (관제 서버에 아직 없음)`],
    });
  }
  if (f.labels.sga_lineage === "unavailable") {
    steps.push({ key: "source", title: "1. 출처 기록 없음", lines: ["센서의 출처 기록을 읽을 수 없어 보호 데이터 여부를 모름 (차단 쪽으로 처리)"] });
  }
  const call = evidence.find((e) => !sources.includes(e.event_id) && e.payload.kind === "tool.call");
  steps.push({
    key: "transfer",
    title: "2. 전송 시도",
    eventId: call?.event_id,
    lines: [
      call ? `${formatTime(call.ts)} · ${String(call.payload.tool ?? "?")}` : "호출 이벤트 없음",
      `목적지: ${f.labels.sga_destinations || "?"}`,
      ...(f.labels.sga_lineage_via ? [`연결 근거: ${f.labels.sga_lineage_via === "value" ? "인자에 같은 값" : f.labels.sga_lineage_via.replace(/^file:/, "그 값을 쓴 파일 ")}`] : []),
    ],
  });
  steps.push({ key: "policy", title: "3. 적용 정책", lines: [`${f.rule_id}${f.rule_version ? ` v${f.rule_version}` : ""} (서명된 정책)`, ...(f.explanation ? [f.explanation] : [])] });
  steps.push({
    key: "result",
    title: "4. 실제 결과",
    lines: [responseText(f.response), ...(f.response?.evidence ? [`근거: ${f.response.evidence}`] : [])],
  });
  return steps;
}

// Security's after-the-fact review of a person's own approval (decision 2026-11-14).
export const REVIEW_LABEL: Record<string, string> = { ok: "확인함", problem: "문제 있음" };

export function reviewText(a: Pick<Approval, "needs_review" | "review">): { label: string; tone: "ok" | "bad" | "wait" | "none" } {
  if (a.review) return { label: `${REVIEW_LABEL[a.review.status] ?? a.review.status} · ${a.review.by}`, tone: a.review.status === "ok" ? "ok" : "bad" };
  if (a.needs_review) return { label: "검토 대기", tone: "wait" };
  return { label: "-", tone: "none" };
}

// Risk score bands for display (server: critical 60, high 20, × recency, capped at 100).
// The band is wording only; access decisions follow `elevated`.
export function riskBand(score: number): { label: string; fill: "high" | "medium" | "low" } {
  if (score >= 60) return { label: "높음", fill: "high" };
  if (score >= 20) return { label: "주의", fill: "medium" };
  return { label: "낮음", fill: "low" };
}

/** Live Finding list: findings newer than what is shown go on top; rows already shown stay as they are
 * (a reader who loaded more pages keeps their place). */
export function mergeNewest<T extends { finding_id: string }>(shown: T[], latest: T[]): T[] {
  const seen = new Set(shown.map((f) => f.finding_id));
  const fresh = latest.filter((f) => !seen.has(f.finding_id));
  return fresh.length ? [...fresh, ...shown] : shown;
}
