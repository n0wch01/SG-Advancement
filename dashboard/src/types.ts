// The slice of the SG-Advance wire schema (schemas/*.v1.json) the dashboard reads.

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Role = "admin" | "viewer" | "member";

export interface Identity {
  role: Role;
  user_id: string;
  display_name: string;
  permissions: string[];
  projects: string[];
  bindings: { role_id: string; project_id: string | null; environment: string; permissions: string[] }[];
}

export interface Project {
  project_id: string;
  name: string;
  environments: string[];
  disabled_at: string | null;
}

export interface SessionBinding {
  binding_id: string;
  device_id: string;
  agent_type: string;
  session_id: string;
  project_id: string;
  user_id: string;
  revoked_at: string | null;
}

export interface TaskClaims {
  grant_id: string; user_id: string; device_id: string; binding_id: string;
  agent_type: string; session_id: string; project_id: string; environment: string; agent_profile: string;
  actions: string[]; paths: string[]; issued_at: string; expires_at: string; policy_version: string;
  parent_id: string | null;
}

export interface TaskGrant {
  grant_id: string; claims: TaskClaims; revoked_at: string | null;
}

export interface IdentityAdministration {
  users: { user_id: string; display_name: string; disabled_at: string | null }[];
  teams: { team_id: string; name: string }[];
  memberships: { user_id: string; team_id: string }[];
  roles: { role_id: string; permissions: string[] }[];
  bindings: { binding_id: string; user_id: string | null; team_id: string | null; role_id: string; project_id: string | null; environment: string }[];
  tokens: { token_id: string; user_id: string; expires_at: string; revoked_at: string | null }[];
  devices: { device_id: string; owner_user_id: string | null }[];
  permissions: string[];
}

export interface Endpoint {
  device_id: string;
  hostname?: string | null;
}

export interface Principal {
  user_id: string;
}

export interface AgentRef {
  type: string;
  session_id: string;
  parent_session_id?: string | null;
  root_session_id?: string | null;
  spawn_depth?: number | null;
  agent_id?: string | null;  // which configured agent: Claude Code main/subagent, OpenClaw agent (2026-11-16)
}

export interface Enforcement {
  action: string;
  enforced: boolean;
  enforcer?: string | null;
  detail?: string | null;
  // Outcome model (2026-11-13): decision stage and whether the side effect is known not to have happened.
  stage?: string | null;
  confirmation?: "not_applicable" | "unconfirmed" | "confirmed" | "contradicted" | "failed" | null;
  evidence?: string | null;
  decision?: "allow" | "deny" | "approve" | "mask" | null;  // the four decisions (2026-11-16)
}

export interface Finding {
  finding_id: string;
  ts: string;
  received_ts?: string | null;
  rule_id: string;
  rule_version?: string;
  severity: Severity;
  category: string;
  title: string;
  message: string;
  recommended_action: string;
  explanation?: string | null;
  evidence_event_ids: string[];
  endpoint: Endpoint;
  principal: Principal;
  agent: AgentRef;
  response?: Enforcement | null;
  tags: string[];
  labels: Record<string, string>;
  detector?: "local" | "central";
}

export interface AgentEvent {
  event_id: string;
  ts: string;
  endpoint: Endpoint;
  principal: Principal;
  agent: AgentRef;
  source: { sensor: string };
  payload: { kind: string } & Record<string, unknown>;
  labels: Record<string, string>;
}

export interface RuleCount {
  rule_id: string;
  title: string;
  severity: Severity;
  count: number;
  last_ts: string;
}

export interface UserCount {
  user_id: string;
  count: number;
  max_severity: Severity;
  last_ts: string;
}

// GET /v1/admin/risk: people with high/critical action findings in the last 24 h (KISA P1-4).
// score 0..100 ranks them; elevated is what access decisions use (unchanged thresholds).
export interface PersonRisk {
  user_id: string;
  critical: number;
  high: number;
  elevated: boolean;
  score: number;
  last_ts: string | null;
}

export interface Summary {
  since: string | null;
  generated_at: string;
  findings: {
    total: number;
    by_severity: Record<Severity, number>;
    by_category: Record<string, number>;
    top_rules: RuleCount[];
    top_users: UserCount[];
  };
  events: { total: number; by_kind: Record<string, number> };
  devices: { total: number; active: number; policy_current: number };
  recent: Finding[];
}

export interface FindingDetail {
  finding: Finding;
  evidence: AgentEvent[];
  session_events: AgentEvent[];
  session_findings: Finding[];
  campaign_members?: Finding[];
  campaigns?: Finding[];
  disposition?: Disposition | null;
}

// A reviewer's verdict on a finding (2026-11-18): a false positive stops counting toward the person's risk.
export interface Disposition {
  status: "false_positive";
  decided_by: string;
  reason: string;
  decided_at: string;
}

export interface FindingRef {
  finding_id: string;
  rule_id: string;
  severity: Severity;
  title: string;
}

export interface Approval {
  event_id: string;
  ts: string;
  device_id: string;
  user_id: string;
  session_id: string;
  call_id: string;
  tool: string;
  decision: string;
  approved: boolean;
  judged_by: string;
  rule_ids: string[];
  max_severity: Severity | null;
  wait_ms: number | null;
  requester: Record<string, string>;
  approver: string | null;
  approver_source: "audit_proxy" | "agent" | null;
  held_call: { event_id: string; ts: string; tool: string; arguments: Record<string, unknown> } | null;
  asked_by: FindingRef[];
  flagged: FindingRef[];
  needs_review?: boolean;
  review?: ApprovalReview | null;
}

export interface ApprovalReview {
  status: "ok" | "problem";
  by: string;
  reason: string;
  at: string;
}

export interface Snapshot {
  ts: string;
  user_id: string;
  session_id: string;
  payload: Record<string, unknown>;
}

export interface DeviceInventory {
  device_id: string;
  hostname: string | null;
  sensor_version: string | null;
  enrolled_at: string;
  last_seen: string | null;
  policy_current: boolean;
  installs: Snapshot[];
  agents: Snapshot[];
  configs: Snapshot[];
  integrity: Snapshot[];
  open_findings: Partial<Record<Severity, number>>;
}

export interface SessionNode {
  session_id: string;
  device_ids: string[];
  agent_type: string;
  parent_session_id: string | null;
  root_session_id: string | null;
  spawn_depth: number | null;
  user_ids: string[];
  first_ts: string;
  last_ts: string;
  events: number;
  findings: number;
  max_severity: Severity | null;
}

export interface Timeline {
  user_id: string | null;
  session_id: string | null;
  truncated: boolean;
  sessions: SessionNode[];
  events: AgentEvent[];
  findings: Finding[];
}

export interface PolicyScope {
  name: string;
  description: string | null;
  devices: number;
  version: string;
  overrides: number;
}

export interface RuleLayer {
  enabled: boolean;
  response: string;
  allow: string[] | null;
}

export interface PolicyRule {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  match_type: string;
  base: RuleLayer;
  common_override: Partial<RuleLayer> | null;
  group_override: Partial<RuleLayer> | null;
  effective: RuleLayer;
}

export interface PolicyChange {
  id: number;
  ts: string;
  actor: string;
  role: string;
  action: string;
  scope: string | null;
  rule_id: string | null;
  target: string | null;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  reason: string;
}

export interface Device {
  device_id: string;
  hostname: string | null;
  last_seen: string | null;
  policy_current: boolean;
  group: string | null;
}

export interface RemoteAction {
  id: string;
  device_id: string;
  action: string;
  target: string;
  finding_id: string | null;
  status: "pending" | "delivered" | "done" | "failed";
  created_at: string;
  created_by: string;
  reason: string;
  delivered_at: string | null;
  result_at: string | null;
  result_detail: string | null;
}

// Approval-fatigue metrics (2026-11-13, KISA ZT guide C2; 금융보안원 ⑭).
export interface ChannelStats {
  requests: number;
  approved: number;
  denied: number;
  unanswered: number;
  rejection_rate: number | null;
  median_wait_s: number | null;
  p90_wait_s: number | null;
  fast_approvals: number;
  fast_approval_rate: number | null;
}

export interface ApprovalMetrics {
  window_days: number;
  since: string;
  user: ChannelStats;
  repeated: { channel: string; tool: string; rule_ids: string[]; requests: number; approval_rate: number; people: number; automation_candidate: boolean }[];
  people: { user_id: string; requests: number; busiest_day: number; fast_approval_rate: number | null }[];
}
