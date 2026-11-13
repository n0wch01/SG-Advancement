// The slice of the SG-Advance wire schema (schemas/*.v1.json) the dashboard reads.

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Role = "admin" | "viewer";

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
}

export interface Enforcement {
  action: string;
  enforced: boolean;
  enforcer?: string | null;
  detail?: string | null;
}

export interface Finding {
  finding_id: string;
  ts: string;
  received_ts?: string | null;
  rule_id: string;
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

export interface SecurityApproval {
  id: string;
  device_id: string;
  status: "pending" | "approved" | "denied" | "expired";
  created_at: string;
  expires_at: string;
  user_id: string;
  session_id: string;
  tool: string;
  arguments_preview: string;
  reason: string;
  rule_ids: string[];
  severity: Severity | null;
  event_id: string | null;
  finding_ids: string[];
  decided_at: string | null;
  decided_by: string | null;
  decision_reason: string | null;
  delivered_at: string | null;
  outcome: string | null;
  outcome_at: string | null;
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
