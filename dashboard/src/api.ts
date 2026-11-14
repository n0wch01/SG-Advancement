// Control plane client. Same origin: production serves the dashboard from the control plane,
// development proxies /v1 through Vite. The token lives in sessionStorage only (gone when the tab
// closes) and is sent as a bearer header, never in a URL.

import type {
  Approval,
  ApprovalMetrics,
  ApprovalReview,
  Device,
  DeviceInventory,
  Finding,
  FindingDetail,
  PersonRisk,
  PolicyChange,
  PolicyRule,
  PolicyScope,
  RemoteAction,
  Role,
  SecurityApproval,
  Summary,
  Timeline,
} from "./types";

const KEY = "sga-dashboard-token";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export function loadToken(): string | null {
  try {
    return sessionStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export function saveToken(token: string | null): void {
  try {
    if (token) sessionStorage.setItem(KEY, token);
    else sessionStorage.removeItem(KEY);
  } catch {
    // private mode or blocked storage: the session simply won't survive a reload
  }
}

type Query = Record<string, string | number | undefined | null>;

export function queryString(q: Query): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : "";
}

export class Api {
  constructor(private readonly token: string) {}

  private get<T>(path: string, q: Query = {}): Promise<T> {
    return this.call<T>("GET", path + queryString(q));
  }

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(`/v1/admin${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      credentials: "omit",
    });
    if (!res.ok) {
      let detail = res.statusText;
      try {
        const body = await res.json();
        if (typeof body?.detail === "string") detail = body.detail;
      } catch {
        // not JSON
      }
      throw new ApiError(res.status, detail);
    }
    return (await res.json()) as T;
  }

  whoami() {
    return this.get<{ role: Role }>("/whoami");
  }

  summary(since: string | null) {
    return this.get<Summary>("/summary", { since });
  }

  findings(q: { severity?: string; min_severity?: string; rule_id?: string; user_id?: string; limit?: number; offset?: number }) {
    return this.get<Finding[]>("/findings", q);
  }

  approvals(q: { approved?: string; decision?: string; user_id?: string; review?: string; since?: string | null; limit?: number; offset?: number }) {
    return this.get<Approval[]>("/approvals", q);
  }

  risk() {
    return this.get<PersonRisk[]>("/risk");
  }

  reviewCount() {
    return this.get<{ pending: number }>("/approvals/review-count");
  }

  reviewApproval(eventId: string, body: { status: "ok" | "problem"; by: string; reason: string }) {
    return this.call<ApprovalReview>("POST", `/approvals/${encodeURIComponent(eventId)}/review`, body);
  }

  approvalMetrics(days: number) {
    return this.get<ApprovalMetrics>("/approvals/metrics", { days });
  }

  timeline(q: { user_id?: string; session_id?: string; since?: string | null }) {
    return this.get<Timeline>("/timeline", q);
  }

  policyScopes() {
    return this.get<{ revision: number; scopes: PolicyScope[] }>("/policy/scopes");
  }

  policyRules(scope: string) {
    return this.get<PolicyRule[]>("/policy/rules", { scope });
  }

  policyChanges(scope?: string) {
    return this.get<PolicyChange[]>("/policy/changes", { scope, limit: 50 });
  }

  devices() {
    return this.get<Device[]>("/devices");
  }

  // Writes: the server accepts them from the admin token only (the dashboard token is GET-only).
  setOverride(body: { scope: string; rule_id: string; enabled?: boolean; response?: string; allow?: string[]; by: string; reason: string }) {
    return this.call<{ revision: number }>("PUT", "/policy/overrides", body);
  }

  clearOverride(body: { scope: string; rule_id: string; by: string; reason: string }) {
    return this.call<{ revision: number }>("POST", "/policy/overrides/clear", body);
  }

  createGroup(body: { name: string; description?: string; by: string; reason: string }) {
    return this.call<{ revision: number }>("POST", "/policy/groups", body);
  }

  assignDevice(device: string, body: { group: string | null; by: string; reason: string }) {
    return this.call<{ revision: number }>("PUT", `/devices/${encodeURIComponent(device)}/group`, body);
  }

  actions(q: { device_id?: string; target?: string } = {}) {
    return this.get<RemoteAction[]>("/actions", { ...q, limit: 200 });
  }

  createAction(body: { device_id: string; action: string; target: string; finding_id?: string; by: string; reason: string }) {
    return this.call<RemoteAction>("POST", "/actions", body);
  }

  securityApprovals(q: { status?: string } = {}) {
    return this.get<SecurityApproval[]>("/security-approvals", { ...q, limit: 100 });
  }

  decideSecurity(id: string, body: { decision: "approve" | "deny"; by: string; reason: string }) {
    return this.call<SecurityApproval>("POST", `/security-approvals/${encodeURIComponent(id)}/decision`, body);
  }

  inventory() {
    return this.get<DeviceInventory[]>("/inventory");
  }

  finding(id: string) {
    return this.get<FindingDetail>(`/findings/${encodeURIComponent(id)}`);
  }
}
