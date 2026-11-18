// Control plane client. Same origin: production serves the dashboard from the control plane,
// development proxies /v1 through Vite. The token lives in sessionStorage only (gone when the tab
// closes) and is sent as a bearer header, never in a URL.

import type {
  AgentEvent,
  Approval,
  ApprovalMetrics,
  ApprovalReview,
  Device,
  DeviceInventory,
  Finding,
  FindingDetail,
  Identity,
  IdentityAdministration,
  PersonRisk,
  PolicyChange,
  PolicyRule,
  PolicyScope,
  Project,
  RemoteAction,
  SessionBinding,
  Summary,
  Timeline,
  TaskGrant,
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
    const controller = method === "GET" ? new AbortController() : undefined;
    const timer = controller ? setTimeout(() => controller.abort(), 10_000) : undefined;
    try {
      const res = await fetch(`/v1/admin${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${this.token}`,
          ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        credentials: "omit",
        signal: controller?.signal,
      });
      if (!res.ok) {
        if (res.status === 401 && typeof window !== "undefined") window.dispatchEvent(new Event("sga-unauthorized"));
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
    } catch (error) {
      if (controller?.signal.aborted) throw new Error("관제 서버 응답이 10초 안에 도착하지 않았습니다.");
      throw error;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  whoami() {
    return this.get<Identity>("/whoami");
  }

  identityAdministration() { return this.get<IdentityAdministration>("/rbac"); }
  projects() { return this.get<Project[]>("/rbac/projects"); }
  sessions() { return this.get<SessionBinding[]>("/rbac/sessions"); }
  ownedDevices() { return this.get<{ device_id: string }[]>("/rbac/owned-devices"); }
  tasks() { return this.get<TaskGrant[]>("/tasks"); }
  issueTask(body: { binding_id: string; environment: string; agent_profile: string; actions: string[]; paths: string[]; lifetime_seconds: number }) {
    return this.call<TaskGrant & { token: string }>("POST", "/tasks", body);
  }
  revokeTask(id: string) { return this.call<{ revoked: boolean }>("DELETE", `/tasks/${encodeURIComponent(id)}`); }
  identityWrite<T = unknown>(method: "POST" | "PUT" | "DELETE", path: string, body?: unknown) {
    return this.call<T>(method, `/rbac${path}`, body);
  }

  summary(since: string | null) {
    return this.get<Summary>("/summary", { since });
  }

  findings(q: { severity?: string; min_severity?: string; rule_id?: string; user_id?: string; since?: string; before?: string; before_id?: string; queue?: string; limit?: number; offset?: number }) {
    return this.get<Finding[]>("/findings", q);
  }

  /** Recorded events, newest first. ``judge``: the injection classifier's verdict (sampling its misses). */
  events(q: { judge?: string; kind?: string; since?: string | null; limit?: number }) {
    return this.get<AgentEvent[]>("/events", q);
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

  // Permissions and target scope are verified again by the server for every write.
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

  inventory() {
    return this.get<DeviceInventory[]>("/inventory");
  }

  finding(id: string) {
    return this.get<FindingDetail>(`/findings/${encodeURIComponent(id)}`);
  }
}
