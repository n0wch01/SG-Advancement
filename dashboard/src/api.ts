// Control plane client. Same origin: production serves the dashboard from the control plane,
// development proxies /v1 through Vite. The token lives in sessionStorage only (gone when the tab
// closes) and is sent as a bearer header, never in a URL.

import type { Approval, DeviceInventory, Finding, FindingDetail, Role, Summary, Timeline } from "./types";

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

  private async get<T>(path: string, q: Query = {}): Promise<T> {
    const res = await fetch(`/v1/admin${path}${queryString(q)}`, {
      headers: { Authorization: `Bearer ${this.token}` },
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

  approvals(q: { approved?: string; decision?: string; user_id?: string; since?: string | null; limit?: number; offset?: number }) {
    return this.get<Approval[]>("/approvals", q);
  }

  timeline(q: { user_id?: string; session_id?: string; since?: string | null }) {
    return this.get<Timeline>("/timeline", q);
  }

  inventory() {
    return this.get<DeviceInventory[]>("/inventory");
  }

  finding(id: string) {
    return this.get<FindingDetail>(`/findings/${encodeURIComponent(id)}`);
  }
}
