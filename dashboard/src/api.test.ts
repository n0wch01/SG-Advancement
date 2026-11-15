import { afterEach, describe, expect, it, vi } from "vitest";

import { Api } from "./api";

describe("dashboard requests", () => {
  afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

  it("sends the period and stable cursor to the server", async () => {
    const fetch = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response("[]", { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetch);
    const api = new Api("test-only-token");
    await api.findings({ since: "2026-11-08T00:00:00Z", min_severity: "high", before: "2026-11-14T00:00:00Z", before_id: "f1", limit: 50 });
    const url = new URL(fetch.mock.calls[0][0] as string, "http://localhost");
    expect(Object.fromEntries(url.searchParams)).toEqual({ since: "2026-11-08T00:00:00Z", min_severity: "high", before: "2026-11-14T00:00:00Z", before_id: "f1", limit: "50" });
    expect(url.search).not.toContain("token");
  });

  it("times out a stalled read so a polling task can retry", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("fetch", vi.fn((_url: string, init: RequestInit) => new Promise((_resolve, reject) => {
      init.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
    })));
    const failure = expect(new Api("test-only-token").findings({})).rejects.toThrow("10초");
    await vi.advanceTimersByTimeAsync(10_000);
    await failure;
  });
});
