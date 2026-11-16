import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { Api } from "./api";
import { FindingFeed } from "./findingFeed";
import type { Finding } from "./types";

const baseTime = new Date("2026-11-15T00:00:00Z").getTime();
function finding(index: number, ts = new Date(baseTime + index * 1000).toISOString()): Finding {
  return {
    finding_id: `f-${String(index).padStart(4, "0")}`, ts, rule_id: "test-rule", severity: "high", category: "tool_misuse",
    title: "Test finding", message: "", recommended_action: "", evidence_event_ids: [],
    endpoint: { device_id: "d1" }, principal: { user_id: "alice" }, agent: { type: "claude_code", session_id: "s1" }, tags: [], labels: {},
  };
}
const ids = (rows: Finding[]) => rows.map((row) => row.finding_id);
const settle = () => vi.advanceTimersByTimeAsync(0);

function repository(rows: Finding[]) {
  const load = vi.fn(async (request: Parameters<Api["findings"]>[0]) => rows
    .filter((row) => !request.since || new Date(row.ts).getTime() >= new Date(request.since).getTime())
    .filter((row) => !request.before || new Date(row.ts).getTime() < new Date(request.before).getTime()
      || (row.ts === request.before && row.finding_id > request.before_id!))
    .sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime() || a.finding_id.localeCompare(b.finding_id))
    .slice(0, request.limit));
  return { rows, load };
}

describe("finding reader", () => {
  beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date("2026-11-15T12:00:00Z")); });
  afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); });

  it("queues and deduplicates new findings without moving the displayed rows", async () => {
    const repo = repository([finding(1), finding(2)]);
    const feed = new FindingFeed(repo.load, {});
    feed.start(3000);
    await settle();
    repo.rows.push(finding(3));
    await feed.poll();
    await feed.poll();
    expect(ids(feed.getSnapshot().rows)).toEqual(["f-0002", "f-0001"]);
    expect(ids(feed.getSnapshot().pending)).toEqual(["f-0003"]);
    feed.applyPending();
    expect(ids(feed.getSnapshot().rows)).toEqual(["f-0003", "f-0002", "f-0001"]);
    expect(feed.getSnapshot().pending).toEqual([]);
    feed.stop();
  });

  it("preserves loaded pages and equal timestamps while new rows are waiting", async () => {
    const repo = repository(Array.from({ length: 75 }, (_, index) => finding(index, finding(1).ts)));
    const feed = new FindingFeed(repo.load, {});
    feed.start(3000);
    await settle();
    repo.rows.push(finding(100));
    await feed.poll();
    await feed.loadMore();
    expect(feed.getSnapshot().rows).toHaveLength(75);
    expect(feed.getSnapshot().pending).toHaveLength(1);
    expect(repo.load.mock.calls.at(-1)![0]).toMatchObject({ before: finding(1).ts, before_id: "f-0049" });
    feed.applyPending();
    expect(new Set(ids(feed.getSnapshot().rows)).size).toBe(76);
    expect(feed.getSnapshot().more).toBe(false);
    feed.stop();
  });

  it("catches up a burst larger than a page without losing the gap or older pages", async () => {
    const repo = repository(Array.from({ length: 60 }, (_, index) => finding(index)));
    const feed = new FindingFeed(repo.load, {});
    feed.start(3000);
    await settle();
    repo.rows.push(...Array.from({ length: 80 }, (_, index) => finding(index + 60)));
    await feed.poll();
    expect(feed.getSnapshot().rows).toHaveLength(50);
    expect(feed.getSnapshot().pending).toHaveLength(80);
    feed.applyPending();
    await feed.loadMore();
    expect(feed.getSnapshot().rows).toHaveLength(140);
    expect(new Set(ids(feed.getSnapshot().rows)).size).toBe(140);
    feed.stop();
  });

  it("keeps the last successful rows and timestamp through failure, then clears the error on recovery", async () => {
    const repo = repository([finding(1)]);
    const feed = new FindingFeed(repo.load, {});
    feed.start(3000);
    await settle();
    const successful = feed.getSnapshot().updatedAt;
    repo.load.mockRejectedValueOnce(new Error("offline"));
    await feed.poll();
    expect(feed.getSnapshot()).toMatchObject({ rows: [finding(1)], updatedAt: successful, error: new Error("offline") });
    await vi.advanceTimersByTimeAsync(1000);
    await feed.refresh();
    expect(feed.getSnapshot().error).toBeNull();
    expect(feed.getSnapshot().updatedAt).not.toBe(successful);
    feed.stop();
  });

  it("allows manual refresh while paused and catches up immediately on resume", async () => {
    const repo = repository([finding(1)]);
    const feed = new FindingFeed(repo.load, {});
    feed.start(3000);
    await settle();
    feed.togglePause();
    repo.rows.push(finding(2));
    await vi.advanceTimersByTimeAsync(9000);
    expect(repo.load).toHaveBeenCalledTimes(1);
    await feed.refresh();
    expect(feed.getSnapshot().pending).toHaveLength(1);
    repo.rows.push(finding(3));
    feed.togglePause();
    await settle();
    expect(feed.getSnapshot().pending).toHaveLength(2);
    feed.stop();
  });

  it("restores pages, pause state, and scroll position after visiting a detail", async () => {
    const repo = repository(Array.from({ length: 75 }, (_, index) => finding(index)));
    const feed = new FindingFeed(repo.load, {});
    feed.start(3000);
    await settle();
    await feed.loadMore();
    feed.scrollY = 950;
    feed.togglePause();
    feed.stop();
    repo.rows.push(finding(100));
    feed.start(3000);
    await settle();
    expect(feed.getSnapshot()).toMatchObject({ paused: true, pending: [] });
    expect(feed.getSnapshot().rows).toHaveLength(75);
    expect(feed.scrollY).toBe(950);
    feed.togglePause();
    await settle();
    expect(feed.getSnapshot().pending).toHaveLength(1);
    expect(feed.getSnapshot().rows).toHaveLength(75);
    feed.stop();
  });

  it("sends the original period on every request and never sends UI-only context", async () => {
    const repo = repository(Array.from({ length: 75 }, (_, index) => finding(index)));
    const since = "2026-11-14T00:00:00Z";
    const feed = new FindingFeed(repo.load, { range: "7d", since, min_severity: "high", user_id: "alice" });
    feed.start(3000);
    await settle();
    await feed.poll();
    await feed.loadMore();
    for (const [request] of repo.load.mock.calls) {
      expect(request).toMatchObject({ since, min_severity: "high", user_id: "alice" });
      expect(request).not.toHaveProperty("range");
    }
    feed.stop();
  });

  it("does not publish a response after leaving the list or overlap paging and polling", async () => {
    const repo = repository(Array.from({ length: 75 }, (_, index) => finding(index)));
    const feed = new FindingFeed(repo.load, {});
    feed.start(3000);
    await settle();
    let resolve!: (rows: Finding[]) => void;
    repo.load.mockImplementationOnce(() => new Promise<Finding[]>((done) => { resolve = done; }));
    const more = feed.loadMore();
    await feed.refresh();
    await feed.poll();
    expect(repo.load).toHaveBeenCalledTimes(2);
    feed.stop();
    resolve([finding(0)]);
    await more;
    expect(feed.getSnapshot().rows).toHaveLength(50);
    expect(feed.getSnapshot().loadingMore).toBe(false);
  });

  it("does not poll hidden tabs", async () => {
    const repo = repository([finding(1)]);
    let visible = true;
    const feed = new FindingFeed(repo.load, {}, () => visible);
    feed.start(3000);
    await settle();
    visible = false;
    await vi.advanceTimersByTimeAsync(6000);
    expect(repo.load).toHaveBeenCalledTimes(1);
    visible = true;
    await feed.poll();
    expect(repo.load).toHaveBeenCalledTimes(2);
    feed.stop();
  });

  it("keeps the current page and reports a server that ignores pagination", async () => {
    const firstPage = Array.from({ length: 50 }, (_, index) => finding(100 - index));
    const load = vi.fn(async () => firstPage);
    const feed = new FindingFeed(load, {});
    feed.start(3000);
    await settle();
    await feed.loadMore();
    expect(feed.getSnapshot().rows).toHaveLength(50);
    expect(feed.getSnapshot().error?.message).toContain("페이지 조회 기준");
    feed.stop();
  });

  it("asks for the review queue unless another queue (or all) is chosen", async () => {
    for (const [filters, queue] of [[{}, "review"], [{ queue: "benign" }, "benign"], [{ queue: "all" }, undefined]] as const) {
      const repo = repository([finding(1)]);
      const feed = new FindingFeed(repo.load, filters as Record<string, string>);
      feed.start(3000);
      await settle();
      expect(repo.load.mock.calls[0][0].queue).toBe(queue);
      feed.stop();
    }
  });
});
