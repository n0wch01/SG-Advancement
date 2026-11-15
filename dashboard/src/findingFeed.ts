import type { Api } from "./api";
import { sinceFor, timeRange } from "./format";
import { createPoller, type PollReason } from "./polling";
import type { Finding } from "./types";

export const FINDINGS_PAGE_SIZE = 50;
type Request = Parameters<Api["findings"]>[0];
type Load = (query: Request) => Promise<Finding[]>;

export interface FindingFeedState {
  rows: Finding[];
  pending: Finding[];
  loading: boolean;
  loadingMore: boolean;
  refreshing: boolean;
  more: boolean;
  paused: boolean;
  error: Error | null;
  updatedAt: string | null;
}

function combine(shown: Finding[], incoming: Finding[]): Finding[] {
  const byId = new Map(shown.map((finding) => [finding.finding_id, finding]));
  for (const finding of incoming) byId.set(finding.finding_id, finding);
  return [...byId.values()].sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime()
    || (a.finding_id < b.finding_id ? -1 : a.finding_id > b.finding_id ? 1 : 0));
}

function checkOlderPage(page: Finding[], cursor: Finding) {
  const time = new Date(cursor.ts).getTime();
  if (page.some((finding) => new Date(finding.ts).getTime() > time
    || (new Date(finding.ts).getTime() === time && finding.finding_id <= cursor.finding_id))) {
    throw new Error("페이지 조회 기준이 적용되지 않았습니다. 관제 서버 업데이트를 확인하세요.");
  }
}

/** A tab-local list: retain loaded pages and queue new rows until the reader accepts them. */
export class FindingFeed {
  private state: FindingFeedState = {
    rows: [], pending: [], loading: true, loadingMore: false, refreshing: false,
    more: false, paused: false, error: null, updatedAt: null,
  };
  private listeners = new Set<() => void>();
  private task: ReturnType<typeof createPoller<Finding[]>> | null = null;
  private generation = 0;
  private running = false;
  private query: Request;
  scrollY = 0;

  constructor(private load: Load, filters: Record<string, string>, private visible = () => true) {
    const { range, since, ...query } = filters;
    this.query = { ...query, since: since ?? sinceFor(timeRange(range)) ?? undefined };
  }

  getSnapshot = () => this.state;
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };

  private update(patch: Partial<FindingFeedState>) {
    this.state = { ...this.state, ...patch };
    this.listeners.forEach((listener) => listener());
  }

  private async latest(generation: number, reason: PollReason) {
    const initialized = this.state.updatedAt !== null;
    const known = new Set([...this.state.rows, ...this.state.pending].map((finding) => finding.finding_id));
    let page = await this.load({ ...this.query, limit: FINDINGS_PAGE_SIZE });
    let latest = page;
    // Catch up after a long pause or a burst larger than one page, without leaving a gap.
    while (initialized && page.length === FINDINGS_PAGE_SIZE && !page.some((finding) => known.has(finding.finding_id))) {
      if (!this.running || generation !== this.generation || (reason === "auto" && this.state.paused)) break;
      const cursor = page[page.length - 1];
      page = await this.load({ ...this.query, before: cursor.ts, before_id: cursor.finding_id, limit: FINDINGS_PAGE_SIZE });
      checkOlderPage(page, cursor);
      latest = combine(latest, page);
    }
    return latest;
  }

  start(intervalMs: number) {
    if (this.running) return;
    this.running = true;
    const generation = ++this.generation;
    this.task = createPoller({
      load: (reason) => this.latest(generation, reason),
      intervalMs,
      canPoll: () => this.visible() && !this.state.paused && !this.state.loadingMore,
      onStart: () => this.update({ refreshing: true, loading: this.state.updatedAt === null }),
      onSuccess: (latest) => {
        const updatedAt = new Date().toISOString();
        if (this.state.updatedAt === null) {
          this.update({ rows: latest, pending: [], more: latest.length === FINDINGS_PAGE_SIZE, error: null, updatedAt });
          return;
        }
        const shown = new Set(this.state.rows.map((finding) => finding.finding_id));
        this.update({
          rows: combine(this.state.rows, latest.filter((finding) => shown.has(finding.finding_id))),
          pending: combine(this.state.pending, latest.filter((finding) => !shown.has(finding.finding_id))),
          error: null, updatedAt,
        });
      },
      onError: (error) => this.update({ error }),
      onSettled: () => this.update({ loading: false, refreshing: false }),
    });
    void this.task.run(this.state.updatedAt === null ? "initial" : "auto");
  }

  stop() {
    this.running = false;
    this.generation++;
    this.task?.stop();
    this.task = null;
    this.update({ loading: false, loadingMore: false, refreshing: false });
  }

  refresh = () => this.state.loadingMore ? undefined : this.task?.run("manual");
  poll = () => this.task?.run("auto");

  togglePause = () => {
    this.update({ paused: !this.state.paused });
    if (!this.state.paused) void this.poll();
  };

  applyPending = () => {
    this.update({ rows: combine(this.state.rows, this.state.pending), pending: [] });
  };

  async loadMore() {
    if (!this.running || this.state.loadingMore || this.task?.isBusy() || !this.state.more) return;
    const generation = this.generation;
    const cursor = this.state.rows[this.state.rows.length - 1];
    if (!cursor) return;
    this.update({ loadingMore: true });
    try {
      const page = await this.load({ ...this.query, before: cursor.ts, before_id: cursor.finding_id, limit: FINDINGS_PAGE_SIZE });
      if (!this.running || generation !== this.generation) return;
      checkOlderPage(page, cursor);
      const rows = combine(this.state.rows, page);
      const ids = new Set(rows.map((finding) => finding.finding_id));
      this.update({
        rows, pending: this.state.pending.filter((finding) => !ids.has(finding.finding_id)),
        more: page.length === FINDINGS_PAGE_SIZE, error: null, updatedAt: new Date().toISOString(),
      });
    } catch (cause) {
      if (this.running && generation === this.generation) this.update({ error: cause instanceof Error ? cause : new Error(String(cause)) });
    } finally {
      if (this.running && generation === this.generation) this.update({ loadingMore: false });
    }
  }
}

export type FindingFeedCache = Map<string, FindingFeed>;
