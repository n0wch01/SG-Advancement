import { useEffect, useState } from "react";

import type { Api } from "../api";
import { RefreshStatus } from "../components/RefreshStatus";
import { ResponseBadge } from "../components/ResponseBadge";
import { SeverityBadge } from "../components/Severity";
import { Empty, ErrorBox, Loading } from "../components/States";
import { SEVERITIES, SEVERITY_LABEL, TIME_RANGES, findingFilters, findingHref, findingsHref, formatTime, rangeQuery, relativeTime, timeRange } from "../format";
import type { FindingFeedCache } from "../findingFeed";
import { useFindingFeed } from "../useFindingFeed";

const FILTERS = ["severity", "min_severity", "rule_id", "user_id"] as const;

export function Findings({ api, query, cache }: { api: Api; query: Record<string, string>; cache: FindingFeedCache }) {
  const { feed, rows, pending, error, loading, loadingMore, refreshing, updatedAt, more, paused } = useFindingFeed(api, query, cache);
  const filters = findingFilters(query);

  return (
    <section onClickCapture={(event) => {
      if ((event.target as HTMLElement).closest("a")) feed.scrollY = window.scrollY;
    }}>
      <div className="page-head">
        <div className="page-intro"><p className="eyebrow">Findings</p><h1>탐지</h1><p className="muted">에이전트의 위험 행동과 실제 처리 결과를 조사합니다.</p></div>
      </div>
      <FilterBar query={query} />
      {query.since && <p className="filter-period muted small">조회 시작 시각: <time dateTime={query.since}>{formatTime(query.since)}</time></p>}
      <RefreshStatus updatedAt={updatedAt} refreshing={refreshing || loadingMore} error={error} paused={paused} onTogglePause={feed.togglePause} onRefresh={feed.refresh} />
      {error && <ErrorBox error={error} />}
      {pending.length > 0 && <div className="new-findings">
        <span role="status">새 탐지 <strong>{pending.length}건</strong>이 있습니다. 읽던 목록은 그대로 유지됩니다.</span>
        <button type="button" className="quiet-button" onClick={() => { feed.applyPending(); feed.scrollY = 0; window.scrollTo(0, 0); }}>목록에 반영</button>
      </div>}
      {!loading && !error && rows.length === 0 && <Empty>조건에 맞는 Finding이 없습니다.</Empty>}
      {rows.length > 0 && (
        <div className="card flush">
          <table className="findings">
            <thead>
              <tr>
                <th>시각</th>
                <th>심각도</th>
                <th>내용</th>
                <th>사람</th>
                <th>장비 · 에이전트</th>
                <th>대응</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr key={f.finding_id}>
                  <td className="nowrap" title={formatTime(f.ts)}>
                    {relativeTime(f.ts)}
                  </td>
                  <td>
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td>
                    <a href={findingHref(f.finding_id, filters)}>{f.title}</a>
                    <div className="mono muted small">{f.rule_id}</div>
                  </td>
                  <td>
                    <a href={findingsHref({ ...filters, user_id: f.principal.user_id })}>{f.principal.user_id}</a>
                  </td>
                  <td className="small">
                    {f.endpoint.device_id}
                    <div className="muted">{f.agent.type}</div>
                  </td>
                  <td className="small"><ResponseBadge response={f.response} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {(loading || loadingMore) && <Loading />}
      {more && !loading && (
        <button className="more" disabled={loadingMore || refreshing} onClick={() => void feed.loadMore()}>
          더 보기
        </button>
      )}
    </section>
  );
}

function FilterBar({ query }: { query: Record<string, string> }) {
  const [draft, setDraft] = useState(query);
  useEffect(() => setDraft(query), [query]);
  const apply = (next: Record<string, string>) => {
    window.location.hash = findingsHref(findingFilters(next));
  };
  return (
    <form
      className="filters"
      onSubmit={(e) => {
        e.preventDefault();
        apply(draft);
      }}
    >
      <label>
        기간
        <select value={timeRange(draft.range)} onChange={(event) => apply({ ...draft, since: "", ...rangeQuery(timeRange(event.target.value)) })}>
          {TIME_RANGES.map(([key, label]) => <option key={key} value={key}>{label}</option>)}
        </select>
      </label>
      <label>
        심각도
        <select
          value={draft.severity ? `=${draft.severity}` : draft.min_severity ? `>=${draft.min_severity}` : ""}
          onChange={(e) => {
            const v = e.target.value;
            const next = { ...draft, severity: "", min_severity: "" };
            if (v.startsWith(">=")) next.min_severity = v.slice(2);
            else if (v.startsWith("=")) next.severity = v.slice(1);
            apply(next);
          }}
        >
          <option value="">전체</option>
          {SEVERITIES.slice(0, 3).map((s) => (
            <option key={`>=${s}`} value={`>=${s}`}>
              {SEVERITY_LABEL[s]} 이상
            </option>
          ))}
          {SEVERITIES.map((s) => (
            <option key={`=${s}`} value={`=${s}`}>
              {SEVERITY_LABEL[s]}만
            </option>
          ))}
        </select>
      </label>
      <label>
        룰 ID
        <input value={draft.rule_id ?? ""} onChange={(e) => setDraft({ ...draft, rule_id: e.target.value })} placeholder="예: openclaw-unmanaged-install" />
      </label>
      <label>
        사람
        <input value={draft.user_id ?? ""} onChange={(e) => setDraft({ ...draft, user_id: e.target.value })} placeholder="예: alice@corp.test" />
      </label>
      <button type="submit">적용</button>
      {FILTERS.some((k) => query[k]) && (
        <a className="reset" href={findingsHref({ range: query.range, since: query.since })}>
          필터 지우기
        </a>
      )}
    </form>
  );
}
