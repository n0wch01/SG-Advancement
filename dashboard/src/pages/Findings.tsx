import { useEffect, useState } from "react";

import type { Api } from "../api";
import { RefreshStatus } from "../components/RefreshStatus";
import { ResponseBadge } from "../components/ResponseBadge";
import { SeverityBadge } from "../components/Severity";
import { Empty, ErrorBox, Loading } from "../components/States";
import { QUEUES, SEVERITIES, SEVERITY_LABEL, TIME_RANGES, clip, eventSummary, findingFilters, findingHref, findingQueue, findingsHref, formatTime, judgeText, rangeQuery, relativeTime, sinceFor, timeRange } from "../format";
import type { FindingFeedCache } from "../findingFeed";
import { REFRESH_MS, useAsync } from "../useAsync";
import { useFindingFeed } from "../useFindingFeed";

const QUEUE_NOTE: Record<string, string> = {
  review: "분류기가 정상으로 보고 집행되지 않은 것만 빼고 모두 보여 줍니다. 분류기가 보지 않는 탐지(유출, 파괴적 명령 등)는 그대로 나옵니다.",
  enforced: "실제로 막거나 가린 기록입니다. 분류기 판정과 상관없이 항상 여기에 남습니다.",
  benign: "분류기가 정상으로 봤고 집행되지 않은 것입니다. 표본으로 검사해 분류기가 놓친 공격을 찾습니다.",
  failed: "분류기가 판정하지 못해(모델 없음, 오류, 검증 실패) 룰만으로 판정한 것입니다.",
  all: "모든 탐지입니다.",
};

const FILTERS = ["severity", "min_severity", "rule_id", "user_id"] as const;

export function Findings({ api, query, cache }: { api: Api; query: Record<string, string>; cache: FindingFeedCache }) {
  const queue = findingQueue(query);
  const { feed, rows, pending, error, loading, loadingMore, refreshing, updatedAt, more, paused } = useFindingFeed(api, query, cache);
  const filters = findingFilters(query);

  return (
    <section onClickCapture={(event) => {
      if ((event.target as HTMLElement).closest("a")) feed.scrollY = window.scrollY;
    }}>
      <div className="page-head">
        <div className="page-intro"><p className="eyebrow">Findings</p><h1>탐지</h1><p className="muted">에이전트의 위험 행동과 실제 처리 결과를 조사합니다.</p></div>
      </div>
      <div className="segmented queue-tabs" role="group" aria-label="대기열">
        {QUEUES.map(([key, label]) => (
          <a key={key} className={key === queue ? "on" : ""} aria-current={key === queue ? "page" : undefined}
            href={findingsHref({ ...filters, queue: key === "review" ? undefined : key })}>{label}</a>
        ))}
      </div>
      <p className="muted small">{QUEUE_NOTE[queue]}</p>
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
                  <td className="small"><ResponseBadge response={f.response} /><JudgeChip labels={f.labels} /></td>
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
      {queue === "benign" && <BenignSample api={api} query={query} />}
    </section>
  );
}

export function JudgeChip({ labels }: { labels?: Record<string, string> }) {
  const judged = judgeText(labels);
  if (!judged) return null;
  return <div><span className={`chip chip-${judged.tone}`} title={labels?.sga_judge_model}>{judged.text}</span></div>;
}

// Sampling the classifier's misses (docs/classifier.md 5): every external result it judged benign, with or
// without a finding. Most have none, so the findings list alone would not show them.
function BenignSample({ api, query }: { api: Api; query: Record<string, string> }) {
  const since = query.since ?? sinceFor(timeRange(query.range));
  const { data, error } = useAsync(() => api.events({ judge: "benign", since, limit: 50 }), [api, since], REFRESH_MS);
  return (
    <section className="card">
      <div className="card-heading"><div><p className="eyebrow">Sampling</p><h2>분류기가 정상으로 본 외부 입력</h2></div><span className="muted small">최근 50건</span></div>
      <p className="muted small">대부분 탐지가 없어 위 목록에는 나오지 않습니다. 몇 건을 골라 읽어 보고, 인젝션이 섞여 있으면 분류기 평가 데이터에 넣으세요.</p>
      {error && <ErrorBox error={error} />}
      {!data && !error && <Loading />}
      {data && data.length === 0 && <Empty>이 기간에 분류기가 정상으로 본 외부 입력이 없습니다.</Empty>}
      {data && data.length > 0 && <div className="table-wrap"><table>
        <thead><tr><th>시각</th><th>사람 · 장비</th><th>출처</th><th>점수</th><th>내용</th></tr></thead>
        <tbody>{data.map((e) => (
          <tr key={e.event_id}>
            <td className="nowrap" title={formatTime(e.ts)}>{relativeTime(e.ts)}</td>
            <td className="small">{e.principal.user_id}<div className="muted">{e.endpoint.device_id}</div></td>
            <td className="mono small">{e.labels.sga_input_source ?? "-"}</td>
            <td className="num small">{e.labels.sga_judge_score ?? "-"}</td>
            <td className="small" title={String(e.payload.output_preview ?? "")}>{clip(eventSummary(e), 140)}</td>
          </tr>
        ))}</tbody>
      </table></div>}
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
        <a className="reset" href={findingsHref({ range: query.range, since: query.since, queue: query.queue })}>
          필터 지우기
        </a>
      )}
    </form>
  );
}
