import { useEffect, useState } from "react";

import type { Api } from "../api";
import { SeverityBadge } from "../components/Severity";
import { Empty, ErrorBox, Loading } from "../components/States";
import { SEVERITIES, SEVERITY_LABEL, findingsHref, formatTime, relativeTime, responseText } from "../format";
import type { Finding } from "../types";

const PAGE = 50;
const FILTERS = ["severity", "min_severity", "rule_id", "user_id"] as const;

export function Findings({ api, query }: { api: Api; query: Record<string, string> }) {
  const [rows, setRows] = useState<Finding[]>([]);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);
  const [more, setMore] = useState(false);
  const key = JSON.stringify(query);

  async function load(offset: number) {
    setLoading(true);
    setError(null);
    try {
      const page = await api.findings({ ...query, limit: PAGE, offset });
      setRows((prev) => (offset === 0 ? page : [...prev, ...page]));
      setMore(page.length === PAGE);
    } catch (e) {
      setError(e as Error);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    setRows([]);
    void load(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api, key]);

  return (
    <section>
      <div className="page-head">
        <h1>Finding</h1>
      </div>
      <FilterBar query={query} />
      {error && <ErrorBox error={error} />}
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
                    <a href={`#/findings/${encodeURIComponent(f.finding_id)}`}>{f.title}</a>
                    <div className="mono muted small">{f.rule_id}</div>
                  </td>
                  <td>
                    <a href={findingsHref({ user_id: f.principal.user_id })}>{f.principal.user_id}</a>
                  </td>
                  <td className="small">
                    {f.endpoint.device_id}
                    <div className="muted">{f.agent.type}</div>
                  </td>
                  <td className="small">{responseText(f.response)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {loading && <Loading />}
      {more && !loading && (
        <button className="more" onClick={() => void load(rows.length)}>
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
    const clean = Object.fromEntries(FILTERS.map((k) => [k, next[k]]).filter(([, v]) => v));
    window.location.hash = findingsHref(clean);
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
        <a className="reset" href={findingsHref()}>
          필터 지우기
        </a>
      )}
    </form>
  );
}
