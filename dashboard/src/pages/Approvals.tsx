import { useEffect, useState } from "react";

import type { Api } from "../api";
import { SeverityBadge } from "../components/Severity";
import { Empty, ErrorBox, Loading } from "../components/States";
import { DECISION_LABEL, approvalsHref, approverText, clip, formatTime, relativeTime, sinceFor, waitText } from "../format";
import type { Approval } from "../types";

const PAGE = 50;
const RANGES: [string, string][] = [
  ["24h", "24시간"],
  ["7d", "7일"],
  ["30d", "30일"],
  ["all", "전체"],
];

// Policy (2026-11-11): people approve risky actions themselves; security reviews them here afterwards.
export function Approvals({ api, query }: { api: Api; query: Record<string, string> }) {
  const view = query.approved === "false" ? "denied" : query.approved === "all" ? "all" : "approved";
  const range = query.range ?? "7d";
  const [rows, setRows] = useState<Approval[]>([]);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);
  const [more, setMore] = useState(false);
  const key = JSON.stringify(query);

  async function load(offset: number) {
    setLoading(true);
    setError(null);
    try {
      const page = await api.approvals({
        approved: view === "all" ? undefined : String(view === "approved"),
        user_id: query.user_id,
        since: sinceFor(range),
        limit: PAGE,
        offset,
      });
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

  const go = (next: Record<string, string | undefined>) => {
    window.location.hash = approvalsHref({ approved: query.approved, range: query.range, user_id: query.user_id, ...next });
  };

  return (
    <section>
      <div className="page-head">
        <h1>승인 감사</h1>
        <div className="segmented" role="group" aria-label="기간">
          {RANGES.map(([k, label]) => (
            <button key={k} className={k === range ? "on" : ""} aria-pressed={k === range} onClick={() => go({ range: k })}>
              {label}
            </button>
          ))}
        </div>
      </div>
      <p className="muted small">
        사람이 에이전트의 위험한 행동을 직접 승인한 기록입니다. 승인한 사람은 팀 게이트웨이에서 감사 프록시가 본 실제 사람이고, 요청한 사람과 다르면 따로
        표시합니다.
      </p>
      <div className="filters">
        <div className="segmented" role="group" aria-label="결정">
          {(
            [
              ["approved", "승인한 것", undefined],
              ["denied", "거절·시간 초과", "false"],
              ["all", "전체", "all"],
            ] as const
          ).map(([k, label, v]) => (
            <button key={k} className={k === view ? "on" : ""} aria-pressed={k === view} onClick={() => go({ approved: v })}>
              {label}
            </button>
          ))}
        </div>
        {query.user_id && (
          <span className="small">
            요청한 사람: <strong>{query.user_id}</strong>{" "}
            <a className="reset" href={approvalsHref({ approved: query.approved, range: query.range })}>
              지우기
            </a>
          </span>
        )}
      </div>

      {error && <ErrorBox error={error} />}
      {!loading && !error && rows.length === 0 && <Empty>이 조건의 승인 기록이 없습니다.</Empty>}
      {rows.length > 0 && (
        <div className="card flush">
          <table className="approvals">
            <thead>
              <tr>
                <th>시각</th>
                <th>요청한 사람</th>
                <th>응답한 사람</th>
                <th>결정</th>
                <th>보류된 툴 호출</th>
                <th>승인을 요청한 룰</th>
                <th>감사 경보</th>
                <th className="num">대기</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <ApprovalRow key={a.event_id} a={a} />
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

function ApprovalRow({ a }: { a: Approval }) {
  const who = approverText(a);
  const args = a.held_call ? clip(JSON.stringify(a.held_call.arguments), 110) : "";
  return (
    <tr className={a.flagged.length ? "flagged" : ""}>
      <td className="nowrap" title={formatTime(a.ts)}>
        {relativeTime(a.ts)}
      </td>
      <td>
        <a href={approvalsHref({ user_id: a.user_id })}>{a.user_id}</a>
        <div className="muted small">{a.device_id}</div>
      </td>
      <td>
        {who.who}
        {who.other && <span className="tag warn">본인 아님</span>}
        <div className="muted small">{who.how}</div>
      </td>
      <td className="nowrap">
        <span className={a.approved ? "decision ok" : "decision no"}>{DECISION_LABEL[a.decision] ?? a.decision}</span>
      </td>
      <td>
        <span className="mono">{a.tool}</span>
        {args && <div className="mono muted small args">{args}</div>}
      </td>
      <td>
        {a.asked_by.length === 0 ? (
          <span className="muted small">{a.rule_ids.join(", ") || "-"}</span>
        ) : (
          a.asked_by.map((f) => (
            <div key={f.finding_id}>
              <SeverityBadge severity={f.severity} /> <a href={`#/findings/${encodeURIComponent(f.finding_id)}`}>{f.title}</a>
            </div>
          ))
        )}
      </td>
      <td>
        {a.flagged.length === 0 ? (
          <span className="muted small">-</span>
        ) : (
          a.flagged.map((f) => (
            <div key={f.finding_id}>
              <SeverityBadge severity={f.severity} /> <a href={`#/findings/${encodeURIComponent(f.finding_id)}`}>{f.title}</a>
            </div>
          ))
        )}
      </td>
      <td className="num">{waitText(a.wait_ms)}</td>
    </tr>
  );
}
