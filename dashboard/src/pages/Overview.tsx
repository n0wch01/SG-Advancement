import { useState } from "react";

import type { Api } from "../api";
import { SeverityBadge } from "../components/Severity";
import { Empty, ErrorBox, Loading } from "../components/States";
import { SEVERITIES, SEVERITY_LABEL, approvalsHref, findingsHref, relativeTime, responseText, riskBand, sinceFor, timelineHref } from "../format";
import type { PersonRisk, Summary } from "../types";
import { useAsync } from "../useAsync";

const RANGES: [string, string][] = [
  ["24h", "24시간"],
  ["7d", "7일"],
  ["30d", "30일"],
  ["all", "전체"],
];

export function Overview({ api }: { api: Api }) {
  const [range, setRange] = useState("7d");
  const { data, error, loading } = useAsync(() => api.summary(sinceFor(range)), [api, range]);
  const review = useAsync(() => api.reviewCount(), [api]);
  const risk = useAsync(() => api.risk(), [api]);
  return (
    <section>
      <div className="page-head">
        <h1>개요</h1>
        <div className="segmented" role="group" aria-label="기간">
          {RANGES.map(([key, label]) => (
            <button key={key} className={key === range ? "on" : ""} aria-pressed={key === range} onClick={() => setRange(key)}>
              {label}
            </button>
          ))}
        </div>
      </div>
      {error && <ErrorBox error={error} />}
      {loading && !data && <Loading />}
      {risk.error && <ErrorBox error={risk.error} />}
      {data && <OverviewBody s={data} reviewPending={review.data?.pending ?? null} people={risk.data} />}
    </section>
  );
}

function OverviewBody({ s, reviewPending, people }: { s: Summary; reviewPending: number | null; people: PersonRisk[] | null }) {
  const f = s.findings;
  const urgent = f.by_severity.critical + f.by_severity.high;
  return (
    <>
      <div className="tiles">
        <Tile label="Finding" value={f.total} href={findingsHref()} />
        <Tile label="긴급·높음" value={urgent} href={findingsHref({ min_severity: "high" })} tone={urgent ? "alert" : undefined} />
        <Tile label="장비 (최근 15분 동기화)" value={`${s.devices.active} / ${s.devices.total}`} note={`최신 정책 ${s.devices.policy_current}대`} />
        <Tile label="이벤트" value={s.events.total} />
        {reviewPending !== null && (
          <Tile
            label="보안팀 검토 대기 (사용자 승인)"
            value={reviewPending}
            href={approvalsHref({ review: "pending" })}
            tone={reviewPending ? "alert" : undefined}
          />
        )}
      </div>

      {people && <RiskCard people={people} />}

      <div className="grid-2">
        <div className="card">
          <h2>심각도별 Finding</h2>
          <SeverityBars counts={f.by_severity} />
        </div>
        <div className="card">
          <h2>사람별 (가장 높은 심각도 순)</h2>
          {f.top_users.length === 0 ? (
            <Empty>이 기간에는 Finding이 없습니다.</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>사람</th>
                  <th>최고 심각도</th>
                  <th className="num">건수</th>
                  <th>마지막</th>
                </tr>
              </thead>
              <tbody>
                {f.top_users.map((u) => (
                  <tr key={u.user_id}>
                    <td>
                      <a href={findingsHref({ user_id: u.user_id })}>{u.user_id}</a>
                      <a className="small side" href={timelineHref({ user_id: u.user_id })}>
                        타임라인
                      </a>
                    </td>
                    <td>
                      <SeverityBadge severity={u.max_severity} />
                    </td>
                    <td className="num">{u.count}</td>
                    <td className="muted">{relativeTime(u.last_ts)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <div className="card">
        <h2>많이 걸린 룰</h2>
        {f.top_rules.length === 0 ? (
          <Empty>이 기간에는 Finding이 없습니다.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>룰</th>
                <th>심각도</th>
                <th className="num">건수</th>
                <th>마지막</th>
              </tr>
            </thead>
            <tbody>
              {f.top_rules.map((r) => (
                <tr key={r.rule_id}>
                  <td>
                    <a href={findingsHref({ rule_id: r.rule_id })}>{r.title}</a>
                    <div className="mono muted small">{r.rule_id}</div>
                  </td>
                  <td>
                    <SeverityBadge severity={r.severity} />
                  </td>
                  <td className="num">{r.count}</td>
                  <td className="muted">{relativeTime(r.last_ts)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <h2>최근 Finding</h2>
        {s.recent.length === 0 ? (
          <Empty>이 기간에는 Finding이 없습니다.</Empty>
        ) : (
          <ul className="feed">
            {s.recent.map((x) => (
              <li key={x.finding_id}>
                <SeverityBadge severity={x.severity} />
                <a href={`#/findings/${encodeURIComponent(x.finding_id)}`}>{x.title}</a>
                <span className="muted">
                  {x.principal.user_id} · {responseText(x.response)} · {relativeTime(x.ts)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </>
  );
}

// People's risk (KISA P1-4). Always the last 24 h, whatever range is picked above: it is the value
// the control plane sends to sensors. One series (score per person), no legend: the number and the
// band word sit next to each bar, and the access column says what actually changes for that person.
function RiskCard({ people }: { people: PersonRisk[] }) {
  return (
    <div className="card">
      <h2>사람 위험도 (최근 24시간, 에이전트 행동 기준)</h2>
      <p className="muted small">
        점수는 critical 60·high 20을 최근일수록 크게(24시간 전은 절반) 더한 값이고 100에서 자릅니다. 접근 제한은 점수가 아니라 기준(critical 1건 또는
        high 3건)으로 정합니다. PC 설정 경보는 세지 않습니다.
      </p>
      {people.length === 0 ? (
        <Empty>최근 24시간에 위험 행동이 기록된 사람이 없습니다.</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>사람</th>
              <th>점수</th>
              <th>접근 제한</th>
              <th className="num">긴급 / 높음</th>
              <th>마지막</th>
            </tr>
          </thead>
          <tbody>
            {people.map((p) => {
              const band = riskBand(p.score);
              return (
                <tr key={p.user_id}>
                  <td>
                    <a href={findingsHref({ user_id: p.user_id })}>{p.user_id}</a>
                    <a className="small side" href={timelineHref({ user_id: p.user_id })}>
                      타임라인
                    </a>
                  </td>
                  <td>
                    <div className="risk-meter" title={`위험도 ${p.score} / 100 (${band.label})`}>
                      <span className="bar-track" aria-hidden="true">
                        <span className={`bar-fill fill-${band.fill}`} style={{ width: `${Math.max(p.score, 1)}%` }} />
                      </span>
                      <span className="num">{p.score}</span>
                      <span className="muted small">{band.label}</span>
                    </div>
                  </td>
                  <td>{p.elevated ? <span className="tag warn">민감 리소스는 보안팀 승인</span> : <span className="muted">없음</span>}</td>
                  <td className="num">
                    {p.critical} / {p.high}
                  </td>
                  <td className="muted">{p.last_ts ? relativeTime(p.last_ts) : "-"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

function Tile({ label, value, note, href, tone }: { label: string; value: number | string; note?: string; href?: string; tone?: "alert" }) {
  const body = (
    <>
      <div className="tile-label">{label}</div>
      <div className="tile-value">{typeof value === "number" ? value.toLocaleString("ko-KR") : value}</div>
      {note && <div className="tile-note muted">{note}</div>}
    </>
  );
  const cls = `tile${tone ? ` tile-${tone}` : ""}`;
  return href ? (
    <a className={cls} href={href}>
      {body}
    </a>
  ) : (
    <div className={cls}>{body}</div>
  );
}

// One series (count per severity), so no legend box: each row names its severity. Bars use the
// status palette and never stand alone: the label and the number sit next to them.
function SeverityBars({ counts }: { counts: Record<string, number> }) {
  const max = Math.max(1, ...SEVERITIES.map((s) => counts[s] ?? 0));
  return (
    <div className="bars" role="table" aria-label="심각도별 Finding 수">
      {SEVERITIES.map((s) => {
        const n = counts[s] ?? 0;
        return (
          <a key={s} className="bar-row" role="row" href={findingsHref({ severity: s })} title={`${SEVERITY_LABEL[s]}: ${n}건`}>
            <span role="rowheader" className="bar-label">
              <SeverityBadge severity={s} />
            </span>
            <span className="bar-track" role="cell" aria-hidden="true">
              {n > 0 && <span className={`bar-fill fill-${s}`} style={{ width: `${(n / max) * 100}%` }} />}
            </span>
            <span className="bar-value num" role="cell">
              {n}
            </span>
          </a>
        );
      })}
    </div>
  );
}
