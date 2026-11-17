import { useState } from "react";

import type { Api } from "../api";
import { Icon, type IconName } from "../components/Icon";
import { RefreshStatus } from "../components/RefreshStatus";
import { ResponseBadge } from "../components/ResponseBadge";
import { SeverityBadge } from "../components/Severity";
import { Empty, ErrorBox, Loading } from "../components/States";
import { SEVERITIES, agentName, SEVERITY_LABEL, TIME_RANGES, approvalsHref, findingHref, findingsHref, formatTime, overviewHref, rangeQuery, relativeTime, riskBand, sinceFor, timelineHref, timeRange, type TimeRange } from "../format";
import type { PersonRisk, Summary } from "../types";
import { REFRESH_MS, useAsync } from "../useAsync";

export function Overview({ api, query }: { api: Api; query: Record<string, string> }) {
  const range = timeRange(query.range, "7d");
  const [paused, setPaused] = useState(false);
  const summary = useAsync(() => api.summary(sinceFor(range)), [api, range], REFRESH_MS, paused);
  const review = useAsync(() => api.reviewCount(), [api], REFRESH_MS, paused);
  const risk = useAsync(() => api.risk(), [api], REFRESH_MS, paused);
  const { data, error, loading } = summary;
  const sources = [summary, review, risk];
  const updatedAt = sources.every((source) => source.updatedAt)
    ? sources.map((source) => source.updatedAt!).sort()[0] : null;
  return (
    <section>
      <div className="page-head overview-head">
        <div className="page-intro"><p className="eyebrow">Security overview</p><h1>에이전트 보안 현황</h1><p className="muted">지금 확인할 위험과 실행 결과를 한눈에.</p></div>
        <div className="segmented" role="group" aria-label="기간">
          {TIME_RANGES.map(([key, label]) => (
            <button key={key} className={key === range ? "on" : ""} aria-pressed={key === range} onClick={() => { window.location.hash = overviewHref({ range: key }); }}>
              {label}
            </button>
          ))}
        </div>
      </div>
      <RefreshStatus updatedAt={updatedAt} refreshing={sources.some((source) => source.refreshing)} error={sources.find((source) => source.error)?.error ?? null} paused={paused} onTogglePause={() => setPaused((value) => !value)} onRefresh={() => Promise.all(sources.map((source) => source.refresh()))} />
      {error && <ErrorBox error={error} />}
      {loading && !data && <Loading />}
      {risk.error && <ErrorBox error={risk.error} />}
      {review.error && <ErrorBox error={review.error} />}
      {data && <OverviewBody s={data} range={range} reviewPending={review.data?.pending ?? null} people={risk.data} />}
    </section>
  );
}

function OverviewBody({ s, range, reviewPending, people }: { s: Summary; range: TimeRange; reviewPending: number | null; people: PersonRisk[] | null }) {
  const f = s.findings;
  const urgent = f.by_severity.critical + f.by_severity.high;
  const period = rangeQuery(range, s.since);
  return (
    <>
      <div className="tiles overview-tiles">
        <Tile icon="findings" label="전체 탐지" value={f.total} note="선택한 기간의 Finding" href={findingsHref(period)} />
        <Tile icon="shield" label="긴급 · 높음" value={urgent} note="우선 확인할 탐지" href={findingsHref({ ...period, min_severity: "high" })} tone={urgent ? "alert" : undefined} />
        <Tile icon="approvals" label="보안팀 검토 대기" value={reviewPending ?? "—"} note="사용자 승인 후 사후 검토 · 전체 기간" href={approvalsHref({ review: "pending", range: "all" })} tone={reviewPending ? "warn" : undefined} />
        <Tile icon="inventory" label="동기화된 장비" value={`${s.devices.active} / ${s.devices.total}`} note={`최근 15분 · 최신 정책 ${s.devices.policy_current}대`} />
      </div>

      <div className="overview-grid">
        <section className="card recent-card">
          <div className="card-heading"><div><p className="eyebrow">Activity</p><h2>최근 탐지</h2></div><a className="text-link" href={findingsHref(period)}>전체 탐지 <Icon name="arrow" /></a></div>
          {s.recent.length === 0 ? <Empty>이 기간에는 탐지된 Finding이 없습니다.</Empty> : <ul className="recent-findings">
            {s.recent.map((x) => <li key={x.finding_id}><a className="recent-finding" href={findingHref(x.finding_id, { ...period, from: "overview" })}>
              <SeverityBadge severity={x.severity} />
              <div className="recent-finding-content"><h3>{x.title}</h3><p>{x.principal.user_id}<span aria-hidden="true"> · </span>{agentName(x.agent)}</p><ResponseBadge response={x.response} /></div>
              <time dateTime={x.ts} title={formatTime(x.ts)}>{relativeTime(x.ts)}</time>
            </a></li>)}
          </ul>}
        </section>
        <div className="overview-side">
          <section className="card distribution-card"><div className="card-heading"><div><p className="eyebrow">Distribution</p><h2>심각도별 탐지</h2></div><span className="muted small">{f.total.toLocaleString("ko-KR")}건</span></div><SeverityBars counts={f.by_severity} period={period} /></section>
          <section className="card telemetry-card"><span className="telemetry-icon"><Icon name="activity" /></span><div><p className="muted small">수집된 이벤트</p><p className="telemetry-value">{s.events.total.toLocaleString("ko-KR")}<span>건</span></p><p className="muted small">선택한 기간의 에이전트 활동</p></div></section>
        </div>
      </div>

      {people && <RiskCard people={people} />}

      <div className="grid-2">
        <div className="card">
          <div className="card-heading"><h2>사람별 탐지</h2><span className="muted small">최고 심각도 순</span></div>
          {f.top_users.length === 0 ? (
            <Empty>이 기간에는 Finding이 없습니다.</Empty>
          ) : (
            <div className="table-wrap"><table>
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
                      <a href={findingsHref({ ...period, user_id: u.user_id })}>{u.user_id}</a>
                      <a className="small side" href={timelineHref({ ...period, user_id: u.user_id })}>
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
            </table></div>
          )}
        </div>
      <div className="card">
        <div className="card-heading"><h2>많이 탐지된 룰</h2><span className="muted small">탐지 건수 순</span></div>
        {f.top_rules.length === 0 ? (
          <Empty>이 기간에는 Finding이 없습니다.</Empty>
        ) : (
          <div className="table-wrap"><table>
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
                    <a href={findingsHref({ ...period, rule_id: r.rule_id })}>{r.title}</a>
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
          </table></div>
        )}
      </div>
      </div>
    </>
  );
}

// People's risk (KISA P1-4). Always the last 24 h, whatever range is picked above: it is the value
// the control plane sends to sensors. One series (score per person), no legend: the number and the
// band word sit next to each bar, and the access column says what actually changes for that person.
function RiskCard({ people }: { people: PersonRisk[] }) {
  const period = rangeQuery("24h");
  return (
    <div className="card">
      <div className="card-heading"><div><p className="eyebrow">People risk</p><h2>사람별 위험도</h2></div><span className="chip chip-neutral">최근 24시간 · 에이전트 행동 기준</span></div>
      <details className="method-note"><summary>위험도 계산과 접근 제한 기준</summary><p className="muted small">
        점수는 critical 60·high 20을 최근일수록 크게(24시간 전은 절반) 더한 값이고 100에서 자릅니다. 접근 제한은 점수가 아니라 기준(critical 1건 또는
        high 3건)으로 정합니다. PC 설정 경보는 세지 않습니다.
      </p></details>
      {people.length === 0 ? (
        <Empty>최근 24시간에 위험 행동이 기록된 사람이 없습니다.</Empty>
      ) : (
        <div className="table-wrap"><table>
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
                    <a href={findingsHref({ ...period, user_id: p.user_id })}>{p.user_id}</a>
                    <a className="small side" href={timelineHref({ ...period, user_id: p.user_id })}>
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
        </table></div>
      )}
    </div>
  );
}

function Tile({ label, value, note, href, tone, icon }: { label: string; value: number | string; note?: string; href?: string; tone?: "alert" | "warn"; icon: IconName }) {
  const body = (
    <>
      <div className="tile-label">{label}<Icon name={icon} /></div>
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
function SeverityBars({ counts, period }: { counts: Record<string, number>; period: Record<string, string> }) {
  const max = Math.max(1, ...SEVERITIES.map((s) => counts[s] ?? 0));
  return (
    <div className="bars" role="table" aria-label="심각도별 Finding 수">
      {SEVERITIES.map((s) => {
        const n = counts[s] ?? 0;
        return (
          <a key={s} className="bar-row" role="row" href={findingsHref({ ...period, severity: s })} title={`${SEVERITY_LABEL[s]}: ${n}건`}>
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
