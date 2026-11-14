import { useState } from "react";

import { ApiError, type Api } from "../api";
import { SeverityBadge } from "../components/Severity";
import { Empty, ErrorBox, Loading } from "../components/States";
import {
  ACTION_STATUS_LABEL,
  CAMPAIGN_RULE,
  REMOTE_ACTION_LABEL,
  campaignPeople,
  eventSummary,
  findingsHref,
  formatTime,
  lineageFlow,
  relativeTime,
  responseText,
  timelineHref,
} from "../format";
import type { AgentEvent, FindingDetail as Detail, Finding, Role } from "../types";
import { useAsync } from "../useAsync";

export function FindingDetail({ api, id, role }: { api: Api; id: string; role: Role | null }) {
  const { data, error, loading } = useAsync(() => api.finding(id), [api, id]);
  return (
    <section>
      <p>
        <a href="#/findings">← Finding 목록</a>
      </p>
      {error && <ErrorBox error={error} />}
      {loading && !data && <Loading />}
      {data && <DetailBody d={data} />}
      {data && data.finding.rule_id !== CAMPAIGN_RULE && role === "admin" && <Respond api={api} f={data.finding} />}
    </section>
  );
}

function DetailBody({ d }: { d: Detail }) {
  const f = d.finding;
  const evidence = new Set(f.evidence_event_ids);
  return (
    <>
      <div className="page-head">
        <h1>
          <SeverityBadge severity={f.severity} /> {f.title}
        </h1>
      </div>

      {(d.campaigns ?? []).map((c) => (
        <p key={c.finding_id} className="notice" role="note">
          <span className="chip chip-bad">캠페인</span> 같은 지표가 {c.labels.people_count}명 이상에게 나타난 캠페인의 일부입니다.{" "}
          <a href={`#/findings/${encodeURIComponent(c.finding_id)}`}>캠페인 보기 →</a>
        </p>
      ))}
      {f.rule_id === CAMPAIGN_RULE && <Campaign f={f} members={d.campaign_members ?? []} />}
      <DataFlow d={d} />

      <div className="grid-2">
        <div className="card">
          <h2>무슨 일인가</h2>
          <p>{f.message}</p>
          {f.explanation && <p className="muted">{f.explanation}</p>}
          <h3>권장 조치</h3>
          <p>{f.recommended_action || "-"}</p>
        </div>
        <div className="card">
          <h2>근거</h2>
          <dl className="facts">
            <dt>시각</dt>
            <dd>{formatTime(f.ts)}</dd>
            <dt>룰</dt>
            <dd>
              <a className="mono" href={findingsHref({ rule_id: f.rule_id })}>
                {f.rule_id}
              </a>
              {f.category && <span className="muted"> · {f.category}</span>}
            </dd>
            <dt>사람</dt>
            <dd>
              <a href={findingsHref({ user_id: f.principal.user_id })}>{f.principal.user_id}</a>
              <a className="small side" href={timelineHref({ user_id: f.principal.user_id })}>
                타임라인
              </a>
            </dd>
            <dt>장비</dt>
            <dd>
              {f.endpoint.device_id}
              {f.endpoint.hostname && <span className="muted"> ({f.endpoint.hostname})</span>}
            </dd>
            <dt>에이전트 · 대화</dt>
            <dd className="mono small">
              {f.agent.type} · {f.agent.session_id}
              <a className="side" href={timelineHref({ session_id: f.agent.root_session_id ?? f.agent.session_id })}>
                대화 타임라인
              </a>
              {f.agent.parent_session_id && (
                <div className="muted">
                  위임: {f.agent.root_session_id ?? f.agent.parent_session_id} → … (깊이 {f.agent.spawn_depth ?? "?"})
                </div>
              )}
            </dd>
            <dt>대응</dt>
            <dd>
              {responseText(f.response)}
              {f.response?.detail && <div className="muted small">{f.response.detail}</div>}
              {f.response?.evidence && <div className="muted small">근거: {f.response.evidence}</div>}
            </dd>
            {f.tags.length > 0 && (
              <>
                <dt>태그</dt>
                <dd>
                  {f.tags.map((t) => (
                    <span key={t} className="tag">
                      {t}
                    </span>
                  ))}
                </dd>
              </>
            )}
          </dl>
        </div>
      </div>

      <div className="card">
        <h2>증거 이벤트</h2>
        <p className="muted small">센서가 엔드포인트에서 비밀값을 마스킹한 뒤 보낸 그대로입니다.</p>
        {d.evidence.length === 0 ? <Empty>연결된 이벤트가 없습니다.</Empty> : d.evidence.map((e) => <EventCard key={e.event_id} e={e} open />)}
      </div>

      <div className="card">
        <h2>같은 대화의 흐름 (이 Finding까지, 오래된 순)</h2>
        {d.session_events.length === 0 ? (
          <Empty>이 대화의 다른 이벤트가 없습니다.</Empty>
        ) : (
          <ol className="timeline">
            {d.session_events.map((e) => (
              <li key={e.event_id} className={evidence.has(e.event_id) ? "hit" : ""}>
                <span className="mono muted small">{formatTime(e.ts).slice(11)}</span>
                <span className="kind mono small">{e.payload.kind}</span>
                <span>{eventSummary(e)}</span>
                {evidence.has(e.event_id) && <span className="tag">증거</span>}
              </li>
            ))}
          </ol>
        )}
      </div>

      {d.session_findings.length > 0 && (
        <div className="card">
          <h2>같은 대화의 다른 Finding</h2>
          <ul className="feed">
            {d.session_findings.map((x) => (
              <li key={x.finding_id}>
                <SeverityBadge severity={x.severity} />
                <a href={`#/findings/${encodeURIComponent(x.finding_id)}`}>{x.title}</a>
                <span className="muted">{formatTime(x.ts)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

// Campaign (M11): who got the same indicator, on which device, and where to respond for each person.
function Campaign({ f, members }: { f: Finding; members: Finding[] }) {
  const people = campaignPeople(members);
  const raised = Number(f.labels.people_count ?? 0);
  return (
    <div className="card">
      <h2>캠페인: 같은 지표를 받은 사람들</h2>
      <dl className="facts">
        <dt>원래 룰</dt>
        <dd>
          <a className="mono" href={findingsHref({ rule_id: f.labels.source_rule })}>
            {f.labels.source_rule}
          </a>
        </dd>
        <dt>지표</dt>
        <dd className="mono">{f.labels.indicator}</dd>
        <dt>사람 수</dt>
        <dd>
          {people.length}명
          {people.length > raised && <span className="muted"> (탐지 당시 {raised}명, 이후 {people.length - raised}명 늘어남)</span>}
        </dd>
      </dl>
      <p className="muted small">
        관제 서버가 24시간 안에 서로 다른 사람 3명 이상에게서 같은 룰·같은 지표를 보고 만든 Finding입니다. 차단은 사람마다 그 사람의 Finding에서
        보냅니다(Finding이 나온 장비로 가야 효과가 있습니다).
      </p>
      <table>
        <thead>
          <tr>
            <th>사람</th>
            <th>장비</th>
            <th>처음 · 마지막</th>
            <th>대응</th>
          </tr>
        </thead>
        <tbody>
          {people.map((p) => {
            const first = p.findings[0];
            const last = p.findings[p.findings.length - 1];
            return (
              <tr key={p.user_id}>
                <td>
                  {p.user_id}
                  <a className="small side" href={timelineHref({ user_id: p.user_id })}>
                    타임라인
                  </a>
                </td>
                <td className="small">{p.devices.join(", ")}</td>
                <td className="small nowrap" title={`${formatTime(first.ts)} · ${formatTime(last.ts)}`}>
                  {relativeTime(first.ts)}
                  {p.findings.length > 1 && ` · ${relativeTime(last.ts)} (${p.findings.length}건)`}
                </td>
                <td className="small">
                  <a href={`#/findings/${encodeURIComponent(last.finding_id)}`}>Finding에서 대응 →</a>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function EventCard({ e, open = false }: { e: AgentEvent; open?: boolean }) {
  const [show, setShow] = useState(open);
  return (
    <div className="event">
      <button className="event-head" aria-expanded={show} onClick={() => setShow(!show)}>
        <span className="kind mono small">{e.payload.kind}</span>
        <span>{eventSummary(e)}</span>
        <span className="muted small">{formatTime(e.ts)}</span>
      </button>
      {show && <pre className="json">{JSON.stringify(e.payload, null, 2)}</pre>}
    </div>
  );
}

// Remote response (M11), admin token only. Targets come from the finding: the conversation at the top
// of its delegation chain (blocking it also blocks the sub-agents), the person, the device it came from.
function Respond({ api, f }: { api: Api; f: Finding }) {
  const session = f.agent.root_session_id ?? f.agent.session_id;
  const [by, setBy] = useState("");
  const [reason, setReason] = useState(`${f.title} (${f.rule_id})`);
  const [msg, setMsg] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const sent = useAsyncList(api, f.endpoint.device_id, tick);
  const send = async (action: string, target: string) => {
    setMsg(null);
    try {
      await api.createAction({ device_id: f.endpoint.device_id, action, target, finding_id: f.finding_id, by, reason });
      setMsg(`${REMOTE_ACTION_LABEL[action]}을(를) 보냈습니다. 센서가 몇 초 안에 실행합니다.`);
      setTick((t) => t + 1);
    } catch (e) {
      setMsg(e instanceof ApiError ? e.message : String(e));
    }
  };
  const ready = by.trim() !== "" && reason.trim() !== "";
  return (
    <div className="card">
      <h2>원격 대응</h2>
      <p className="muted small">
        장비 <strong>{f.endpoint.device_id}</strong>로 보냅니다. 대화 차단은 이 대화와 거기서 위임된 하위 에이전트의 이후 툴 호출을 모두 막습니다.
      </p>
      <div className="filters">
        <label>
          누가
          <input value={by} onChange={(e) => setBy(e.target.value)} placeholder="예: secops@corp.test" />
        </label>
        <label className="grow">
          왜
          <input value={reason} onChange={(e) => setReason(e.target.value)} />
        </label>
      </div>
      <div className="editor-actions">
        <button className="primary" disabled={!ready} onClick={() => void send("block_session", session)}>
          이 대화 차단
        </button>
        <button className="primary" disabled={!ready} onClick={() => void send("block_user", f.principal.user_id)}>
          {f.principal.user_id} 차단
        </button>
        <button className="link" disabled={!ready} onClick={() => void send("abort_session", f.agent.session_id)}>
          실행 중단 시도
        </button>
        <a className="small" href="#/actions">
          대응 목록 →
        </a>
      </div>
      {msg && <p className="small">{msg}</p>}
      {sent.length > 0 && (
        <ul className="feed">
          {sent
            .filter((a) => a.finding_id === f.finding_id || a.target === session || a.target === f.principal.user_id)
            .map((a) => (
              <li key={a.id}>
                <span>{REMOTE_ACTION_LABEL[a.action] ?? a.action}</span>
                <span className="mono small">{a.target}</span>
                <span className="muted small">
                  {ACTION_STATUS_LABEL[a.status]}
                  {a.result_detail ? ` · ${a.result_detail}` : ""}
                </span>
              </li>
            ))}
        </ul>
      )}
    </div>
  );
}

function useAsyncList(api: Api, device: string, tick: number) {
  const { data } = useAsync(() => api.actions({ device_id: device }), [api, device, tick]);
  return data ?? [];
}

function DataFlow({ d }: { d: Detail }) {
  const steps = lineageFlow(d.finding, d.evidence);
  if (!steps) return null;
  return (
    <div className="card">
      <h2>데이터 흐름</h2>
      <p className="muted small">테스트 DB에서 조회한 보호 데이터가 어디로 가려 했는지. 값은 PC 밖으로 보내지 않아 가려져 있습니다.</p>
      <ol className="flow">
        {steps.map((s, i) => (
          <li key={`${s.key}-${i}`} className={`flow-${s.key}`}>
            <strong>{s.title}</strong>
            {s.lines.map((l) => (
              <div key={l} className="small">
                {l}
              </div>
            ))}
            {s.eventId && <div className="muted small mono">이벤트 {s.eventId.slice(0, 12)}…</div>}
          </li>
        ))}
      </ol>
    </div>
  );
}
