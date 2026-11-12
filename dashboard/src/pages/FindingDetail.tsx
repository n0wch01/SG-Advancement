import { useState } from "react";

import type { Api } from "../api";
import { SeverityBadge } from "../components/Severity";
import { Empty, ErrorBox, Loading } from "../components/States";
import { eventSummary, findingsHref, formatTime, responseText } from "../format";
import type { AgentEvent, FindingDetail as Detail } from "../types";
import { useAsync } from "../useAsync";

export function FindingDetail({ api, id }: { api: Api; id: string }) {
  const { data, error, loading } = useAsync(() => api.finding(id), [api, id]);
  return (
    <section>
      <p>
        <a href="#/findings">← Finding 목록</a>
      </p>
      {error && <ErrorBox error={error} />}
      {loading && !data && <Loading />}
      {data && <DetailBody d={data} />}
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
            </dd>
            <dt>장비</dt>
            <dd>
              {f.endpoint.device_id}
              {f.endpoint.hostname && <span className="muted"> ({f.endpoint.hostname})</span>}
            </dd>
            <dt>에이전트 · 대화</dt>
            <dd className="mono small">
              {f.agent.type} · {f.agent.session_id}
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
