import { useEffect, useMemo, useState } from "react";

import type { Api } from "../api";
import { SeverityBadge } from "../components/Severity";
import { Empty, ErrorBox, Loading } from "../components/States";
import { eventSummary, formatTime, sessionTree, shortSession, timelineHref } from "../format";
import type { AgentEvent, Finding, Timeline as TimelineData } from "../types";
import { useAsync } from "../useAsync";

type Item = { ts: string; event?: AgentEvent; finding?: Finding };

export function Timeline({ api, query }: { api: Api; query: Record<string, string> }) {
  const scoped = Boolean(query.user_id || query.session_id);
  return (
    <section>
      <div className="page-head">
        <h1>타임라인</h1>
      </div>
      <ScopeForm query={query} api={api} />
      {scoped ? (
        <TimelineBody api={api} query={query} />
      ) : (
        <Empty>사람이나 대화를 고르면 그 활동을 시간순으로 보여 줍니다. 대화를 고르면 거기서 위임된 하위 에이전트 대화도 함께 봅니다.</Empty>
      )}
    </section>
  );
}

function ScopeForm({ query, api }: { query: Record<string, string>; api: Api }) {
  const [user, setUser] = useState(query.user_id ?? "");
  const [session, setSession] = useState(query.session_id ?? "");
  useEffect(() => {
    setUser(query.user_id ?? "");
    setSession(query.session_id ?? "");
  }, [query.user_id, query.session_id]);
  // Suggest the people with findings recently, so nobody has to type an e-mail address.
  const people = useAsync(() => api.summary(null).then((s) => s.findings.top_users.map((u) => u.user_id)), [api]);
  return (
    <form
      className="filters"
      onSubmit={(e) => {
        e.preventDefault();
        window.location.hash = timelineHref({ user_id: user.trim() || undefined, session_id: session.trim() || undefined });
      }}
    >
      <label>
        사람
        <input list="timeline-people" value={user} onChange={(e) => setUser(e.target.value)} placeholder="예: alice@corp.test" />
        <datalist id="timeline-people">
          {(people.data ?? []).map((p) => (
            <option key={p} value={p} />
          ))}
        </datalist>
      </label>
      <label>
        대화 ID
        <input value={session} onChange={(e) => setSession(e.target.value)} placeholder="예: agent:main:dashboard:…" />
      </label>
      <button type="submit">보기</button>
    </form>
  );
}

function TimelineBody({ api, query }: { api: Api; query: Record<string, string> }) {
  const { data, error, loading } = useAsync(
    () => api.timeline({ user_id: query.user_id, session_id: query.session_id }),
    [api, query.user_id, query.session_id],
  );
  const [focus, setFocus] = useState<string | null>(null);
  const [onlyFindings, setOnlyFindings] = useState(false);
  useEffect(() => setFocus(null), [query.user_id, query.session_id]);
  if (error) return <ErrorBox error={error} />;
  if (loading && !data) return <Loading />;
  if (!data) return null;
  if (data.events.length === 0 && data.findings.length === 0) return <Empty>이 범위의 활동이 없습니다.</Empty>;
  return (
    <div className="timeline-layout">
      <SessionTree data={data} focus={focus} setFocus={setFocus} />
      <div className="card">
        <div className="timeline-head">
          <h2>
            {query.session_id ? `대화 ${shortSession(query.session_id)}와 위임된 대화` : `${query.user_id}의 활동`}
            {focus && <span className="muted small"> · {shortSession(focus)}만</span>}
          </h2>
          <label className="small check">
            <input type="checkbox" checked={onlyFindings} onChange={(e) => setOnlyFindings(e.target.checked)} /> Finding만
          </label>
        </div>
        {data.truncated && <p className="muted small">최근 활동만 보여 줍니다(범위를 좁히면 더 볼 수 있습니다).</p>}
        <Items data={data} focus={focus} onlyFindings={onlyFindings} />
      </div>
    </div>
  );
}

function SessionTree({ data, focus, setFocus }: { data: TimelineData; focus: string | null; setFocus: (s: string | null) => void }) {
  const tree = useMemo(() => sessionTree(data.sessions), [data.sessions]);
  return (
    <div className="card tree">
      <h2>대화와 위임</h2>
      <button className={`tree-all ${focus === null ? "on" : ""}`} onClick={() => setFocus(null)}>
        전체 ({data.sessions.length}개 대화)
      </button>
      <ul>
        {tree.map(({ node, depth }) => (
          <li key={node.session_id} style={{ paddingLeft: depth * 16 }}>
            <button className={focus === node.session_id ? "on" : ""} onClick={() => setFocus(node.session_id)} title={node.session_id}>
              {depth > 0 && <span className="muted">↳ </span>}
              <span className="mono small">{shortSession(node.session_id)}</span>
              {node.max_severity && <SeverityBadge severity={node.max_severity} />}
              <div className="muted small">
                {node.user_ids.join(", ")} · {node.device_ids.join(", ")} · 이벤트 {node.events}
                {node.findings > 0 && ` · Finding ${node.findings}`}
                {depth > 0 && node.spawn_depth !== null && ` · 위임 깊이 ${node.spawn_depth}`}
              </div>
            </button>
            {depth === 0 && node.session_id !== data.session_id && (
              <a className="small" href={timelineHref({ session_id: node.session_id })}>
                이 대화의 위임 트리 보기
              </a>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function Items({ data, focus, onlyFindings }: { data: TimelineData; focus: string | null; onlyFindings: boolean }) {
  const depth = useMemo(() => new Map(sessionTree(data.sessions).map((t) => [t.node.session_id, t.depth])), [data.sessions]);
  const items = useMemo(() => {
    const all: Item[] = [
      ...(onlyFindings ? [] : data.events.map((e) => ({ ts: e.ts, event: e }))),
      ...data.findings.map((f) => ({ ts: f.ts, finding: f })),
    ];
    const inFocus = (sid: string) => focus === null || sid === focus;
    return all
      .filter((i) => inFocus((i.event ?? i.finding)!.agent.session_id))
      .sort((a, b) => a.ts.localeCompare(b.ts) || (a.event ? -1 : 1)); // the event before the finding it caused
  }, [data, focus, onlyFindings]);
  if (items.length === 0) return <Empty>표시할 항목이 없습니다.</Empty>;
  let day = "";
  return (
    <ol className="tl">
      {items.map((i) => {
        const d = formatTime(i.ts).slice(0, 10);
        const header = d !== day ? <li className="tl-day">{(day = d)}</li> : null;
        const sid = (i.event ?? i.finding)!.agent.session_id;
        const indent = depth.get(sid) ?? 0;
        const sess = (
          <span className="mono small tl-session" title={sid}>
            {indent > 0 ? "↳ " : ""}
            {shortSession(sid)}
          </span>
        );
        return (
          <FragmentRow key={i.event?.event_id ?? i.finding!.finding_id} header={header}>
            {i.finding ? (
              <li className="tl-finding">
                <span className="mono muted small">{formatTime(i.ts).slice(11)}</span>
                {sess}
                <SeverityBadge severity={i.finding.severity} />
                <span>
                  <a href={`#/findings/${encodeURIComponent(i.finding.finding_id)}`}>{i.finding.title}</a>
                  <span className="muted small"> · {i.finding.principal.user_id}</span>
                </span>
              </li>
            ) : (
              <li>
                <span className="mono muted small">{formatTime(i.ts).slice(11)}</span>
                {sess}
                <span className="kind mono small">{i.event!.payload.kind}</span>
                <span>
                  {eventSummary(i.event!)}
                  <span className="muted small"> · {i.event!.principal.user_id}</span>
                </span>
              </li>
            )}
          </FragmentRow>
        );
      })}
    </ol>
  );
}

function FragmentRow({ header, children }: { header: React.ReactNode; children: React.ReactNode }) {
  return (
    <>
      {header}
      {children}
    </>
  );
}
