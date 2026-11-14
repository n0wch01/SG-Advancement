import { useEffect, useState } from "react";

import { ApiError, type Api } from "../api";
import { SeverityBadge } from "../components/Severity";
import { Empty, ErrorBox, Loading } from "../components/States";
import { DECISION_LABEL, approvalsHref, approverText, clip, formatTime, relativeTime, reviewText, sinceFor, timelineHref, waitText } from "../format";
import type { Approval, ApprovalMetrics, ChannelStats, Role } from "../types";

const PAGE = 50;
const RANGES: [string, string][] = [
  ["24h", "24시간"],
  ["7d", "7일"],
  ["30d", "30일"],
  ["all", "전체"],
];

// Policy (2026-11-11, 2026-11-14): people approve risky actions themselves, grade 3-1 included; only very
// high risk is blocked outright. Security reviews each approved high/critical call here afterwards.
export function Approvals({ api, query, role }: { api: Api; query: Record<string, string>; role: Role | null }) {
  const view = query.review === "pending" ? "pending" : query.approved === "false" ? "denied" : query.approved === "all" ? "all" : "approved";
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
        approved: view === "all" ? undefined : String(view !== "denied"),
        review: view === "pending" ? "pending" : undefined,
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
    window.location.hash = approvalsHref({ approved: query.approved, review: query.review, range: query.range, user_id: query.user_id, ...next });
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
              ["pending", "보안팀 검토 대기", undefined, "pending"],
              ["approved", "승인한 것", undefined, undefined],
              ["denied", "거절·시간 초과", "false", undefined],
              ["all", "전체", "all", undefined],
            ] as const
          ).map(([k, label, v, rv]) => (
            <button key={k} className={k === view ? "on" : ""} aria-pressed={k === view} onClick={() => go({ approved: v, review: rv })}>
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

      <FatiguePanel api={api} range={range} />

      {error && <ErrorBox error={error} />}
      {!loading && !error && rows.length === 0 && <Empty>이 조건의 승인 기록이 없습니다.</Empty>}
      {view === "pending" &&
        rows.map((a) => <ReviewCard key={a.event_id} api={api} a={a} admin={role === "admin"} onDone={() => void load(0)} />)}
      {rows.length > 0 && view !== "pending" && (
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
                <th>보안팀 검토</th>
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
      <td className="nowrap">
        <ReviewChip a={a} />
      </td>
      <td className="num">{waitText(a.wait_ms)}</td>
    </tr>
  );
}

function ReviewChip({ a }: { a: Approval }) {
  const r = reviewText(a);
  if (r.tone === "none") return <span className="muted small">-</span>;
  const cls = r.tone === "ok" ? "chip" : r.tone === "bad" ? "chip chip-bad" : "chip chip-warn";
  return (
    <span className={cls} title={a.review?.reason}>
      {r.label}
    </span>
  );
}

// One approved high/critical call: what ran, why it asked, and security's verdict. "문제 있음" is
// followed by a response from the finding page (block the person or the conversation).
function ReviewCard({ api, a, admin, onDone }: { api: Api; a: Approval; admin: boolean; onDone: () => void }) {
  const [by, setBy] = useState("");
  const [reason, setReason] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const ready = by.trim() !== "" && reason.trim() !== "";
  const who = approverText(a);
  const submit = async (status: "ok" | "problem") => {
    setMsg(null);
    try {
      await api.reviewApproval(a.event_id, { status, by, reason });
      onDone();
    } catch (e) {
      setMsg(e instanceof ApiError ? e.message : String(e));
    }
  };
  return (
    <div className="card">
      <div className="page-head">
        <h3>
          {a.max_severity && <SeverityBadge severity={a.max_severity} />} {a.user_id} · <span className="mono">{a.tool}</span>
        </h3>
        <span className="muted small" title={formatTime(a.ts)}>
          {relativeTime(a.ts)} 승인 · {who.who}
          {who.other && <span className="tag warn">본인 아님</span>}
        </span>
      </div>
      <pre className="json">{a.held_call ? JSON.stringify(a.held_call.arguments, null, 2) : "(보류된 호출 기록 없음)"}</pre>
      <p className="small">
        {a.asked_by.length === 0
          ? a.rule_ids.join(", ")
          : a.asked_by.map((f) => (
              <a key={f.finding_id} className="side" href={`#/findings/${encodeURIComponent(f.finding_id)}`}>
                {f.title}
              </a>
            ))}
        <a className="side" href={timelineHref({ session_id: a.session_id })}>
          대화 타임라인
        </a>
      </p>
      {admin ? (
        <>
          <div className="filters">
            <label>
              누가
              <input value={by} onChange={(e) => setBy(e.target.value)} placeholder="예: secops@corp.test" />
            </label>
            <label className="grow">
              왜
              <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="검토 의견 (문제 있음이면 이어서 Finding 화면에서 차단)" />
            </label>
          </div>
          <div className="editor-actions">
            <button className="primary" disabled={!ready} onClick={() => void submit("ok")}>
              확인함
            </button>
            <button className="primary danger" disabled={!ready} onClick={() => void submit("problem")}>
              문제 있음
            </button>
          </div>
          {msg && (
            <p className="error" role="alert">
              {msg}
            </p>
          )}
        </>
      ) : (
        <p className="muted small">검토는 관리자 토큰으로 로그인해야 할 수 있습니다.</p>
      )}
    </div>
  );
}

const RANGE_DAYS: Record<string, number> = { "24h": 1, "7d": 7, "30d": 30, all: 90 };
const pct = (x: number | null) => (x === null ? "–" : `${Math.round(x * 100)}%`);
const secs = (x: number | null) => (x === null ? "–" : x < 60 ? `${x}초` : `${Math.round(x / 60)}분`);

// Approval fatigue (KISA agentic AI ZT guide C2; 금융보안원 ⑭): asking too often turns approval into a reflex.
function FatiguePanel({ api, range }: { api: Api; range: string }) {
  const days = RANGE_DAYS[range] ?? 7;
  const [m, setM] = useState<ApprovalMetrics | null>(null);
  const [error, setError] = useState<Error | null>(null);
  useEffect(() => {
    setM(null);
    api.approvalMetrics(days).then(setM, setError);
  }, [api, days]);
  if (error) return <ErrorBox error={error} />;
  if (!m) return <Loading />;
  const candidates = m.repeated.filter((t) => t.automation_candidate);
  return (
    <div className="card">
      <h2>승인 피로 지표 (최근 {m.window_days}일)</h2>
      <p className="muted small">
        승인 요청이 너무 잦으면 내용을 읽지 않고 누르게 됩니다. 5초 안에 승인한 비율이 높거나 거의 늘 승인되는 반복 요청은 룰을 조정할 후보입니다(조정은 직접 결정).
      </p>
      <ChannelTiles title="사용자 승인 (에이전트 확인 창)" s={m.user} />
      <ChannelTiles title="보안팀 승인 (콘솔)" s={m.security} />
      {candidates.length > 0 && (
        <table className="small">
          <thead>
            <tr>
              <th>자동화·룰 조정 후보</th>
              <th>툴</th>
              <th className="num">요청</th>
              <th className="num">승인율</th>
              <th className="num">사람</th>
            </tr>
          </thead>
          <tbody>
            {candidates.map((t) => (
              <tr key={`${t.channel}-${t.tool}-${t.rule_ids.join(",")}`}>
                <td>{t.rule_ids.join(", ") || "–"}</td>
                <td>{t.tool}</td>
                <td className="num">{t.requests}</td>
                <td className="num">{pct(t.approval_rate)}</td>
                <td className="num">{t.people}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function ChannelTiles({ title, s }: { title: string; s: ChannelStats }) {
  const fastHigh = (s.fast_approval_rate ?? 0) >= 0.5 && s.approved >= 5;
  return (
    <>
      <h3 className="small">{title}</h3>
      <div className="tiles">
        <div className="tile">
          <div className="tile-label">요청</div>
          <div className="tile-value">{s.requests.toLocaleString("ko-KR")}</div>
          <div className="tile-note muted">승인 {s.approved} · 거절 {s.denied} · 무응답 {s.unanswered}</div>
        </div>
        <div className="tile">
          <div className="tile-label">반려율</div>
          <div className="tile-value">{pct(s.rejection_rate)}</div>
        </div>
        <div className="tile">
          <div className="tile-label">승인 소요 시간 (중앙값)</div>
          <div className="tile-value">{secs(s.median_wait_s)}</div>
          <div className="tile-note muted">상위 10%: {secs(s.p90_wait_s)}</div>
        </div>
        <div className={`tile${fastHigh ? " tile-alert" : ""}`}>
          <div className="tile-label">5초 안에 승인</div>
          <div className="tile-value">{pct(s.fast_approval_rate)}</div>
          <div className="tile-note muted">{s.fast_approvals}건</div>
        </div>
      </div>
    </>
  );
}
