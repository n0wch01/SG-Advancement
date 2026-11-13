import { useEffect, useState } from "react";

import { ApiError, type Api } from "../api";
import { SeverityBadge } from "../components/Severity";
import { Empty, ErrorBox, Loading } from "../components/States";
import {
  SECURITY_OUTCOME_LABEL,
  SECURITY_STATUS_LABEL,
  formatTime,
  relativeTime,
  remainingText,
  timelineHref,
} from "../format";
import type { Role, SecurityApproval } from "../types";

const REFRESH_MS = 2000;
const STATUS_TONE: Record<string, string> = { approved: "good", denied: "bad", expired: "neutral", pending: "warn" };

// Security approval queue (M11, decision 2026-11-12): a rule with the "보안팀 승인" response holds the
// tool call on the device until someone here decides; nobody within 5 minutes → denied.
export function Security({ api, role }: { api: Api; role: Role | null }) {
  const [rows, setRows] = useState<SecurityApproval[] | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [now, setNow] = useState(() => new Date());
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let live = true;
    const load = () =>
      api
        .securityApprovals()
        .then((r) => live && (setRows(r), setError(null)))
        .catch((e) => live && setError(e as Error));
    void load();
    const poll = setInterval(load, REFRESH_MS);
    const clock = setInterval(() => setNow(new Date()), 1000);
    return () => {
      live = false;
      clearInterval(poll);
      clearInterval(clock);
    };
  }, [api, tick]);

  const pending = (rows ?? []).filter((r) => r.status === "pending" && new Date(r.expires_at) > now);
  const done = (rows ?? []).filter((r) => !pending.includes(r));
  return (
    <section>
      <div className="page-head">
        <h1>보안 승인</h1>
      </div>
      <p className="muted small">
        룰의 대응이 "보안팀 승인"이면 툴 호출이 그 장비에서 멈추고 여기서 결정을 기다립니다. 5분 안에 아무도 결정하지 않으면 거부됩니다.
        결정은 1~2초 안에 장비에 닿습니다. 어떤 룰을 보안팀 승인으로 둘지는 정책 화면에서 정합니다.
      </p>
      {error && <ErrorBox error={error} />}
      {!rows && !error && <Loading />}
      {rows && (
        <>
          <h2>결정 대기 ({pending.length})</h2>
          {pending.length === 0 && (
            <div className="card">
              <Empty>기다리는 호출이 없습니다.</Empty>
            </div>
          )}
          {pending.map((r) => (
            <Pending key={r.id} api={api} r={r} now={now} admin={role === "admin"} onDone={() => setTick((t) => t + 1)} />
          ))}
          <h2>최근 결정</h2>
          <div className="card flush">
            <table>
              <thead>
                <tr>
                  <th>요청</th>
                  <th>사람 · 툴</th>
                  <th>결정</th>
                  <th>실제 결과</th>
                  <th>누가 · 왜</th>
                </tr>
              </thead>
              <tbody>
                {done.length === 0 && (
                  <tr>
                    <td colSpan={5}>
                      <Empty>아직 결정된 요청이 없습니다.</Empty>
                    </td>
                  </tr>
                )}
                {done.map((r) => (
                  <tr key={r.id}>
                    <td className="nowrap small" title={formatTime(r.created_at)}>
                      {relativeTime(r.created_at)}
                    </td>
                    <td className="small">
                      {r.user_id} · <span className="mono">{r.tool}</span>
                      <div className="muted mono">{r.rule_ids.join(", ")}</div>
                    </td>
                    <td className="small">
                      <span className={`chip chip-${STATUS_TONE[r.status] ?? "neutral"}`}>{SECURITY_STATUS_LABEL[r.status] ?? r.status}</span>
                    </td>
                    <td className="small">{r.outcome ? (SECURITY_OUTCOME_LABEL[r.outcome] ?? r.outcome) : "보고 없음"}</td>
                    <td className="small">
                      {r.decided_by ?? "-"}
                      {r.decision_reason && <div className="muted">“{r.decision_reason}”</div>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}

function Pending({ api, r, now, admin, onDone }: { api: Api; r: SecurityApproval; now: Date; admin: boolean; onDone: () => void }) {
  const [by, setBy] = useState("");
  const [reason, setReason] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const ready = by.trim() !== "" && reason.trim() !== "";
  const decide = async (decision: "approve" | "deny") => {
    setMsg(null);
    try {
      await api.decideSecurity(r.id, { decision, by, reason });
      onDone();
    } catch (e) {
      setMsg(e instanceof ApiError ? e.message : String(e));
    }
  };
  return (
    <div className="card">
      <div className="page-head">
        <h3>
          {r.severity && <SeverityBadge severity={r.severity} />} {r.user_id} · <span className="mono">{r.tool}</span>
        </h3>
        <span className="chip chip-warn" title={`${formatTime(r.expires_at)}까지`}>
          남은 시간 {remainingText(r.expires_at, now)}
        </span>
      </div>
      <p>{r.reason}</p>
      <pre className="json">{r.arguments_preview || "(인자 없음)"}</pre>
      <p className="small muted">
        <span className="mono">{r.rule_ids.join(", ")}</span> · 장비 {r.device_id} · 대화 <span className="mono">{r.session_id}</span>
        <a className="side" href={timelineHref({ session_id: r.session_id })}>
          대화 타임라인
        </a>
        {r.finding_ids[0] && (
          <a className="side" href={`#/findings/${encodeURIComponent(r.finding_ids[0])}`}>
            Finding
          </a>
        )}
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
              <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="결정 사유 (거부 사유는 에이전트에게도 전달됩니다)" />
            </label>
          </div>
          <div className="editor-actions">
            <button className="primary" disabled={!ready} onClick={() => void decide("approve")}>
              승인
            </button>
            <button className="primary danger" disabled={!ready} onClick={() => void decide("deny")}>
              거부
            </button>
          </div>
          {msg && (
            <p className="error" role="alert">
              {msg}
            </p>
          )}
        </>
      ) : (
        <p className="muted small">결정은 관리자 토큰으로 로그인해야 할 수 있습니다.</p>
      )}
    </div>
  );
}
