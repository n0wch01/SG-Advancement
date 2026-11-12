import { useState } from "react";

import { ApiError, type Api } from "../api";
import { Empty, ErrorBox, Loading } from "../components/States";
import { ACTION_STATUS_LABEL, REMOTE_ACTION_LABEL, activeBlocks, formatTime, relativeTime, timelineHref } from "../format";
import type { RemoteAction, Role } from "../types";
import { useAsync } from "../useAsync";

const STATUS_TONE: Record<string, string> = { done: "good", failed: "bad", pending: "warn", delivered: "warn" };

export function Actions({ api, role }: { api: Api; role: Role | null }) {
  const [tick, setTick] = useState(0);
  const { data, error, loading } = useAsync(() => api.actions(), [api, tick]);
  const admin = role === "admin";
  return (
    <section>
      <div className="page-head">
        <h1>원격 대응</h1>
        <button className="link" onClick={() => setTick((t) => t + 1)}>
          새로고침
        </button>
      </div>
      <p className="muted small">
        보안팀이 장비에 보낸 대응과 결과입니다. 센서가 몇 초 안에 받아 실행하고 결과를 보고합니다. 대화·사람 차단은 게이트웨이 플러그인이 이후 툴 호출을 실행 전에
        막습니다. 실행 중단은 센서에 관리자 권한이 없어(결정 B) 다른 사람의 실행이면 실패로 기록됩니다. 새 대응은 Finding 상세에서 보냅니다.
      </p>
      {error && <ErrorBox error={error} />}
      {loading && !data && <Loading />}
      {data && (
        <>
          <div className="card">
            <h2>지금 차단 중</h2>
            <Blocks api={api} admin={admin} actions={data} onDone={() => setTick((t) => t + 1)} />
          </div>
          <div className="card flush">
            <table>
              <thead>
                <tr>
                  <th>보낸 시각</th>
                  <th>대응</th>
                  <th>대상</th>
                  <th>장비</th>
                  <th>상태</th>
                  <th>누가 · 왜</th>
                </tr>
              </thead>
              <tbody>
                {data.length === 0 && (
                  <tr>
                    <td colSpan={6}>
                      <Empty>보낸 대응이 없습니다.</Empty>
                    </td>
                  </tr>
                )}
                {data.map((a) => (
                  <tr key={a.id}>
                    <td className="nowrap" title={formatTime(a.created_at)}>
                      {relativeTime(a.created_at)}
                    </td>
                    <td>{REMOTE_ACTION_LABEL[a.action] ?? a.action}</td>
                    <td className="mono small">
                      {a.target}
                      {a.finding_id && (
                        <div>
                          <a href={`#/findings/${encodeURIComponent(a.finding_id)}`}>근거 Finding</a>
                        </div>
                      )}
                    </td>
                    <td className="small">{a.device_id}</td>
                    <td className="small">
                      <span className={`chip chip-${STATUS_TONE[a.status] ?? "neutral"}`}>{ACTION_STATUS_LABEL[a.status] ?? a.status}</span>
                      {a.result_detail && <div className="muted">{a.result_detail}</div>}
                    </td>
                    <td className="small">
                      {a.created_by}
                      <div className="muted">“{a.reason}”</div>
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

function Blocks({ api, admin, actions, onDone }: { api: Api; admin: boolean; actions: RemoteAction[]; onDone: () => void }) {
  const blocks = activeBlocks(actions);
  const [by, setBy] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  if (blocks.length === 0) return <Empty>차단 중인 대화나 사람이 없습니다.</Empty>;
  return (
    <>
      <ul className="feed">
        {blocks.map((b) => (
          <li key={b.id}>
            <span className="chip chip-bad">{b.action === "block_session" ? "대화" : "사람"}</span>
            <span className="mono small">{b.target}</span>
            <a className="small" href={timelineHref(b.action === "block_session" ? { session_id: b.target } : { user_id: b.target })}>
              타임라인
            </a>
            <span className="muted small">
              {b.device_id} · {ACTION_STATUS_LABEL[b.status]} · {relativeTime(b.created_at)}
            </span>
            {admin && (
              <button
                className="link"
                disabled={!by.trim() || !reason.trim()}
                onClick={async () => {
                  setError(null);
                  try {
                    await api.createAction({
                      device_id: b.device_id,
                      action: b.action === "block_session" ? "unblock_session" : "unblock_user",
                      target: b.target,
                      by,
                      reason,
                    });
                    onDone();
                  } catch (e) {
                    setError(e instanceof ApiError ? e.message : String(e));
                  }
                }}
              >
                해제
              </button>
            )}
          </li>
        ))}
      </ul>
      {admin && (
        <div className="filters">
          <label>
            누가
            <input value={by} onChange={(e) => setBy(e.target.value)} />
          </label>
          <label>
            왜 (해제 사유)
            <input value={reason} onChange={(e) => setReason(e.target.value)} />
          </label>
        </div>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </>
  );
}
