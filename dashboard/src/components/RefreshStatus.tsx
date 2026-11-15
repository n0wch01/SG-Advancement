import { useEffect, useState } from "react";

import { formatTime } from "../format";

export interface RefreshStatusProps {
  updatedAt: string | null;
  refreshing: boolean;
  error: Error | null;
  paused: boolean;
  onTogglePause: () => void;
  onRefresh: () => unknown;
  intervalMs?: number;
}

export function RefreshStatus({ updatedAt, refreshing, error, paused, onTogglePause, onRefresh, intervalMs = 3000 }: RefreshStatusProps) {
  const [now, setNow] = useState(Date.now);
  const [visible, setVisible] = useState(() => document.visibilityState === "visible");
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    const onVisibility = () => setVisible(document.visibilityState === "visible");
    document.addEventListener("visibilitychange", onVisibility);
    return () => { clearInterval(timer); document.removeEventListener("visibilitychange", onVisibility); };
  }, []);
  const age = updatedAt ? Math.max(0, Math.floor((now - new Date(updatedAt).getTime()) / 1000)) : null;
  const stale = age !== null && age >= 15;
  const label = error ? (updatedAt ? "갱신 실패 · 마지막 데이터 유지" : "불러오기 실패")
    : paused ? "자동 갱신 일시정지"
      : !visible ? "탭 비활성 · 자동 갱신 대기"
        : stale ? "최신 데이터 확인 지연"
          : `${intervalMs / 1000}초마다 자동 갱신`;
  return (
    <div className={`refresh-status${error || stale ? " stale" : ""}`} aria-busy={refreshing}>
      <div className="refresh-status-copy">
        <span className="refresh-status-label" role="status"><span className={`status-dot${paused ? " pending" : ""}`} />{label}</span>
        <span className="refresh-timestamp">
          {updatedAt ? <>마지막 성공 <time dateTime={updatedAt}>{formatTime(updatedAt)}</time> · {age! < 60 ? `${age}초 전` : `${Math.floor(age! / 60)}분 전`}</> : "갱신 성공 기록 없음"}
        </span>
      </div>
      <div className="refresh-controls">
        <button type="button" className="quiet-button" onClick={onTogglePause} aria-pressed={paused}>{paused ? "자동 갱신 재개" : "일시정지"}</button>
        <button type="button" className="quiet-button" onClick={() => void onRefresh()} disabled={refreshing}>새로고침</button>
      </div>
    </div>
  );
}
