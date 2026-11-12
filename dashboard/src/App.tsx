import { useEffect, useMemo, useState } from "react";

import { Api, ApiError, loadToken, saveToken } from "./api";
import { parseHash, type Route } from "./format";
import { Approvals } from "./pages/Approvals";
import { FindingDetail } from "./pages/FindingDetail";
import { Findings } from "./pages/Findings";
import { Inventory } from "./pages/Inventory";
import { Overview } from "./pages/Overview";
import type { Role } from "./types";

function useRoute(): Route {
  const [route, setRoute] = useState(() => parseHash(window.location.hash));
  useEffect(() => {
    const on = () => setRoute(parseHash(window.location.hash));
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

export function App() {
  const [token, setToken] = useState<string | null>(() => loadToken());
  const [role, setRole] = useState<Role | null>(null);
  const api = useMemo(() => (token ? new Api(token) : null), [token]);
  const route = useRoute();

  useEffect(() => {
    if (!api) return;
    api.whoami().then(
      (r) => setRole(r.role),
      (e) => {
        if (e instanceof ApiError && e.status === 401) logout();
      },
    );
  }, [api]);

  function logout() {
    saveToken(null);
    setToken(null);
    setRole(null);
  }

  if (!api) {
    return (
      <Login
        onLogin={(t, r) => {
          saveToken(t);
          setToken(t);
          setRole(r);
        }}
      />
    );
  }

  return (
    <div className="shell">
      <header className="top">
        <a className="brand" href="#/">
          SGA-Dashboard
        </a>
        <nav>
          <a href="#/" className={route.page === "overview" ? "on" : ""}>
            개요
          </a>
          <a href="#/findings" className={route.page === "findings" || route.page === "finding" ? "on" : ""}>
            Finding
          </a>
          <a href="#/approvals" className={route.page === "approvals" ? "on" : ""}>
            승인 감사
          </a>
          <a href="#/inventory" className={route.page === "inventory" ? "on" : ""}>
            인벤토리
          </a>
        </nav>
        <div className="who">
          {role && <span className={`role role-${role}`}>{role === "viewer" ? "읽기 전용" : "관리자"}</span>}
          <button className="link" onClick={logout}>
            로그아웃
          </button>
        </div>
      </header>
      {role === "admin" && (
        <p className="banner" role="note">
          관리자 토큰으로 로그인했습니다. 화면을 볼 때는 읽기 전용 대시보드 토큰(SGA_DASHBOARD_TOKEN)을 쓰세요.
        </p>
      )}
      <main>
        {route.page === "overview" && <Overview api={api} />}
        {route.page === "findings" && <Findings api={api} query={route.query} />}
        {route.page === "finding" && <FindingDetail api={api} id={route.id} />}
        {route.page === "approvals" && <Approvals api={api} query={route.query} />}
        {route.page === "inventory" && <Inventory api={api} />}
      </main>
    </div>
  );
}

function Login({ onLogin }: { onLogin: (token: string, role: Role) => void }) {
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div className="login">
      <form
        className="card"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            const { role } = await new Api(value.trim()).whoami();
            onLogin(value.trim(), role);
          } catch (err) {
            setError(err instanceof ApiError && err.status === 401 ? "토큰이 맞지 않습니다." : `접속 실패: ${(err as Error).message}`);
          } finally {
            setBusy(false);
          }
        }}
      >
        <h1>SGA-Dashboard</h1>
        <p className="muted">SG-Advance 관제 콘솔. 대시보드 토큰(읽기 전용)으로 로그인합니다. 토큰은 이 탭에만 보관되고 탭을 닫으면 사라집니다.</p>
        <label>
          대시보드 토큰
          <input type="password" autoComplete="off" value={value} onChange={(e) => setValue(e.target.value)} required />
        </label>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <button type="submit" disabled={busy || !value.trim()}>
          {busy ? "확인 중…" : "로그인"}
        </button>
      </form>
    </div>
  );
}
