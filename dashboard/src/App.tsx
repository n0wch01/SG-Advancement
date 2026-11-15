import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";

import { Api, ApiError, loadToken, saveToken } from "./api";
import { Icon, type IconName } from "./components/Icon";
import { findingsHref, overviewHref, parseHash, type Route } from "./format";
import type { FindingFeedCache } from "./findingFeed";
import { Actions } from "./pages/Actions";
import { Approvals } from "./pages/Approvals";
import { Security } from "./pages/Security";
import { FindingDetail } from "./pages/FindingDetail";
import { Findings } from "./pages/Findings";
import { Inventory } from "./pages/Inventory";
import { Overview } from "./pages/Overview";
import { Policy } from "./pages/Policy";
import { Timeline } from "./pages/Timeline";
import type { Role } from "./types";

const NAVIGATION: { label: string; items: { page: Route["page"]; label: string; href: string; icon: IconName }[] }[] = [
  { label: "워크스페이스", items: [
    { page: "overview", label: "개요", href: "#/", icon: "overview" },
    { page: "findings", label: "탐지", href: "#/findings", icon: "findings" },
    { page: "timeline", label: "타임라인", href: "#/timeline", icon: "timeline" },
    { page: "inventory", label: "인벤토리", href: "#/inventory", icon: "inventory" },
  ] },
  { label: "보안 운영", items: [
    { page: "security", label: "보안 승인", href: "#/security", icon: "security" },
    { page: "approvals", label: "승인 감사", href: "#/approvals", icon: "approvals" },
    { page: "actions", label: "대응", href: "#/actions", icon: "actions" },
    { page: "policy", label: "정책", href: "#/policy", icon: "policy" },
  ] },
];

function useTheme() {
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    try {
      return localStorage.getItem("sga-dashboard-theme") === "light" ? "light" : "dark";
    } catch {
      return "dark";
    }
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("sga-dashboard-theme", theme);
    } catch {
      // The theme still works when storage is unavailable.
    }
  }, [theme]);
  return { theme, toggleTheme: () => setTheme((current) => current === "dark" ? "light" : "dark") };
}

function Brand() {
  return (
    <a className="brand" href="#/">
      <span className="brand-mark"><Icon name="shield" /></span>
      <span>SG Advance<span className="brand-caption">AGENT SECURITY</span></span>
    </a>
  );
}

function ThemeButton({ theme, onToggle }: { theme: "dark" | "light"; onToggle: () => void }) {
  const label = theme === "dark" ? "밝은 테마로 전환" : "어두운 테마로 전환";
  return (
    <button type="button" className="theme-toggle" onClick={onToggle} aria-label={label} title={label}>
      <Icon name={theme === "dark" ? "sun" : "moon"} />
    </button>
  );
}

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
  const findingFeeds = useMemo<FindingFeedCache>(() => new Map(), [api]);
  const route = useRoute();
  const lastOverview = useRef("#/");
  const lastFindings = useRef("#/findings");
  if (route.page === "overview") lastOverview.current = overviewHref(route.query);
  if (route.page === "findings") lastFindings.current = findingsHref(route.query);
  const { theme, toggleTheme } = useTheme();
  const activePage = route.page === "finding" ? "findings" : route.page;
  const pageLabel = NAVIGATION.flatMap((group) => group.items).find((item) => item.page === activePage)?.label ?? "개요";

  useLayoutEffect(() => {
    if (route.page !== "findings") window.scrollTo(0, 0);
  }, [route.page, route.page === "finding" ? route.id : null]);

  useEffect(() => {
    const previous = window.history.scrollRestoration;
    window.history.scrollRestoration = "manual";
    return () => { window.history.scrollRestoration = previous; };
  }, []);

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
    findingFeeds.forEach((feed) => feed.stop());
    findingFeeds.clear();
    lastOverview.current = "#/";
    lastFindings.current = "#/findings";
    saveToken(null);
    setToken(null);
    setRole(null);
  }

  if (!api) {
    return (
      <Login
        theme={theme}
        toggleTheme={toggleTheme}
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
      <a className="skip-link" href="#main-content" onClick={(event) => {
        event.preventDefault();
        document.getElementById("main-content")?.focus();
      }}>본문으로 이동</a>
      <aside className="sidebar">
        <Brand />
        <nav className="primary-nav" aria-label="메인 메뉴">
          {NAVIGATION.map((group) => (
            <div className="nav-group" key={group.label}>
              <p className="nav-label">{group.label}</p>
              {group.items.map((item) => (
                <a href={item.page === "overview" ? lastOverview.current : item.page === "findings" ? lastFindings.current : item.href} key={item.page} className={activePage === item.page ? "on" : ""} aria-current={activePage === item.page ? "page" : undefined}>
                  <Icon name={item.icon} /><span>{item.label}</span>
                </a>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <p className="workspace-note">
            <span className={`status-dot${role ? "" : " pending"}`} />
            {role ? "인증된 관제 세션" : "권한 확인 중"}
          </p>
          <button className="logout" onClick={logout}><Icon name="logout" />로그아웃</button>
        </div>
      </aside>
      <div className="workspace">
        <header className="top">
          <div className="breadcrumb">
            <span>워크스페이스</span><span aria-hidden="true">/</span><span>{pageLabel}</span>
            {route.page === "finding" && <><span aria-hidden="true">/</span><span>사건 상세</span></>}
          </div>
          <div className="who">
            {role && <span className={`role role-${role}`}>{role === "viewer" ? "읽기 전용" : "관리자"}</span>}
            <ThemeButton theme={theme} onToggle={toggleTheme} />
          </div>
        </header>
        <div className="workspace-content">
          {role === "admin" && (
            <p className="banner" role="note">
              관리자 토큰으로 로그인했습니다(정책 편집 가능). 보기만 할 때는 읽기 전용 대시보드 토큰(SGA_DASHBOARD_TOKEN)을 쓰세요.
            </p>
          )}
          <main id="main-content" tabIndex={-1}>
            {route.page === "overview" && <Overview api={api} query={route.query ?? {}} />}
            {route.page === "findings" && <Findings api={api} query={route.query} cache={findingFeeds} />}
            {route.page === "finding" && <FindingDetail key={route.id} api={api} id={route.id} role={role} query={route.query ?? {}} />}
            {route.page === "approvals" && <Approvals api={api} query={route.query} role={role} />}
            {route.page === "inventory" && <Inventory api={api} />}
            {route.page === "timeline" && <Timeline api={api} query={route.query} />}
            {route.page === "policy" && <Policy api={api} role={role} query={route.query} />}
            {route.page === "actions" && <Actions api={api} role={role} />}
            {route.page === "security" && <Security api={api} role={role} />}
          </main>
        </div>
      </div>
    </div>
  );
}

function Login({ onLogin, theme, toggleTheme }: { onLogin: (token: string, role: Role) => void; theme: "dark" | "light"; toggleTheme: () => void }) {
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div className="login">
      <div className="login-appearance"><ThemeButton theme={theme} onToggle={toggleTheme} /></div>
      <div className="login-content">
      <Brand />
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
        <div><p className="eyebrow">Security workspace</p><h1>관제 콘솔 로그인</h1></div>
        <p className="muted">에이전트의 행동과 보안 상태를 한곳에서 확인하세요.</p>
        <label>
          대시보드 토큰
          <input type="password" autoComplete="off" placeholder="대시보드 토큰을 입력하세요" value={value} onChange={(e) => setValue(e.target.value)} required />
        </label>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <button type="submit" disabled={busy || !value.trim()}>
          {busy ? "확인 중…" : "로그인"}
        </button>
        <p className="login-note">읽기 전용 대시보드 토큰으로 접속합니다.<br />토큰은 이 탭에만 보관되며 탭을 닫으면 사라집니다.</p>
      </form>
      <p className="login-footer">SG-Advance · 코딩 에이전트 통합 보안 관제</p>
      </div>
    </div>
  );
}
