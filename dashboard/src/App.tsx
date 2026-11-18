import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";

import { Api, ApiError, loadToken, saveToken } from "./api";
import { IdentityContext, PAGE_PERMISSIONS } from "./access";
import { Icon, type IconName } from "./components/Icon";
import { findingsHref, overviewHref, parseHash, type Route } from "./format";
import type { FindingFeedCache } from "./findingFeed";
import { Actions } from "./pages/Actions";
import { Access } from "./pages/Access";
import { Approvals } from "./pages/Approvals";
import { FindingDetail } from "./pages/FindingDetail";
import { Findings } from "./pages/Findings";
import { Inventory } from "./pages/Inventory";
import { Overview } from "./pages/Overview";
import { Policy } from "./pages/Policy";
import { Timeline } from "./pages/Timeline";
import type { Identity } from "./types";

const NAVIGATION: { label: string; items: { page: Route["page"]; label: string; href: string; icon: IconName }[] }[] = [
  { label: "워크스페이스", items: [
    { page: "overview", label: "개요", href: "#/", icon: "overview" },
    { page: "findings", label: "탐지", href: "#/findings", icon: "findings" },
    { page: "timeline", label: "타임라인", href: "#/timeline", icon: "timeline" },
    { page: "inventory", label: "인벤토리", href: "#/inventory", icon: "inventory" },
  ] },
  { label: "보안 운영", items: [
    { page: "approvals", label: "승인 감사", href: "#/approvals", icon: "approvals" },
    { page: "actions", label: "대응", href: "#/actions", icon: "actions" },
    { page: "policy", label: "정책", href: "#/policy", icon: "policy" },
    { page: "access", label: "접근 관리", href: "#/access", icon: "shield" },
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
  const [identity, setIdentity] = useState<Identity | null>(null);
  const role = identity?.role ?? null;
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
  const canView = !!identity && (!PAGE_PERMISSIONS[route.page] || identity.permissions.includes(PAGE_PERMISSIONS[route.page]));
  const scopeKey = JSON.stringify(identity?.bindings ?? []) + identity?.user_id;

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
    let active = true;
    const refresh = () => api.whoami().then(
      (r) => { if (active) setIdentity(r); },
      (e) => { if (active && e instanceof ApiError && e.status === 401) logout(); },
    );
    void refresh();
    const timer = setInterval(() => void refresh(), 30_000);
    window.addEventListener("focus", refresh);
    return () => { active = false; clearInterval(timer); window.removeEventListener("focus", refresh); };
  }, [api]);

  useEffect(() => {
    findingFeeds.forEach((feed) => feed.stop());
    findingFeeds.clear();
  }, [scopeKey, findingFeeds]);

  useEffect(() => {
    if (!api) return;
    window.addEventListener("sga-unauthorized", logout);
    return () => window.removeEventListener("sga-unauthorized", logout);
  }, [api]);

  function logout() {
    findingFeeds.forEach((feed) => feed.stop());
    findingFeeds.clear();
    lastOverview.current = "#/";
    lastFindings.current = "#/findings";
    saveToken(null);
    setToken(null);
    setIdentity(null);
  }

  if (!api) {
    return (
      <Login
        theme={theme}
        toggleTheme={toggleTheme}
        onLogin={(t, r) => {
          saveToken(t);
          setToken(t);
          setIdentity(r);
        }}
      />
    );
  }

  return (
    <IdentityContext.Provider value={identity}><div className="shell">
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
              {group.items.filter((item) => !PAGE_PERMISSIONS[item.page] || identity?.permissions.includes(PAGE_PERMISSIONS[item.page])).map((item) => (
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
            {identity && <span className={`role role-${role}`}>{identity.display_name} · {role === "viewer" ? "공용 조회" : role === "admin" ? "공용 관리자" : "개별 계정"}</span>}
            <ThemeButton theme={theme} onToggle={toggleTheme} />
          </div>
        </header>
        <div className="workspace-content">
          {role === "admin" && (
            <p className="banner" role="note">
              초기 설정용 공용 관리자 세션입니다. 접근 관리에서 개인 계정과 필요한 권한을 발급하세요.
            </p>
          )}
          <main id="main-content" tabIndex={-1} key={scopeKey}>
            {!identity ? <p>권한 확인 중…</p> : !canView ? <p className="notice">이 화면을 조회할 권한이 없습니다. <a href="#/access">내 프로젝트와 세션 확인</a></p> : <>
            {route.page === "overview" && <Overview api={api} query={route.query ?? {}} />}
            {route.page === "findings" && <Findings api={api} query={route.query} cache={findingFeeds} />}
            {route.page === "finding" && <FindingDetail key={route.id} api={api} id={route.id} role={role} query={route.query ?? {}} />}
            {route.page === "approvals" && <Approvals api={api} query={route.query} role={role} />}
            {route.page === "inventory" && <Inventory api={api} />}
            {route.page === "timeline" && <Timeline api={api} query={route.query} />}
            {route.page === "policy" && <Policy api={api} role={role} query={route.query} />}
            {route.page === "actions" && <Actions api={api} role={role} />}
            {route.page === "access" && <Access api={api} />}
            </>}
          </main>
        </div>
      </div>
    </div></IdentityContext.Provider>
  );
}

function Login({ onLogin, theme, toggleTheme }: { onLogin: (token: string, identity: Identity) => void; theme: "dark" | "light"; toggleTheme: () => void }) {
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
            const identity = await new Api(value.trim()).whoami();
            onLogin(value.trim(), identity);
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
          개인 API 토큰
          <input type="password" autoComplete="off" placeholder="발급받은 토큰을 입력하세요" value={value} onChange={(e) => setValue(e.target.value)} required />
        </label>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <button type="submit" disabled={busy || !value.trim()}>
          {busy ? "확인 중…" : "로그인"}
        </button>
        <p className="login-note">개인 토큰 또는 기존 공용 토큰으로 접속합니다.<br />토큰은 이 탭에만 보관되며 탭을 닫으면 사라집니다.</p>
      </form>
      <p className="login-footer">SG-Advance · 코딩 에이전트 통합 보안 관제</p>
      </div>
    </div>
  );
}
