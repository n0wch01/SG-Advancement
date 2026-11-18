import { useContext, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { IdentityContext, usePermission } from "../access";
import { Api } from "../api";
import type { IdentityAdministration, Project, SessionBinding } from "../types";
import { Tasks } from "./Tasks";

const ROLE_NAMES: Record<string, string> = {
  identity_admin: "계정 관리자", security_admin: "보안 정책 관리자", soc: "관제 담당자",
  developer: "개발자", qa: "QA",
};
const text = (data: FormData, key: string) => String(data.get(key) ?? "").trim();
const idPath = (id: string) => encodeURIComponent(id);

function Select({ label, name, items, optional }: { label: string; name: string; items: { id: string; name: string }[]; optional?: string }) {
  return <label>{label}<select name={name} required={!optional}>
    <option value="">{optional ?? "선택하세요"}</option>
    {items.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
  </select></label>;
}

function Form({ title, busy, children, onSubmit }: { title: string; busy: boolean; children: ReactNode; onSubmit: (event: FormEvent<HTMLFormElement>) => void }) {
  return <form className="card access-form" onSubmit={onSubmit}><h2>{title}</h2>
    <fieldset disabled={busy}>{children}<button type="submit">{busy ? "처리 중…" : "저장"}</button></fieldset>
  </form>;
}

export function Access({ api }: { api: Api }) {
  const identity = useContext(IdentityContext);
  const admin = usePermission("identity.manage");
  const register = usePermission("sessions.register");
  const respond = usePermission("response.manage");
  const [projects, setProjects] = useState<Project[]>([]);
  const [sessions, setSessions] = useState<SessionBinding[]>([]);
  const [devices, setDevices] = useState<{ device_id: string }[]>([]);
  const [management, setManagement] = useState<IdentityAdministration | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [issued, setIssued] = useState<{ token: string; expires_at: string } | null>(null);

  async function load() {
    const [p, s, d, m] = await Promise.all([
      api.projects(), api.sessions(), api.ownedDevices(), admin ? api.identityAdministration() : Promise.resolve(null),
    ]);
    setProjects(p); setSessions(s); setDevices(d); setManagement(m);
  }
  useEffect(() => { void load().catch((e) => setError(String(e))); }, [api, admin]);

  async function mutate(action: () => Promise<unknown>) {
    setBusy(true); setError(null); setMessage(null);
    try { await action(); await load(); setMessage("변경을 저장했습니다. 권한은 다음 서버 요청부터 반영됩니다."); }
    catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }
  function submit(action: (data: FormData) => Promise<unknown>) {
    return (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const form = event.currentTarget;
      const data = new FormData(form);
      void mutate(async () => { await action(data); form.reset(); });
    };
  }
  const users = management?.users.map((u) => ({ id: u.user_id, name: `${u.display_name} (${u.user_id})` })) ?? [];
  const projectOptions = projects.filter((p) => !p.disabled_at).map((p) => ({ id: p.project_id, name: p.name }));
  const deviceOptions = (management?.devices ?? devices).map((d) => ({ id: d.device_id, name: d.device_id }));
  return <>
    <div className="page-head"><div><p className="eyebrow">Identity & project access</p><h1>접근 관리</h1></div>
      <button className="link" onClick={() => void load().catch((e) => setError(String(e)))}>새로고침</button></div>
    <p className="muted">{identity?.display_name}의 프로젝트와 등록된 에이전트 세션입니다. 관제 권한과 자원 실행 권한은 별도로 확인합니다.</p>
    {error && <p className="error" role="alert">{error}</p>}
    {message && <p className="notice" role="status">{message}</p>}
    {issued && <div className="card"><h2>개인 토큰 발급 완료</h2>
      <p>지금 한 번만 표시합니다. 안전한 곳에 보관하세요. 만료: {new Date(issued.expires_at).toLocaleString()}</p>
      <label>발급된 개인 토큰<textarea readOnly value={issued.token} rows={2} autoComplete="off" /></label>
      <button onClick={() => setIssued(null)}>토큰 표시 닫기</button></div>}
    <div className="card"><h2>프로젝트</h2>
      {projects.length === 0 ? <p className="muted">배정된 프로젝트가 없습니다. 계정 관리자의 역할 배정이 필요합니다.</p> :
        <ul>{projects.map((p) => <li key={p.project_id}>{p.name} <span className="mono muted">{p.project_id}</span> · {p.environments.join(", ")}</li>)}</ul>}
      {identity?.bindings.length ? <p className="small">{identity.bindings.map((b) => `${ROLE_NAMES[b.role_id] ?? b.role_id}: ${b.project_id ?? "시스템 범위"} / ${b.environment}`).join(" · ")}</p> : null}
    </div>
    {(register || admin) && <Form title="에이전트 세션 등록" busy={busy} onSubmit={submit((data) => api.identityWrite("POST", "/sessions", {
      device_id: text(data, "device"), agent_type: text(data, "agent"), session_id: text(data, "session"),
      project_id: text(data, "project"), ...(admin ? { user_id: text(data, "user") } : {}),
    }))}>
      <p className="muted small">관리자가 사용자 소유로 등록한 장치와 배정된 프로젝트만 연결할 수 있습니다. CLI의 세션 ID를 입력하세요. 등록 이후 수집한 기록부터 적용되며 과거 기록의 범위는 바꾸지 않습니다.</p>
      {admin && <Select label="실행 사용자" name="user" items={users} />}
      <Select label="장치" name="device" items={deviceOptions} />
      <Select label="프로젝트" name="project" items={projectOptions} />
      <Select label="코딩 에이전트" name="agent" items={[{ id: "claude_code", name: "Claude Code CLI" }, { id: "codex_cli", name: "Codex CLI" }]} />
      <label>세션 ID<input name="session" required maxLength={200} autoComplete="off" /></label>
    </Form>}
    <section className="card"><h2>등록된 세션</h2><div className="table-wrap"><table><thead><tr>
      <th>프로젝트 / 사용자</th><th>장치 / 에이전트</th><th>세션</th><th>상태</th><th>작업</th>
    </tr></thead><tbody>{sessions.map((s) => <tr key={s.binding_id}>
      <td>{s.project_id}<br />{s.user_id}</td><td>{s.device_id}<br />{s.agent_type}</td><td className="mono small">{s.session_id}</td>
      <td>{s.revoked_at ? "등록 폐기" : "활성"}</td><td>{!s.revoked_at && (admin || respond || s.user_id === identity?.user_id) &&
        <button className="link" disabled={busy} onClick={() => void mutate(() => api.identityWrite("DELETE", `/sessions/${idPath(s.binding_id)}`))}>등록 폐기</button>}</td>
    </tr>)}</tbody></table></div>{sessions.length === 0 && <p className="muted">조회 가능한 등록 세션이 없습니다.</p>}</section>
    <Tasks api={api} sessions={sessions} />
    {management && <>
      <div className="access-grid">
        <Form title="사용자 생성" busy={busy} onSubmit={submit((d) => api.identityWrite("POST", "/users", { id: text(d, "id"), name: text(d, "name") }))}>
          <label>사용자 ID<input name="id" required pattern="[a-zA-Z0-9][a-zA-Z0-9._-]*" maxLength={100} /></label>
          <label>표시 이름<input name="name" required maxLength={200} /></label>
        </Form>
        <Form title="개인 API 토큰 발급" busy={busy} onSubmit={submit(async (d) => {
          const token = await api.identityWrite<{ token: string; expires_at: string }>("POST", `/users/${idPath(text(d, "user"))}/tokens`, { lifetime_seconds: Number(text(d, "hours")) * 3600 });
          setIssued(token);
        })}>
          <Select label="사용자" name="user" items={users} />
          <label>유효 시간<input name="hours" type="number" defaultValue={8} min={1} max={720} required /></label>
        </Form>
        <Form title="프로젝트 생성" busy={busy} onSubmit={submit((d) => api.identityWrite("POST", "/projects", {
          id: text(d, "id"), name: text(d, "name"), workspace_root: text(d, "root") || null,
        }))}>
          <label>프로젝트 ID<input name="id" required maxLength={100} /></label>
          <label>프로젝트 이름<input name="name" required maxLength={200} /></label>
          <label>보호할 작업 폴더 (선택)<input name="root" placeholder="서버의 전용 작업 폴더 절대 경로" /></label>
          <p className="muted small">기본 환경은 개발·테스트입니다. 운영 배포나 비밀 접근 권한은 자동으로 주어지지 않습니다.</p>
        </Form>
        <Form title="장치 사용자 지정" busy={busy} onSubmit={submit((d) => api.identityWrite("PUT", `/devices/${idPath(text(d, "device"))}/owner`, { user_id: text(d, "user") }))}>
          <Select label="장치" name="device" items={deviceOptions} /><Select label="소유 사용자" name="user" items={users} />
          <p className="muted small">사용자가 바뀌면 이 장치의 기존 세션 등록은 폐기됩니다.</p>
        </Form>
        <Form title="팀 생성" busy={busy} onSubmit={submit((d) => api.identityWrite("POST", "/teams", { id: text(d, "id"), name: text(d, "name") }))}>
          <label>팀 ID<input name="id" required maxLength={100} /></label><label>팀 이름<input name="name" required maxLength={200} /></label>
        </Form>
        <Form title="팀 구성원 변경" busy={busy} onSubmit={submit((d) => api.identityWrite("PUT", `/teams/${idPath(text(d, "team"))}/members/${idPath(text(d, "user"))}`, { enabled: text(d, "enabled") === "true" }))}>
          <Select label="팀" name="team" items={management.teams.map((t) => ({ id: t.team_id, name: t.name }))} />
          <Select label="사용자" name="user" items={users} />
          <Select label="변경" name="enabled" items={[{ id: "true", name: "구성원 추가" }, { id: "false", name: "구성원 제외" }]} />
        </Form>
        <Form title="사용자 역할 배정" busy={busy} onSubmit={submit((d) => api.identityWrite("POST", "/bindings", {
          user_id: text(d, "user"), role_id: text(d, "role"), project_id: text(d, "project") || null, environment: text(d, "environment"),
        }))}>
          <Select label="사용자" name="user" items={users} /><BindingFields management={management} projects={projectOptions} />
        </Form>
        <Form title="팀 역할 배정" busy={busy} onSubmit={submit((d) => api.identityWrite("POST", "/bindings", {
          team_id: text(d, "team"), role_id: text(d, "role"), project_id: text(d, "project") || null, environment: text(d, "environment"),
        }))}>
          <Select label="팀" name="team" items={management.teams.map((t) => ({ id: t.team_id, name: t.name }))} />
          <BindingFields management={management} projects={projectOptions} />
        </Form>
      </div>
      <RoleEditor api={api} management={management} busy={busy} submit={submit} />
      <section className="card"><h2>계정 상태</h2><ul className="feed">{management.users.map((u) => <li key={u.user_id}>
        <span>{u.display_name} · {u.disabled_at ? "사용 중지" : "활성"}</span>
        <button className="link" disabled={busy} onClick={() => void mutate(() => api.identityWrite("PUT", `/users/${idPath(u.user_id)}/enabled`, { enabled: !!u.disabled_at }))}>{u.disabled_at ? "사용 재개" : "사용 중지"}</button>
      </li>)}</ul><p className="muted small">중지한 계정은 다음 요청부터 거부하고 기존 세션 등록도 폐기합니다. 재개 시 세션을 새로 등록해야 합니다.</p></section>
      <section className="card"><h2>역할 배정 내역</h2><ul className="feed">{management.bindings.map((b) => <li key={b.binding_id}>
        <span>{b.user_id ?? `팀 ${b.team_id}`} · {ROLE_NAMES[b.role_id] ?? b.role_id} · {b.project_id ?? "시스템 범위"} / {b.environment}</span>
        <button className="link" disabled={busy} onClick={() => void mutate(() => api.identityWrite("DELETE", `/bindings/${idPath(b.binding_id)}`))}>권한 회수</button>
      </li>)}</ul></section>
      <section className="card"><h2>발급 토큰</h2><ul className="feed">{management.tokens.map((t) => <li key={t.token_id}>
        <span>{t.user_id} · {new Date(t.expires_at).toLocaleString()} 만료 · {t.revoked_at ? "폐기됨" : "발급됨"}</span>
        {!t.revoked_at && <button className="link" disabled={busy} onClick={() => void mutate(() => api.identityWrite("DELETE", `/tokens/${idPath(t.token_id)}`))}>토큰 폐기</button>}
      </li>)}</ul></section>
    </>}
  </>;
}

function BindingFields({ management, projects }: { management: IdentityAdministration; projects: { id: string; name: string }[] }) {
  return <><Select label="역할" name="role" items={management.roles.map((r) => ({ id: r.role_id, name: ROLE_NAMES[r.role_id] ?? r.role_id }))} />
    <Select label="프로젝트 범위" name="project" items={projects} optional="시스템 범위" />
    <Select label="실행 환경" name="environment" items={[{ id: "development", name: "개발" }, { id: "test", name: "테스트" }, { id: "production", name: "운영" }]} />
    <p className="muted small">계정·정책 관리는 시스템 범위에 배정합니다. 개발·QA의 자원 권한은 프로젝트를 지정해야 합니다. 관제 역할은 프로젝트별로 배정할 수 있습니다.</p></>;
}

function RoleEditor({ api, management, busy, submit }: {
  api: Api; management: IdentityAdministration; busy: boolean;
  submit: (action: (data: FormData) => Promise<unknown>) => (event: FormEvent<HTMLFormElement>) => void;
}) {
  const [selected, setSelected] = useState("");
  const [permissions, setPermissions] = useState<string[]>([]);
  return <Form title="역할 권한 편집" busy={busy} onSubmit={submit((d) => api.identityWrite("PUT", `/roles/${idPath(text(d, "newRole") || selected)}`, { permissions }))}>
    <label>기존 역할<select value={selected} onChange={(e) => { setSelected(e.target.value); setPermissions(management.roles.find((r) => r.role_id === e.target.value)?.permissions ?? []); }}>
      <option value="">새 역할 만들기</option>{management.roles.map((r) => <option key={r.role_id} value={r.role_id}>{ROLE_NAMES[r.role_id] ?? r.role_id}</option>)}
    </select></label>
    <label>새 역할 ID<input name="newRole" required={!selected} maxLength={100} /></label>
    <div className="permission-options">{management.permissions.map((p) => <label key={p}>
      <input type="checkbox" checked={permissions.includes(p)} onChange={(e) => setPermissions((old) => e.target.checked ? [...old, p] : old.filter((v) => v !== p))} />{p}
    </label>)}</div><p className="muted small">저장하면 이 역할을 배정받은 사용자의 다음 요청부터 바뀝니다. 관제 권한에 자원 실행 권한을 자동으로 포함하지 않습니다.</p>
  </Form>;
}
