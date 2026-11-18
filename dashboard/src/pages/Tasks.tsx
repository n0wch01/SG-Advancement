import { useContext, useEffect, useState, type FormEvent } from "react";
import { IdentityContext, usePermission } from "../access";
import { Api } from "../api";
import type { SessionBinding, TaskGrant } from "../types";

const ACTIONS = [
  { id: "source.read", label: "소스·테스트 읽기" },
  { id: "source.write", label: "소스 수정" },
  { id: "tests.write", label: "테스트 수정" },
  { id: "pr.create", label: "PR 기록" },
  { id: "ci.run", label: "CI 실행" },
];

export function Tasks({ api, sessions }: { api: Api; sessions: SessionBinding[] }) {
  const identity = useContext(IdentityContext);
  const identityManage = usePermission("identity.manage");
  const responseManage = usePermission("response.manage");
  const manage = identityManage || responseManage;
  const [tasks, setTasks] = useState<TaskGrant[]>([]);
  const [issued, setIssued] = useState<(TaskGrant & { token: string }) | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const mine = sessions.filter((s) => s.user_id === identity?.user_id && !s.revoked_at);
  const actions = ACTIONS.filter((a) => identity?.permissions.includes(a.id));
  const load = () => api.tasks().then(setTasks);
  useEffect(() => { void load().catch((e) => setError(String(e))); }, [api]);
  async function issue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setBusy(true); setError(null); setIssued(null);
    try {
      const value = await api.issueTask({
        binding_id: String(data.get("session")), environment: String(data.get("environment")),
        agent_profile: String(data.get("profile")), actions: data.getAll("actions").map(String),
        paths: String(data.get("paths")).split(/[\n,]/).map((p) => p.trim()).filter(Boolean),
        lifetime_seconds: Number(data.get("minutes")) * 60,
      });
      setIssued(value); await load();
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }
  function download() {
    if (!issued) return;
    const url = URL.createObjectURL(new Blob([issued.token], { type: "text/plain" }));
    const anchor = document.createElement("a");
    anchor.href = url; anchor.download = `sga-task-${issued.grant_id}.grant`; anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return <section className="card access-form"><h2>보호 자원 작업 권한</h2>
    <p className="muted small">보호 저장소의 파일 읽기·수정, Git push(작업 브랜치만), PR 기록과 CI 실행을 지원합니다. 매 접근에서 현재 권한과 정책을 확인하며 연결이 끊기면 거부합니다. 운영 배포는 작업 권한으로 줄 수 없고, 다른 로컬 파일은 별도 범위입니다.</p>
    {error && <p className="error" role="alert">{error}</p>}
    {mine.length > 0 && actions.length > 0 && <form onSubmit={(e) => void issue(e)}><fieldset disabled={busy}>
      <label>내 등록 세션<select name="session" required><option value="">선택하세요</option>{mine.map((s) => <option key={s.binding_id} value={s.binding_id}>{s.project_id} · {s.agent_type} · {s.session_id}</option>)}</select></label>
      <label>환경<select name="environment"><option value="development">개발</option><option value="test">테스트</option></select></label>
      <label>에이전트 허용 범위<select name="profile"><option value="coder">소스·테스트 수정 가능</option><option value="tester">읽기·테스트 수정</option><option value="reader">읽기 전용</option></select></label>
      <div className="permission-options">{actions.map((a) => <label key={a.id}><input type="checkbox" name="actions" value={a.id} defaultChecked={a.id === "source.read"} />{a.label}</label>)}</div>
      <label>허용 경로 (한 줄에 하나)<textarea name="paths" defaultValue={"src\ntests"} rows={3} required /></label>
      <label>유효 시간 (분)<input type="number" name="minutes" min={1} max={60} defaultValue={15} required /></label>
      <button disabled={busy}>{busy ? "확인 중…" : "내 작업 권한 발급"}</button>
    </fieldset></form>}
    {issued && <div className="notice"><h3>작업 권한 발급 완료</h3>
      <p>만료: {new Date(issued.claims.expires_at).toLocaleString()}. 개인 로그인 토큰을 에이전트에 전달하지 마세요.</p>
      <button onClick={download}>MCP용 권한 파일 저장</button> <button className="link" onClick={() => setIssued(null)}>표시 닫기</button>
      <p className="small">이 화면을 닫으면 권한 파일을 다시 내려받을 수 없습니다. 저장한 파일은 본인만 읽을 수 있도록 권한을 설정한 뒤 MCP 연결에 사용합니다.</p>
    </div>}
    <div className="table-wrap"><table><thead><tr><th>사용자 / 프로젝트</th><th>작업 범위</th><th>만료 / 상태</th><th>작업</th></tr></thead><tbody>{tasks.map((task) => <tr key={task.grant_id}>
      <td>{task.claims.user_id}<br />{task.claims.project_id} · {task.claims.environment}</td>
      <td>{task.claims.actions.join(", ")}<br /><span className="mono small">{task.claims.paths.join(", ")}</span>{task.claims.parent_id && <span className="tag">위임받음</span>}</td>
      <td>{new Date(task.claims.expires_at).toLocaleString()}<br />{task.revoked_at ? "회수됨" : Date.parse(task.claims.expires_at) <= Date.now() ? "만료됨" : "발급됨 · 접근 시 재검사"}</td>
      <td>{!task.revoked_at && (manage || task.claims.user_id === identity?.user_id) && <button className="link" disabled={busy} onClick={async () => {
        setBusy(true); setError(null);
        try { await api.revokeTask(task.grant_id); await load(); }
        catch (e) { setError(e instanceof Error ? e.message : String(e)); }
        finally { setBusy(false); }
      }}>권한 회수</button>}</td>
    </tr>)}</tbody></table></div>
  </section>;
}
