import { useState } from "react";

import { ApiError, type Api } from "../api";
import { SeverityBadge } from "../components/Severity";
import { Empty, ErrorBox, Loading } from "../components/States";
import { ACTION_LABEL, CHANGE_LABEL, formatTime, relativeTime, responseChoices } from "../format";
import type { PolicyRule, Role } from "../types";
import { useAsync } from "../useAsync";

const href = (scope: string, changed?: boolean) =>
  `#/policy?scope=${encodeURIComponent(scope)}${changed ? "&changed=1" : ""}`;

export function Policy({ api, role, query }: { api: Api; role: Role | null; query: Record<string, string> }) {
  const scope = query.scope || "common";
  const changedOnly = query.changed === "1";
  const [tick, setTick] = useState(0); // bump after a write to reload everything
  const scopes = useAsync(() => api.policyScopes(), [api, tick]);
  const rules = useAsync(() => api.policyRules(scope), [api, scope, tick]);
  const log = useAsync(() => api.policyChanges(), [api, tick]);
  const admin = role === "admin";
  const reload = () => setTick((t) => t + 1);
  const current = scopes.data?.scopes.find((s) => s.name === scope);

  return (
    <section>
      <div className="page-head">
        <h1>정책</h1>
        {scopes.data && <span className="muted small">정책 리비전 #{scopes.data.revision}</span>}
      </div>
      <p className="muted small">
        저장소의 룰 위에 <strong>공통 정책</strong>(보안팀, 완화 가능·모두 기록)과 <strong>팀 정책</strong>(공통보다 더 엄격하게만: 룰 켜기, 대응 올리기, 허용
        목록 줄이기)을 얹습니다. 팀 장비는 공통 + 자기 팀 정책을 서명된 묶음으로 받습니다.
        {!admin && " 읽기 전용으로 보고 있습니다. 바꾸려면 관리자 토큰이나 CLI(sga-server policy)를 쓰세요."}
      </p>

      {scopes.error && <ErrorBox error={scopes.error} />}
      {scopes.data && (
        <div className="scope-tabs" role="tablist">
          {scopes.data.scopes.map((s) => (
            <a key={s.name} role="tab" aria-selected={s.name === scope} className={s.name === scope ? "on" : ""} href={href(s.name, changedOnly)}>
              <strong>{s.name === "common" ? "공통" : s.name}</strong>
              <span className="muted small">
                장비 {s.devices} · 변경 {s.overrides}
              </span>
            </a>
          ))}
        </div>
      )}
      {admin && <NewGroup api={api} onDone={reload} />}

      <div className="card flush">
        <div className="card-bar">
          <span className="small">
            {scope === "common" ? "공통 정책" : `${scope} 팀 정책`}
            {current && <span className="mono muted"> · 버전 {current.version.slice(0, 12)}</span>}
          </span>
          <label className="small check">
            <input type="checkbox" checked={changedOnly} onChange={(e) => (window.location.hash = href(scope, e.target.checked))} /> 바뀐 룰만
          </label>
        </div>
        {rules.error && <ErrorBox error={rules.error} />}
        {rules.loading && !rules.data && <Loading />}
        {rules.data && (
          <RuleTable
            api={api}
            admin={admin}
            scope={scope}
            rows={rules.data.filter((r) => !changedOnly || r.common_override || r.group_override)}
            onDone={reload}
          />
        )}
      </div>

      <div className="grid-2">
        <div className="card">
          <h2>장비 배정</h2>
          <Devices api={api} admin={admin} groups={(scopes.data?.scopes ?? []).map((s) => s.name)} tick={tick} onDone={reload} />
        </div>
        <div className="card">
          <h2>변경 이력</h2>
          {log.error && <ErrorBox error={log.error} />}
          {log.data && log.data.length === 0 && <Empty>아직 바꾼 적이 없습니다.</Empty>}
          <ul className="feed changes">
            {(log.data ?? []).map((c) => (
              <li key={c.id}>
                <span className="mono muted small">#{c.id}</span>
                <span>
                  <strong>{CHANGE_LABEL[c.action] ?? c.action}</strong> {c.scope === "common" ? "공통" : c.scope}
                  {c.rule_id && <span className="mono small"> {c.rule_id}</span>}
                  {c.target && <span className="mono small"> {c.target}</span>}
                  <div className="small">
                    <span className="mono muted">{c.before ? JSON.stringify(c.before) : "∅"}</span> →{" "}
                    <span className="mono">{c.after ? JSON.stringify(c.after) : "∅"}</span>
                  </div>
                  <div className="muted small">
                    {c.actor} · “{c.reason}”
                  </div>
                </span>
                <span className="muted small" title={formatTime(c.ts)}>
                  {relativeTime(c.ts)}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}

function RuleTable({ api, admin, scope, rows, onDone }: { api: Api; admin: boolean; scope: string; rows: PolicyRule[]; onDone: () => void }) {
  const [editing, setEditing] = useState<string | null>(null);
  if (rows.length === 0) return <Empty>바뀐 룰이 없습니다.</Empty>;
  return (
    <table className="policy">
      <thead>
        <tr>
          <th>룰</th>
          <th>심각도</th>
          <th>저장소 기본</th>
          <th>적용</th>
          <th>변경</th>
          {admin && <th />}
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <RuleRow key={r.id} api={api} admin={admin} scope={scope} r={r} open={editing === r.id} setOpen={(o) => setEditing(o ? r.id : null)} onDone={onDone} />
        ))}
      </tbody>
    </table>
  );
}

function state(l: { enabled: boolean; response: string }) {
  return l.enabled ? (ACTION_LABEL[l.response] ?? l.response) : "꺼짐";
}

function RuleRow({
  api,
  admin,
  scope,
  r,
  open,
  setOpen,
  onDone,
}: {
  api: Api;
  admin: boolean;
  scope: string;
  r: PolicyRule;
  open: boolean;
  setOpen: (o: boolean) => void;
  onDone: () => void;
}) {
  const changed = state(r.effective) !== state(r.base) || JSON.stringify(r.effective.allow) !== JSON.stringify(r.base.allow);
  return (
    <>
      <tr className={changed ? "changed" : ""}>
        <td>
          {r.title}
          <div className="mono muted small">{r.id}</div>
        </td>
        <td>
          <SeverityBadge severity={r.severity} />
        </td>
        <td className="small">{state(r.base)}</td>
        <td className="small">
          <strong>{state(r.effective)}</strong>
          {r.effective.allow && changed && <div className="muted mono">허용 {r.effective.allow.length}개</div>}
        </td>
        <td className="small">
          {r.common_override && <span className="tag">공통 {JSON.stringify(r.common_override)}</span>}
          {r.group_override && <span className="tag warn">팀 {JSON.stringify(r.group_override)}</span>}
          {!r.common_override && !r.group_override && <span className="muted">-</span>}
        </td>
        {admin && (
          <td>
            <button className="link" onClick={() => setOpen(!open)}>
              {open ? "닫기" : "수정"}
            </button>
          </td>
        )}
      </tr>
      {open && (
        <tr className="editor-row">
          <td colSpan={6}>
            <Editor api={api} scope={scope} r={r} onDone={() => (setOpen(false), onDone())} />
          </td>
        </tr>
      )}
    </>
  );
}

function Editor({ api, scope, r, onDone }: { api: Api; scope: string; r: PolicyRule; onDone: () => void }) {
  const team = scope !== "common";
  // What the layer below gives this scope: the repository rule for common, common's result for a team.
  const below = team ? { ...r.base, ...(r.common_override ?? {}) } : r.base;
  const mine = (team ? r.group_override : r.common_override) ?? {};
  const [enabled, setEnabled] = useState<string>(mine.enabled === undefined ? "" : String(mine.enabled));
  const [response, setResponse] = useState<string>(mine.response ?? "");
  const [allow, setAllow] = useState<string[]>(mine.allow ?? below.allow ?? []);
  const [allowDraft, setAllowDraft] = useState((mine.allow ?? below.allow ?? []).join("\n"));
  const [by, setBy] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const isAllowlist = r.match_type === "allowlist";

  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      onDone();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const save = () =>
    run(() => {
      const body: Parameters<Api["setOverride"]>[0] = { scope, rule_id: r.id, by, reason };
      if (enabled !== "") body.enabled = enabled === "true";
      if (response) body.response = response;
      if (isAllowlist) {
        const next = team ? allow : allowDraft.split("\n").map((x) => x.trim()).filter(Boolean);
        if (JSON.stringify(next) !== JSON.stringify(below.allow ?? [])) body.allow = next;
      }
      return api.setOverride(body);
    });

  return (
    <div className="editor">
      <div className="editor-fields">
        <label>
          켜기/끄기
          <select value={enabled} onChange={(e) => setEnabled(e.target.value)}>
            <option value="">그대로 ({below.enabled ? "켜짐" : "꺼짐"})</option>
            <option value="true">켜기</option>
            {!team && <option value="false">끄기</option>}
          </select>
        </label>
        <label>
          대응
          <select value={response} onChange={(e) => setResponse(e.target.value)}>
            <option value="">그대로 ({ACTION_LABEL[below.response] ?? below.response})</option>
            {responseChoices(scope, below.response).map((x) => (
              <option key={x} value={x}>
                {ACTION_LABEL[x] ?? x}
              </option>
            ))}
          </select>
        </label>
        {isAllowlist && team && (
          <fieldset className="allow-pick">
            <legend>허용 목록 (공통 목록에서 남길 것만)</legend>
            {(below.allow ?? []).map((a) => (
              <label key={a} className="check mono small">
                <input
                  type="checkbox"
                  checked={allow.includes(a)}
                  onChange={(e) => setAllow(e.target.checked ? [...allow, a] : allow.filter((x) => x !== a))}
                />{" "}
                {a}
              </label>
            ))}
          </fieldset>
        )}
        {isAllowlist && !team && (
          <label className="wide">
            허용 목록 (한 줄에 하나)
            <textarea rows={5} value={allowDraft} onChange={(e) => setAllowDraft(e.target.value)} className="mono small" />
          </label>
        )}
      </div>
      <div className="editor-fields">
        <label>
          누가
          <input value={by} onChange={(e) => setBy(e.target.value)} placeholder="예: secops@corp.test" required />
        </label>
        <label className="wide">
          왜 (변경 이력에 남습니다)
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="예: 데이터팀은 운영 DB 접근이 잦아 차단으로 올림" required />
        </label>
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div className="editor-actions">
        <button type="button" className="primary" disabled={busy || !by.trim() || !reason.trim()} onClick={() => void save()}>
          저장
        </button>
        {(team ? r.group_override : r.common_override) && (
          <button
            type="button"
            className="link"
            disabled={busy || !by.trim() || !reason.trim()}
            onClick={() => void run(() => api.clearOverride({ scope, rule_id: r.id, by, reason }))}
          >
            이 범위의 변경 취소
          </button>
        )}
      </div>
    </div>
  );
}

function NewGroup({ api, onDone }: { api: Api; onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [by, setBy] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  if (!open)
    return (
      <p>
        <button className="link" onClick={() => setOpen(true)}>
          + 팀 만들기
        </button>
      </p>
    );
  return (
    <form
      className="filters"
      onSubmit={async (e) => {
        e.preventDefault();
        setError(null);
        try {
          await api.createGroup({ name: name.trim(), by, reason });
          setOpen(false);
          window.location.hash = href(name.trim());
          onDone();
        } catch (err) {
          setError(err instanceof ApiError ? err.message : String(err));
        }
      }}
    >
      <label>
        팀 이름
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="예: data-team" required />
      </label>
      <label>
        누가
        <input value={by} onChange={(e) => setBy(e.target.value)} required />
      </label>
      <label>
        왜
        <input value={reason} onChange={(e) => setReason(e.target.value)} required />
      </label>
      <button type="submit">만들기</button>
      <button type="button" className="link" onClick={() => setOpen(false)}>
        취소
      </button>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </form>
  );
}

function Devices({ api, admin, groups, tick, onDone }: { api: Api; admin: boolean; groups: string[]; tick: number; onDone: () => void }) {
  const { data, error } = useAsync(() => api.devices(), [api, tick]);
  const [by, setBy] = useState("");
  const [reason, setReason] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  if (error) return <ErrorBox error={error} />;
  if (!data) return <Loading />;
  return (
    <>
      <table>
        <thead>
          <tr>
            <th>장비</th>
            <th>팀</th>
            <th>정책</th>
          </tr>
        </thead>
        <tbody>
          {data.map((d) => (
            <tr key={d.device_id}>
              <td>
                {d.device_id}
                <div className="muted small">{d.last_seen ? relativeTime(d.last_seen) : "-"}</div>
              </td>
              <td>
                {admin ? (
                  <select
                    value={d.group ?? "common"}
                    onChange={async (e) => {
                      setMsg(null);
                      if (!by.trim() || !reason.trim()) {
                        setMsg("아래에 누가·왜를 먼저 적어 주세요.");
                        return;
                      }
                      try {
                        await api.assignDevice(d.device_id, { group: e.target.value === "common" ? null : e.target.value, by, reason });
                        onDone();
                      } catch (err) {
                        setMsg(err instanceof ApiError ? err.message : String(err));
                      }
                    }}
                  >
                    {groups.map((g) => (
                      <option key={g} value={g}>
                        {g === "common" ? "공통만" : g}
                      </option>
                    ))}
                  </select>
                ) : (
                  (d.group ?? "공통만")
                )}
              </td>
              <td className="small">{d.policy_current ? "최신" : <span className="muted">다음 동기화 때 반영</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {admin && (
        <div className="filters">
          <label>
            누가
            <input value={by} onChange={(e) => setBy(e.target.value)} />
          </label>
          <label>
            왜
            <input value={reason} onChange={(e) => setReason(e.target.value)} />
          </label>
        </div>
      )}
      {msg && (
        <p className="error" role="alert">
          {msg}
        </p>
      )}
    </>
  );
}
