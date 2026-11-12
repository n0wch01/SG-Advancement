import type { Api } from "../api";
import { SeverityBadge } from "../components/Severity";
import { Empty, ErrorBox, Loading } from "../components/States";
import { GUARD_LABEL, SEVERITIES, agentPosture, findingsHref, formatTime, reasonText, relativeTime } from "../format";
import type { DeviceInventory, Snapshot } from "../types";
import { useAsync } from "../useAsync";

type Row = Record<string, unknown>;
const s = (v: unknown) => (typeof v === "string" ? v : v === undefined || v === null ? "" : String(v));
const list = (v: unknown): Row[] => (Array.isArray(v) ? (v as Row[]) : []);

// State chips carry a word, never color alone.
function Chip({ tone, children }: { tone: "good" | "bad" | "warn" | "neutral"; children: React.ReactNode }) {
  return <span className={`chip chip-${tone}`}>{children}</span>;
}

export function Inventory({ api }: { api: Api }) {
  const { data, error, loading } = useAsync(() => api.inventory(), [api]);
  return (
    <section>
      <div className="page-head">
        <h1>인벤토리</h1>
      </div>
      <p className="muted small">장비마다 센서가 마지막으로 보낸 상태입니다: 에이전트 설치(관리 여부), 에이전트별 구성, 설정 기준선, 설치된 코드의 무결성.</p>
      {error && <ErrorBox error={error} />}
      {loading && !data && <Loading />}
      {data && data.length === 0 && <Empty>등록된 장비가 없습니다.</Empty>}
      {data?.map((d) => <DeviceCard key={d.device_id} d={d} />)}
    </section>
  );
}

function DeviceCard({ d }: { d: DeviceInventory }) {
  const nothing = !d.installs.length && !d.agents.length && !d.configs.length && !d.integrity.length;
  return (
    <div className="card device">
      <div className="device-head">
        <h2>
          {d.device_id}
          {d.hostname && d.hostname !== d.device_id && <span className="muted small"> ({d.hostname})</span>}
        </h2>
        <div className="device-meta small">
          <span>{d.last_seen ? `마지막 동기화 ${relativeTime(d.last_seen)}` : "동기화 기록 없음"}</span>
          {d.policy_current ? <Chip tone="good">최신 정책</Chip> : <Chip tone="warn">이전 정책</Chip>}
          {SEVERITIES.filter((x) => d.open_findings[x]).map((x) => (
            <a key={x} href={findingsHref({ severity: x })} className="nowrap">
              <SeverityBadge severity={x} /> {d.open_findings[x]}
            </a>
          ))}
        </div>
      </div>
      {nothing && <Empty>상태 스냅샷을 보낸 적이 없습니다(프록시처럼 관측만 하는 장비).</Empty>}
      {d.installs.length > 0 && <Installs rows={d.installs} />}
      {d.agents.length > 0 && <Agents rows={d.agents} />}
      {d.configs.length > 0 && <Configs rows={d.configs} />}
      {d.integrity.length > 0 && <Integrity rows={d.integrity} />}
    </div>
  );
}

function Installs({ rows }: { rows: Snapshot[] }) {
  return (
    <>
      <h3>에이전트 설치</h3>
      <table>
        <thead>
          <tr>
            <th>설치</th>
            <th>상태</th>
            <th>게이트웨이</th>
            <th>버전</th>
            <th>마지막 확인</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const p = r.payload;
            const reasons = list(p.unmanaged_reasons).map((x) => reasonText(s(x)));
            return (
              <tr key={r.session_id}>
                <td>
                  <span className="mono small">{s(p.instance)}</span>
                  <div className="muted small">
                    {s(p.product)} · {r.user_id}
                  </div>
                </td>
                <td>
                  {p.present === false ? (
                    <Chip tone="neutral">사라짐</Chip>
                  ) : p.managed ? (
                    <Chip tone="good">관리됨</Chip>
                  ) : p.configured ? (
                    <Chip tone="bad">비관리</Chip>
                  ) : (
                    <Chip tone="neutral">설정 안 됨</Chip>
                  )}
                  {reasons.length > 0 && <div className="muted small">{reasons.join(", ")}</div>}
                </td>
                <td className="small">
                  {p.running ? "실행 중" : "꺼짐"}
                  {p.bind ? ` · ${s(p.bind)}` : ""}
                  {p.bind_scope === "network" && !p.managed && p.running ? (
                    <div>
                      <Chip tone="bad">네트워크에 열림</Chip>
                    </div>
                  ) : null}
                </td>
                <td className="small">
                  {s(p.version) || "-"}
                  <div className="muted">{s(p.install_source)}</div>
                </td>
                <td className="muted small" title={formatTime(r.ts)}>
                  {relativeTime(r.ts)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </>
  );
}

function Agents({ rows }: { rows: Snapshot[] }) {
  return (
    <>
      <h3>에이전트</h3>
      <table>
        <thead>
          <tr>
            <th>에이전트</th>
            <th>모델 · 런타임</th>
            <th>기본 권한</th>
            <th className="num">툴</th>
            <th>스킬</th>
            <th>런타임 점검 (T19)</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const p = r.payload;
            const a = agentPosture(p);
            return (
              <tr key={r.session_id}>
                <td className="mono">
                  {s(p.agent_id) || <span className="muted small">{r.session_id}</span>}
                </td>
                <td className="small">
                  {s(p.model) || "-"}
                  <div className="muted">{s(p.runtime) || "-"}</div>
                </td>
                <td>{p.permission_mode === "full" ? <Chip tone="warn">full</Chip> : s(p.permission_mode) || "-"}</td>
                <td className="num">{a.tools}</td>
                <td className="small">
                  {a.skills}개
                  {a.tamperedSkills.length > 0 && (
                    <div>
                      <Chip tone="bad">변조</Chip> {a.tamperedSkills.join(", ")}
                    </div>
                  )}
                  {a.unverifiedSkills.length > 0 && (
                    <div>
                      <Chip tone="warn">미승인</Chip> {a.unverifiedSkills.join(", ")}
                    </div>
                  )}
                </td>
                <td className="small">
                  {a.unpinnedModels === null ? (
                    <span className="muted">보고 없음</span>
                  ) : a.unpinnedModels > 0 ? (
                    <Chip tone="warn">고정 안 된 모델 {a.unpinnedModels}</Chip>
                  ) : (
                    <Chip tone="good">모든 모델 고정</Chip>
                  )}
                  {a.sessions !== null && (
                    <div className="muted">
                      대화 {a.sessions}
                      {a.staleSessions > 0 && (
                        <>
                          {" "}
                          · <Chip tone="warn">예전 런타임 {a.staleSessions}</Chip>
                        </>
                      )}
                    </div>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </>
  );
}

function Configs({ rows }: { rows: Snapshot[] }) {
  return (
    <>
      <h3>설정 기준선</h3>
      {rows.map((r) => {
        const p = r.payload;
        const sandboxes = list(p.sandboxes);
        const unsafeExec = list(p.exec_policies).filter((e) => ["full", "off"].includes(s(e.security)) || s(e.ask) === "off" || s(e.mode) === "full");
        return (
          <dl key={r.session_id} className="facts">
            <dt>설정 파일</dt>
            <dd className="mono small">{s(p.path) || "-"}</dd>
            <dt>실행 전 판정 플러그인</dt>
            <dd>{p.guard_plugin === "enabled" ? <Chip tone="good">켜짐</Chip> : <Chip tone="bad">{GUARD_LABEL[s(p.guard_plugin)] ?? "알 수 없음"}</Chip>}</dd>
            <dt>셸 실행 정책</dt>
            <dd>{unsafeExec.length ? <Chip tone="bad">완화됨 ({unsafeExec.map((e) => s(e.scope)).join(", ")})</Chip> : <Chip tone="good">기준선</Chip>}</dd>
            <dt>샌드박스</dt>
            <dd className="small">
              {sandboxes.length === 0 && <span className="muted">보고 없음</span>}
              {sandboxes.map((b) => (
                <span key={s(b.scope)} className="nowrap">
                  {s(b.scope)}: {b.mode === "off" ? <Chip tone="warn">꺼짐</Chip> : s(b.mode)}
                  {b.mode_source === "default" ? <span className="muted"> (기본값)</span> : null}{" "}
                </span>
              ))}
            </dd>
            <dt>마지막 변경</dt>
            <dd className="muted small">
              {relativeTime(r.ts)}
              {list(p.changed).length > 0 && ` · ${list(p.changed).map(s).join(", ")}`}
            </dd>
          </dl>
        );
      })}
    </>
  );
}

function Integrity({ rows }: { rows: Snapshot[] }) {
  return (
    <>
      <h3>설치된 코드 무결성</h3>
      {rows.map((r) => {
        const p = r.payload;
        const core = (p.core ?? null) as Row | null;
        const plugins = list(p.plugins);
        const bad = plugins.filter((x) => x.integrity === "mismatch");
        const pending = plugins.filter((x) => x.integrity === "pending" || x.integrity === "unknown");
        return (
          <dl key={r.session_id} className="facts">
            <dt>본체</dt>
            <dd>
              {s(p.product)} {s(p.version)}{" "}
              {core ? (
                core.integrity === "verified" ? (
                  <Chip tone="good">서명된 배포본과 일치 · {s(core.trust)}</Chip>
                ) : core.integrity === "mismatch" ? (
                  <Chip tone="bad">변조</Chip>
                ) : (
                  <Chip tone="warn">
                    {s(core.integrity)} · {s(core.trust)}
                  </Chip>
                )
              ) : (
                <span className="muted">-</span>
              )}
            </dd>
            <dt>플러그인</dt>
            <dd className="small">
              {plugins.length}개 · {bad.length ? <Chip tone="bad">변조 {bad.length}</Chip> : <Chip tone="good">변조 없음</Chip>}
              {pending.length > 0 && <span className="muted"> · 확인 대기 {pending.length}</span>}
            </dd>
            <dt>확인 시각</dt>
            <dd className="muted small">{relativeTime(r.ts)}</dd>
          </dl>
        );
      })}
    </>
  );
}
