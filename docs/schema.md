# 와이어 스키마 v1

소스 오브 트루스는 Python 모델([src/agent_sentinel/schema/](../src/agent_sentinel/schema/))이며,
[schemas/](../schemas/)의 JSON Schema는 `scripts/export_schema.py`로 생성한다. 테스트가 둘의 불일치를 잡는다.

## AgentEvent

```
AgentEvent
├ schema_version "1", event_id, ts(UTC aware), received_ts(중앙이 기록)
├ endpoint   { device_id, hostname, os, ip }          ← 어디서
├ principal  { user_id, display_name, groups }        ← 누구를 대신해
├ agent      { type, session_id, run_id, model, cwd } ← 어떤 에이전트가
├ source     { sensor, sensor_version, seq }          ← 어떻게 관측했나
├ payload    (kind로 구분되는 union)
├ labels     { scenario: "S1", ... }
└ raw        선택, 마스킹된 원본 프레임
```

### payload.kind

| kind | 의미 | 주요 필드 |
|---|---|---|
| `session.start` / `session.end` | 세션 수명주기 | reason |
| `prompt.user` | 사용자 입력 | text |
| `message.assistant` | 모델 응답 | text |
| `tool.call` | 툴 실행 **직전** (차단 판단 지점) | call_id, tool, provider, arguments |
| `tool.result` | 툴 실행 결과 | call_id, ok, output_preview, error, duration_ms |
| `llm.call` | LLM API 호출 | provider, model, tokens, cost_usd |
| `net.egress` | 외부 네트워크 요청 | method, url, host, bytes_out, destination |
| `inventory.snapshot` | 사용 가능한 툴·플러그인·MCP 서버 목록 | tools, plugins, mcp_servers |

`provider.kind`는 툴의 출처를 나타낸다: `builtin | plugin | mcp | function | unknown`.

### 에이전트별 원시 이벤트 → kind 매핑 (초안)

| 원시 이벤트 | kind |
|---|---|
| OpenClaw `session.message` (user / assistant) | `prompt.user` / `message.assistant` |
| OpenClaw `session.tool` (call / result) | `tool.call` / `tool.result` |
| OpenClaw `tools.effective` / `tools.catalog` RPC | `inventory.snapshot` |
| OpenClaw `agent` lifecycle start / end | `session.start` / `session.end` |
| Claude Code `SessionStart` / `SessionEnd` hook | `session.start` / `session.end` |
| Claude Code `UserPromptSubmit` hook | `prompt.user` |
| Claude Code `PreToolUse` / `PostToolUse` hook | `tool.call` / `tool.result` |
| MCP `tools/list` 응답 | `inventory.snapshot` |
| MCP `tools/call` 요청 / 응답 | `tool.call` / `tool.result` |
| LangGraph `on_chat_model_start/end`, `on_tool_start/end` | `llm.call`, `tool.call` / `tool.result` |
| Gemini CLI, Codex CLI | M10에서 실제 hook/설정 사양을 확인해 확정 |
| sentinel fetch interceptor (기존 SG) | `net.egress` |

## Finding

```
Finding
├ finding_id, ts, rule_id, rule_version
├ severity  info < low < medium < high < critical
├ category  prompt_injection | data_exfiltration | supply_chain | tool_misuse |
│           resource_abuse | privilege_escalation | memory_poisoning | policy_violation | other
├ title, message, recommended_action, explanation(매칭 근거, 마스킹됨), confidence(0~1)
├ detector  local | central
├ evidence_event_ids
├ endpoint, principal, agent   ← 트리거 이벤트에서 상속 (Finding.from_event)
├ response  { action, enforced, enforcer, detail }
└ tags      owasp-llm:LLM01, owasp-agentic:T2, mitre-atlas:AML.T0051 ...
```

### 기존 SG 시나리오와의 대응

| SG 시나리오 | category | 일반화 방향 |
|---|---|---|
| S1 악성 플러그인 공급망 | `supply_chain`, `data_exfiltration` | 플러그인 + MCP 서버 허용목록, 툴 설명 변조 탐지 |
| S2 README 프롬프트 인젝션 | `prompt_injection`, `data_exfiltration` | `tool.result` 내용 검사 → 이후 `tool.call`/`net.egress` 차단 |
| S3 API 남용 / Denial of Wallet | `resource_abuse` | 사용자·그룹별 호출·토큰·비용 한도 |

## 버전 정책

- 필드 **추가**는 v1 안에서 허용하되 기본값을 둔다. `extra="forbid"`이므로 수신 측을 먼저 올린다.
- 필드 의미 변경이나 삭제는 `schema_version`을 올린다.
