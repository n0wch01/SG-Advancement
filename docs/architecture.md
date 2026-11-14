# 아키텍처

## 문제 정의

- 구성원마다 쓰는 에이전트가 다르고(코딩 CLI, 사내 LangGraph 봇, 개인 비서형 OpenClaw), 각자 툴·플러그인·MCP 서버를 붙인다.
- 보안팀은 **누가 / 어떤 에이전트로 / 어떤 툴을 / 어떤 데이터에** 쓰는지 볼 수 없고, 정책을 일관되게 강제할 수단이 없다.

## 구성 요소

| 구성 요소 | 위치 | 역할 |
|---|---|---|
| **Sensor** | 각 엔드포인트 | 어댑터로 에이전트 활동을 수집 → `AgentEvent`로 정규화 → 로컬 탐지·차단 → 중앙 전송 |
| **Adapter** | Sensor 내부 | 에이전트별 연동 (아래 표) |
| **Control Plane API** | 중앙 | 장비 등록, 이벤트/finding 수집, 정책 저장·버전·배포, 원격 대응 큐 |
| **Central detector** | 중앙 | 장비·사용자 간 상관 분석 (같은 악성 MCP가 여러 명에게 등장 등) |
| **Console** | 중앙 | 인벤토리, 위협 타임라인, 정책 편집기, 대응 |

## 에이전트 연동 방식

| 에이전트 | 센서 | 차단 가능 시점 | 승인(`require_approval`) | 비고 |
|---|---|---|---|---|
| OpenClaw | `openclaw_plugin` (게이트웨이 플러그인) + `openclaw_gateway` (WS 관측) | **사전, 모든 툴**(`before_tool_call`에서 block). Codex 런타임 툴도 hook 중계로 차단. WS는 관측·탐지만(결정 B) | 플러그인이 `requireApproval`로 OpenClaw 승인 창에 넘긴다(한 번 허용·거절) | WS는 SG 코드 이전, [from-sg.md](from-sg.md). 상세 [sensor.md](sensor.md) |
| Claude Code | `claude_code_hook` (`sga-hook`) + `claude_code_config` (hook 위치 점검) | **사전, 모든 툴**(PreToolUse에서 deny, 보안팀 승인은 hook이 대기) | PreToolUse가 `ask`를 돌려 Claude Code의 확인 창으로 넘긴다. 그 툴의 PostToolUse가 오면 승인으로 기록 | 관리 설정(managed-settings.d)으로 강제, 권한 없으면 사용자 설정 + 점검 룰. M6 ✅ |
| Gemini CLI | - | 미구현(선택 과제 X1) | - | 설치·MCP 설정은 섀도 AI 스캔으로 찾는다(`ai-agent-outside-control`, `mcp-server-bypasses-gateway`) |
| Codex CLI | - | 미구현(선택 과제 X1). OpenClaw의 Codex 런타임으로 도는 툴은 플러그인이 막는다 | - | 설치·MCP 설정은 섀도 AI 스캔으로 찾는다 |
| LangGraph | - | 미구현(M10 미룸) | - | 시나리오 S3(denial of wallet)는 이벤트 재생으로만 보인다 |
| 모든 MCP 클라이언트 | `mcp_proxy` (센서의 MCP 게이트웨이, 중앙 MCP 게이트웨이) | **사전**(`tools/call`을 서버에 보내기 전에 거부, 변조 툴은 목록에서 숨김). 사내 MCP 서버로 가는 유일한 길(중앙, 자격증명 보관) | 사람에게 물을 수 없어 **보안팀 보류**로 보낸다(승인 원칙 2026-11-14). 확인된 승인 없이는 서버로 보내지 않는다 | 에이전트 종류와 무관한 범용 경로. M8 ✅ |
| 팀 게이트웨이의 에이전트 | `egress_proxy` | 사전(서명된 정책의 허용 도메인 밖은 차단) | 묻지 않고 차단 | 에이전트 망을 격리하고 이 프록시로만 내보낸다. LLM 비용 한도용 `llm_proxy`는 미구현 |

### 현재 구현: OpenClaw (M5c 기준)

```
 엔드포인트 (직원 PC 또는 팀 게이트웨이 호스트)                              중앙
┌───────────────────────────────────────────────────────────┐
│ OpenClaw 게이트웨이 :18789                                  │
│  ├ sg-advance 플러그인 (TS)                              │
│  │   before_tool_call ──┐  hello 60초마다                    │
│  │   block / requireApproval ◀┐                             │
│  └ WS 이벤트 (tool·message·inventory)                        │
│        │                │     │                              │
│        │ 관측만          ▼     │ 판정                        │
│ ┌──────▼─────────────────────────────┐   ① unix 소켓 (0600)   │
│ │ sga-sensor run (LaunchAgent)  │   ② 없으면 evaluate CLI │      ┌───────────────────────┐
│ │  OpenClaw WS 어댑터 · 로컬 API      │      (캐시, degraded)  │      │ Control Plane         │
│ │  탐지 엔진 (YAML 룰, 서명된 정책)    │   ③ 그것도 없으면       │ HTTPS│  FastAPI + SQLite     │
│ │  PluginRegistry (판정·신호 감시)     │      툴 위험도 기본값    │─────▶│  장비 등록·이벤트·finding│
│ │  우선순위 대기열(spool)              │◀───────────────────────┼──────│  Ed25519 서명 정책 배포  │
│ └────────────────────────────────────┘   정책 pull · 이벤트 push│      └───────────────────────┘
└───────────────────────────────────────────────────────────┘
```

- **막는 곳은 플러그인 하나**: 게이트웨이 안에서 모든 툴 호출 직전에 데몬에 묻는다. 센서는 게이트웨이 관리자 권한(`operator.admin`)을 받지 않는다.
- **WS는 감시자**: 플러그인 판정 없이 실행된 툴 → `openclaw-plugin-bypass`. 플러그인 인사가 150초 끊기면 → `openclaw-plugin-heartbeat-lost`.
- **판정을 못 할 때는 단계적으로**: 데몬 → 캐시 판정(`sga_verdict: degraded`) → 툴 위험도(읽기 전용 툴은 통과, 나머지는 사용자 승인 요청).

승인 원칙(2026-11-14, [zero-trust.md](zero-trust.md#승인-원칙-2026-11-14)): **사용자가 먼저 승인하고, 매우 위험한 것만 바로 차단하고, 보안팀은 사후에 확인한다.**

- 바로 차단: 공격 진행 신호(인젝션 뒤 민감 행동, 위임 전파)와 외부 유출.
- 사용자 승인: 그 밖의 위험 행동(되돌릴 수 없는 3-1 포함). 에이전트의 확인 창으로 묻고, 3-1은 "되돌릴 수 없음" 경고 문구로 따로 보인다. 사람에게 물을 수 없는 MCP 게이트웨이는 보안팀 보류로 보낸다.
- 보안팀 사후 검토: 사용자가 승인한 high·critical 호출은 콘솔 승인 감사의 검토 대기 큐에 오르고, 확인 결과는 감사 체인에 남는다. 문제가 있으면 대화·사람 차단 같은 원격 조치를 한다.
- 장애·판정 실패, 보안팀이 이미 내린 결정은 사용자 승인으로 넘기지 않는다([fail-closed.md](fail-closed.md)).

하나의 에이전트를 여러 센서가 동시에 관측할 수 있다(예: Claude Code를 hook과 MCP 프록시가 함께 관측).
`AgentEvent.agent`(무엇이)와 `AgentEvent.source`(어떻게 봤는지)를 분리한 이유다.

## 설계 원칙

1. **탐지·차단은 로컬, 정책·가시성은 중앙.** 중앙과 연결이 끊겨도 마지막으로 받은 정책으로 계속 차단한다.
2. **스키마 우선.** 모든 어댑터는 `AgentEvent` v1으로만 말한다. 탐지 룰은 에이전트별 원시 포맷을 모른다.
3. **비밀은 엔드포인트를 떠나기 전에 마스킹한다.** 센서가 `arguments`/`output_preview`를 redact한 뒤 전송한다.
4. **응답 단계는 점진적이다.** `allow < alert < require_approval < security_approval < block < abort_session < quarantine`.
   `security_approval`(M11)은 툴 호출을 장비에서 멈추고 보안팀이 콘솔에서 결정하게 한다(5분 안에 없으면 거부, [response.md](response.md#보안팀-승인-큐)).
   정책이 그룹별로 단계를 정하고, `Finding.response.enforced`에 실제 집행 여부를 남긴다.
5. **데모 재현성.** `docker compose up` 하나로 중앙 서버와 가상 직원 N명, 가상 외부망(악성 MCP, 유출 수신 서버)이 뜬다.

## 데모 토폴로지 (실제 구성, compose.yaml)

```
[이 Mac]        sga-sensor (LaunchAgent) · Claude Code hook · 개인 OpenClaw + sg-advance 플러그인
[corp-net]      control-plane(API · DB · SGA-Dashboard)
                carol-pc(shadow: 직원 PC의 비관리 OpenClaw)  lan-gateway(lan: 장비 인증서 mTLS)
                mcp-gateway(mcp: 중앙 MCP 게이트웨이, 사내 서버 자격증명 보관)
[team-net]      team-proxy(직원별 포트, 신원) → team-gateway(team: 팀 공용 OpenClaw + 플러그인·센서)
                  WebSocket은 team-audit(감사 프록시: 승인·중단·보관·삭제한 사람 기록)을 거친다
                team-egress(egress 프록시: 에이전트 망의 유일한 출구)
[crm-net]       corp-crm(사내 MCP 서버, 중앙 MCP 게이트웨이와만 연결)
[internet-sim]  공격 시나리오용 가상 외부(악성 MCP, 유출 수신 서버 등). 룰 케이스·평가·데모 재생에서 주소로 쓴다
```

- 실행: `SGA_ADMIN_TOKEN=x docker compose up -d --build`, 프로필을 더하면 `--profile team --profile shadow --profile mcp --profile lan`.
- 처음 계획했던 가상 직원(LangGraph + Ollama, M10)과 Gemini·Codex 엔드포인트는 만들지 않았다(미룬 과제).
- 다른 PC(Windows 노트북)는 한 줄 설치로 붙는다([multi-host.md](multi-host.md)). 실설치 확인은 남아 있다.
