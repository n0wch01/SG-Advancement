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
| Gemini CLI | `gemini_cli_hook` | 사전(가능 시) | X1에서 확인. 안 되면 차단 + 콘솔 승인 큐 | hook 사양은 선택 과제 X1에서 확인 |
| Codex CLI | `codex_cli_hook` | 확인 필요 | X1에서 확인. 안 되면 차단 + 콘솔 승인 큐 | 연동 지점은 선택 과제 X1에서 조사 |
| LangGraph | `langgraph_callback` | 사전(callback에서 예외) | 그래프를 멈추고(사람 개입 단계) 승인을 기다린다. 가상 직원은 승인자도 시뮬레이션 | Ollama 로컬 모델로 가상 직원 다수 시뮬레이션 |
| 모든 MCP 클라이언트 | `mcp_proxy` (센서의 MCP 게이트웨이) | **사전**(`tools/call`을 서버에 보내기 전에 거부, 변조 툴은 목록에서 숨김) | 게이트웨이는 묻지 않고 에이전트의 확인 창에 맡김(Claude Code는 hook이 `ask`). 보안팀 승인은 게이트웨이가 대기 | 에이전트 종류와 무관한 범용 경로. M8 ✅ |
| 모든 에이전트 | `egress_proxy` / `llm_proxy` | 사전 | 요청을 보류하고 콘솔 승인 큐 | 외부 유출, 비용 한도 |

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

`require_approval`은 **사용자가 에이전트 화면에서 승인**하는 것이 기본이고, 그게 불가능한 에이전트는 **차단한 뒤 콘솔 승인 큐**(M11)에 올린다.
누가 언제 승인·거절했는지는 finding의 `response`에 남는다. 보안팀은 승인을 미리 막는 대신 **사후 감사**한다:
콘솔에서 사용자가 승인한 위험 행동을 모아 보고, 이상하면 세션 중단·격리 같은 원격 조치를 한다.

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

## 데모 토폴로지 (목표)

```
[corp-net]      control-plane(api, db, console) · endpoint-alice(OpenClaw) · endpoint-bob(Claude Code)
                endpoint-carol(LangGraph+MCP proxy) · endpoint-erin(Gemini CLI) · endpoint-frank(Codex CLI) · ollama
[internet-sim]  evil-mcp · exfil-sink · poisoned-repo
```

이후 단계에서는 실제 다른 PC나 VM의 센서가 등록 토큰으로 LAN이나 Tailscale을 통해 중앙에 붙는다.
