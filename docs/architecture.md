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

| 에이전트 | 센서 | 차단 가능 시점 | 비고 |
|---|---|---|---|
| OpenClaw | `openclaw_gateway` (WS 구독) | 사후(세션 abort) | 기존 SG 코드 재사용 |
| Claude Code | `claude_code_hook` | **사전**(PreToolUse에서 deny) | managed settings로 정책 강제 |
| Gemini CLI | `gemini_cli_hook` | 사전(가능 시) | hook 사양은 M10에서 확인 |
| Codex CLI | `codex_cli_hook` | 확인 필요 | 연동 지점은 M10에서 조사 |
| LangGraph | `langgraph_callback` | 사전(callback에서 예외) | Ollama 로컬 모델로 가상 직원 다수 시뮬레이션 |
| 모든 MCP 클라이언트 | `mcp_proxy` | **사전**(JSON-RPC 중계 중 거부) | 에이전트 종류와 무관한 범용 경로 |
| 모든 에이전트 | `egress_proxy` / `llm_proxy` | 사전 | 외부 유출, 비용 한도 |

하나의 에이전트를 여러 센서가 동시에 관측할 수 있다(예: Claude Code를 hook과 MCP 프록시가 함께 관측).
`AgentEvent.agent`(무엇이)와 `AgentEvent.source`(어떻게 봤는지)를 분리한 이유다.

## 설계 원칙

1. **탐지·차단은 로컬, 정책·가시성은 중앙.** 중앙과 연결이 끊겨도 마지막으로 받은 정책으로 계속 차단한다.
2. **스키마 우선.** 모든 어댑터는 `AgentEvent` v1으로만 말한다. 탐지 룰은 에이전트별 원시 포맷을 모른다.
3. **비밀은 엔드포인트를 떠나기 전에 마스킹한다.** 센서가 `arguments`/`output_preview`를 redact한 뒤 전송한다.
4. **응답 단계는 점진적이다.** `allow < alert < require_approval < block < abort_session < quarantine`.
   정책이 그룹별로 단계를 정하고, `Finding.response.enforced`에 실제 집행 여부를 남긴다.
5. **데모 재현성.** `docker compose up` 하나로 중앙 서버와 가상 직원 N명, 가상 외부망(악성 MCP, 유출 수신 서버)이 뜬다.

## 데모 토폴로지 (목표)

```
[corp-net]      control-plane(api, db, console) · endpoint-alice(OpenClaw) · endpoint-bob(Claude Code)
                endpoint-carol(LangGraph+MCP proxy) · endpoint-erin(Gemini CLI) · endpoint-frank(Codex CLI) · ollama
[internet-sim]  evil-mcp · exfil-sink · poisoned-repo
```

이후 단계에서는 실제 다른 PC나 VM의 센서가 등록 토큰으로 LAN이나 Tailscale을 통해 중앙에 붙는다.
