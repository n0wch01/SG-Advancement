# 팀 프로젝트(SG)에서 무엇을 왜 바꿨나

이 프로젝트는 팀 프로젝트 [ajou-samsung-giants](https://github.com/n0wch01/ajou-samsung-giants)(이하 SG)에서 출발했다.
SG는 **OpenClaw 게이트웨이 하나**를 대상으로 한 보안 가시화 MVP였고, 여기서는 그것을 **여러 종류의 에이전트를 중앙에서 관제하는 구조**로 다시 설계했다.
이 문서는 SG의 각 부분이 어디로 갔고, 무엇을 왜 바꿨는지를 정리한다.

## 한눈에

| 영역 | SG | 지금 | 바꾼 이유 |
|---|---|---|---|
| 대상 | OpenClaw 하나 | OpenClaw, Claude Code, MCP, LangGraph, (Gemini·Codex) | 실제 조직은 에이전트를 섞어 쓴다 |
| 이벤트 형식 | 게이트웨이 프레임을 거의 그대로 `trace.jsonl`에 기록 | 공통 스키마 `AgentEvent` v1 | 룰이 에이전트별 원시 형식을 몰라도 되게 |
| 탐지 | 배치 함수(`detect.py`)와 실시간 클래스(`RealTime*Detector`)가 같은 룰을 따로 구현 | 스트리밍 엔진 하나. 배치는 같은 코드로 replay | 두 구현이 서로 다르게 판정하는 문제 제거 |
| 룰 | 코드와 YAML이 섞임 | 선언형 YAML + 회귀 케이스 | 오탐·미탐을 케이스로 고정하고 튜닝 |
| 정책 배포 | 각 PC의 로컬 파일 | 중앙이 서명해서 배포, 센서가 검증·캐시 | 일관된 정책, 캐시 변조 방지 |
| 결과 저장 | 로컬 `findings-realtime.jsonl` | 중앙 Control Plane(SQLite → Postgres) | 여러 장비를 한 화면에서 |
| 장비 신원 | 없음 | 등록 토큰 → 장비 토큰, 사칭 거부 | 누가 보낸 데이터인지 보장 |
| 오프라인 | 고려 없음 | 디스크 대기열, 우선순위, 재전송 중복 제거 | 끊겨도 증거가 남게 |
| 대시보드 | `security-viz`가 게이트웨이와 로컬 파일을 직접 읽음 | 중앙 API를 읽는 콘솔(M7) | 장비가 여럿이 되면 직접 읽을 수 없다 |

## OpenClaw 연동 (M5)

SG의 `scripts/openclaw_ws.py`, `sentinel/ingest.py`, `sentinel/respond.py`가
[sensor/adapters/openclaw_gateway.py](../src/agent_sentinel/sensor/adapters/openclaw_gateway.py)와
[sensor/adapters/openclaw.py](../src/agent_sentinel/sensor/adapters/openclaw.py)로 옮겨왔다.

### 그대로 가져온 것

- 게이트웨이 프로토콜 v3 핸드셰이크(`connect.challenge` → `connect` → `hello-ok`)
- OpenClaw CLI의 장치 신원(`identity/device.json`)으로 connect에 서명하는 방식. 이게 없으면 게이트웨이가 요청한 권한(scope)을 깎는다.
- 시스템 프록시를 쓰지 않는 기본값. 루프백 연결이 프록시를 타면 게이트웨이가 페어링을 요구한다.
- 환경 변수 이름(`OPENCLAW_GATEWAY_TOKEN`, `OPENCLAW_DEVICE_IDENTITY_PATH` 등)

### 고친 것

| 문제 | SG에서 | 지금 |
|---|---|---|
| **자동 중단이 30초 멈춤** | 이벤트 처리기가 수신 루프 안에서 실행되고, 그 안에서 `sessions.abort` 응답을 기다렸다. 응답을 읽을 수신 루프가 처리기를 기다리고 있어서 교착 상태가 됐다. 요청은 게이트웨이에 가지만, 센서는 30초 타임아웃까지 다른 이벤트를 처리하지 못하고 실패로 기록했다 | 수신 루프는 이벤트를 큐에 넣기만 하고, 별도 작업이 순서대로 처리한다. 테스트로 재현해 잡았다 (`test_s1_plugin_tool_call_aborts_the_run`) |
| 필드 이름 추측 | 같은 값을 `name`, `tool`, `toolName`, `call.name` 등 여러 후보로 찾았다 | 설치된 OpenClaw(2026.4.15)의 게이트웨이 코드를 읽고 실제 프레임 모양에 맞췄다. 그 근거를 어댑터 docstring에 적었다 |
| 툴 결과가 비어 있음 | 툴 이벤트의 결과는 세션 verbose가 `full`일 때만 실린다. 기본 설정에서는 인젝션이 담긴 결과를 볼 수 없었다 | 트랜스크립트(`session.message`의 `toolResult`)에서 결과 텍스트를 가져온다. 툴 이벤트와 트랜스크립트에서 중복되지 않게 호출 ID로 한 번만 낸다 |
| 플러그인 툴 판별 경쟁 | (해당 없음: 툴 목록을 별도로 기록) | 연결하자마자 이벤트가 오면 어떤 툴이 플러그인인지 모르는 상태에서 판정하게 된다. **툴 목록을 먼저 받고 나서 구독**하고, 목록에 없는 툴이 나타나면 목록을 다시 받는다 |
| 세션 하나만 | `OPENCLAW_GATEWAY_SESSION_KEY`로 지정한 세션 하나 | `sessions.subscribe`는 원래 모든 세션의 툴 이벤트를 준다. 세션 키를 지정하지 않고 전부 관제한다 |
| 중단 기준 | 심각도(`high` 이상)로 중단 | 룰마다 정한 응답 단계(`block` 이상)로 중단. 정책에서 조절할 수 있다 |
| 중단 결과 | 로그 파일에만 | finding의 `response`에 실제 결과(`enforced`, 실패 사유)를 담아 중앙으로 |

### 알게 된 사실 (게이트웨이 코드 기준)

- 툴 이벤트는 모든 클라이언트에 방송되지 않는다. `sessions.subscribe`를 호출한 연결에만 `session.tool`로 간다.
- `sessions.abort`는 `key`와 선택 항목 `runId`만 받는다. 다른 키를 넣으면 거부한다(SG 주석의 "strict params"가 이것이다).
- 게이트웨이에는 셸 실행 승인 기능(`exec.approval.requested` 이벤트, `exec.approval.resolve` 메서드, `operator.approvals` 권한)이 있다.
  SG는 이 이벤트를 "approval" 종류로 분류만 했다. 지금은 센서가 승인 요청에 답해서, 셸 명령은 **실행 전에** 거절한다(`--gate-exec`).
  OpenClaw 연동이 "사후 중단만 가능"에서 "셸 명령은 사전 차단"으로 바뀐 부분이다.

## 탐지 엔진 (M2)

| SG | 지금 |
|---|---|
| `detect.py`의 배치 함수 + `RealTime{Rate,Pattern,Combined}Detector` | `Engine.process()` 하나. `Engine.replay()`도 같은 경로 |
| trace 줄의 `normalized` 요약을 정규식으로 검사 | `AgentEvent` JSON의 점 경로(`payload.arguments` 등)를 검사 |
| 룰 타입: trace_line_regex, event_payload_regex, tools_effective_diff, rate_limit, loop_detect, event_sequence | regex, allowlist, rate, repeat, sequence ([detection.md](detection.md)의 대응표) |
| 새 실행이 시작되면 탐지 상태 초기화 | 세션 단위로 상태 유지. 여러 실행에 걸친 공격(1번 실행에서 문서 읽기, 2번 실행에서 유출)도 잡는다 |
