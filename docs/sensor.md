# 센서 코어

직원 PC(엔드포인트)에 설치되는 부분이다([src/sg_advance/sensor/](../src/sg_advance/sensor/)).
UI 없이 CLI 하나(`sga-sensor`)로 동작하고, 서버용 패키지(FastAPI, SQLAlchemy)가 없어도 설치된다.
HTTP는 표준 라이브러리 `urllib`, 대기열은 표준 `sqlite3`를 쓴다. 추가 의존성은 서명 검증용 `cryptography` 하나다.

## 하는 일

```
어댑터 ─AgentEvent─▶ Sensor.process ─▶ 로컬 룰 엔진 ─▶ Verdict ─▶ 어댑터가 집행 (M5~)
                          └─▶ 마스킹 ─▶ Spool(디스크) ─flush─▶ Control Plane
```

1. **판정은 즉시, 전송은 나중에.** `process()`는 판정을 바로 돌려준다. 중앙 전송은 대기열을 거치므로
   서버가 느리거나 꺼져 있어도 에이전트를 기다리게 하지 않는다.
2. **탐지는 원본으로, 저장은 마스킹본으로.** 룰은 비밀값이 든 원본을 보고 판정한다(유출 탐지에 필요).
   디스크 대기열과 중앙에는 마스킹된 사본만 들어간다.
3. **장비 ID는 코어가 채운다.** 어댑터는 등록 정보를 몰라도 된다. 코어가 `endpoint.device_id`를 등록된 값으로 덮어쓴다.
   서버는 다른 장비 ID가 섞인 배치를 거부하므로(M3), 이 처리가 없으면 전송이 실패한다.

## 사용법

```bash
# 관리자: 등록 토큰 발급
curl -X POST http://127.0.0.1:8000/v1/admin/enrollment-tokens -H "Authorization: Bearer $ADMIN" \
     -H 'content-type: application/json' -d '{"label": "bob laptop"}'

# 직원 PC
export SGA_ENROLL_TOKEN=set_...          # 셸 기록과 프로세스 목록에 토큰이 남지 않게 환경 변수로
sga-sensor enroll --server http://127.0.0.1:8000 --device-id dev-bob
sga-sensor replay examples/events/claude_code.jsonl    # 이벤트 재생 → 판정 출력 → 전송
sga-sensor status                                       # 장비, 정책, 대기열 상태
sga-sensor sync                                         # 정책 갱신 + 대기열 전송
```

상태는 `~/.sg-advance/`(또는 `SGA_HOME`, `--home`)에 저장된다.

| 파일 | 내용 | 권한 |
|---|---|---|
| `credentials.json` | 서버 주소, 장비 ID·토큰, 신뢰하는 정책 공개키 | 0600 |
| `policy.json` | 마지막으로 받은 서명된 정책 | 0600 |
| `spool.db` | 보내지 못한 이벤트·finding | 기본 |

## 정책 서명과 공개키

서버는 시작할 때 Ed25519 키를 만들거나 읽어서(`SGA_SIGNING_KEY`) 정책 묶음에 서명한다.
서명 대상은 `version`(룰 내용의 sha256)이다. 그래서 센서는 두 가지를 확인한다.

1. 룰 내용을 다시 해시한 값이 `version`과 같은가 → 내용이 손상되지 않았다.
2. `version`의 서명이 신뢰하는 공개키로 검증되는가 → 서버가 만든 정책이다.

이 검사는 **네트워크에서 받을 때와 디스크 캐시를 읽을 때 모두** 한다. PC 사용자가 `policy.json`을 열어
룰을 끄고 해시까지 다시 계산해 넣어도, 서명이 맞지 않아 그 캐시는 쓰이지 않는다(`test_tampered_cache_is_never_used`).

공개키를 얻는 방법은 두 가지다.

| 방식 | 명령 | 설명 |
|---|---|---|
| A. 등록 응답에서 받기 (기본) | `enroll --server … ` | 등록 토큰으로 인증된 응답에 든 키를 처음 한 번 믿고 저장한다 |
| B. 설치할 때 고정 | `enroll … --pin-key <base64>` | 관리자가 `GET /v1/admin/policy`의 `public_key`를 설치 담당자에게 따로 전달한다 |

B는 등록 토큰을 쓰기 **전에** `/healthz`의 키 지문을 먼저 비교한다. 엉뚱한 서버에 붙으면 1회용 토큰을 버리지 않고 바로 중단한다.

## 중앙과 끊겼을 때

| 상황 | 동작 |
|---|---|
| 시작할 때 서버가 꺼져 있고, 유효한 캐시가 있다 | 캐시된 정책으로 계속 탐지한다 (`policy: offline`) |
| 시작할 때 서버가 꺼져 있고, 캐시가 없거나 변조됐다 | `NoPolicy` 오류. 어떤 정책으로 판정할지 알 수 없다 |
| 전송 중 네트워크 오류, 5xx, 408, 429 | 대기열에 그대로 두고 다음 `flush`에서 다시 보낸다 |
| 응답만 잃어버렸다 (서버는 저장함) | 다시 보내면 서버가 `duplicates`로 세고 버린다 |
| 401 (장비 토큰 거부) | 대기열을 유지하고 멈춘다. 다시 등록해야 한다 |
| 400·403·413 (같은 내용으로는 절대 성공 못 함) | 배치를 반으로 나눠 가며 문제 항목만 찾아 `dead`로 격리한다. 나머지는 전송된다 |
| 422 (서버가 센서보다 오래됨: 새 이벤트 종류·필드) | 문제 항목만 **보류**하고 1분·2분·4분… 최대 1시간 간격으로 다시 보낸다. 서버를 올리면 들어간다. 7일이 지나면 `dead` |
| 오래 끊겨서 대기열이 가득 찼다 (기본 5만 건) | **낮은 등급의 오래된 이벤트부터** 버리고 finding은 지킨다. 등급별로 버린 개수가 `status`에 나온다 |

## 대기열 우선순위

[priority.py](../src/sg_advance/sensor/priority.py). 오래 끊겨 있을 때 무엇을 남기고 무엇을 먼저 보낼지 정한다.

| 등급 | 무엇 | 예 |
|---|---|---|
| 3 긴급 | finding, 룰에 걸린 이벤트, finding이 증거로 가리키는 이벤트 | `.env` 유출 시도, 인젝션 문서를 읽은 직전 단계 |
| 2 높음 | 에이전트가 **한 일**과 **할 수 있는 것**, 사람이 **시킨 것** | `tool.call`, `net.egress`, `inventory.snapshot`, 세션 시작·종료, `prompt.user` |
| 1 보통 | 에이전트가 **본 것** | `tool.result` |
| 0 낮음 | 맥락용 대화 | `message.assistant`, `llm.call` |

- **버릴 때**: 낮은 등급부터, 같은 등급에서는 오래된 것부터 버린다. finding은 버리지 않는다.
- **보낼 때**: 높은 등급부터 보낸다. 같은 등급에서는 이벤트를 finding보다 먼저 보낸다(콘솔이 증거를 바로 찾을 수 있게).
- **증거 승격**: 시퀀스 룰은 앞 단계 이벤트가 그 자체로는 평범하다(예: 문서를 읽은 `tool.result`).
  finding이 생기는 순간 그 앞 단계 이벤트들을 긴급으로 올려서, 대기열이 넘쳐도 증거가 사라지지 않게 한다.
- **맥락 승격**: finding이 증거로 꼽지 않았더라도, **같은 세션에서 직전 10분**(`context_seconds`) 안의 이벤트는 모두 긴급으로 올린다.
  실제 사건 대부분이 에이전트가 읽은 이슈·티켓·메일에서 시작했지만, 그 텍스트는 룰에 안 걸리는 경우가 많았다([incidents.md](incidents.md)).
- **사용자 프롬프트는 높음**: 사용자가 공격자인 경우(GTG-1002)와, 에이전트가 사용자 지시를 어긴 경우(Replit)의 근거가 된다.
- 등급표는 지금 코드에 있다. M9에서 중앙 정책으로 옮겨 그룹별로 바꿀 수 있게 할 수 있다.

## 로컬 데몬 (`sga-sensor run`)

[daemon.py](../src/sg_advance/sensor/daemon.py). 엔드포인트마다 하나 떠 있는 프로세스다.
룰 엔진을 데몬이 들고 있어서, 시퀀스·빈도 룰이 이 PC의 모든 어댑터에서 오는 이벤트를 함께 본다.

```bash
export OPENCLAW_GATEWAY_TOKEN=...                       # 게이트웨이 토큰은 환경 변수로만 받는다
sga-sensor run --openclaw                          # 기본 ws://127.0.0.1:18789
sga-sensor run --openclaw --observe-only           # 탐지·보고만, 실행 중단은 하지 않음
sga-sensor run --openclaw --gate-exec              # 셸 명령 승인 요청에 답한다 (위험하면 실행 전 거절)
sga-sensor run --openclaw --capture frames.jsonl   # 게이트웨이 원본 프레임을 마스킹해서 기록 (디버깅)
sga-sensor run --replay examples/events/*.jsonl    # 데모용: 파일을 재생
```

| 하는 일 | 주기 | 비고 |
|---|---|---|
| 어댑터 실행 | 계속 | 어댑터 하나가 죽어도 나머지는 계속 돈다 |
| 정책 동기화 | 60초 (`--sync-interval`) | 실패하면 마지막 정책 유지 |
| 대기열 전송 | 5초 (`--flush-interval`) | 종료할 때 한 번 더 |
| 처음 정책 받기 | 받을 때까지 재시도 | 중앙이 아직 안 떴을 수 있다(컨테이너 기동 순서). 그동안 판정은 하지 않는다 |

네트워크 호출은 작업 스레드에서 돌아서, 중앙이 느려도 이벤트 처리가 밀리지 않는다.
OpenClaw 플러그인(M5c)과 Claude Code hook(M6)처럼 툴 실행 직전에 판정을 물어야 하는 쪽을 위한 로컬 소켓은 M5c에서 붙인다.

## OpenClaw 어댑터

[adapters/openclaw.py](../src/sg_advance/sensor/adapters/openclaw.py). 설치: `sg-advance[openclaw]`(websockets).
SG 코드에서 무엇을 가져오고 고쳤는지는 [from-sg.md](from-sg.md#openclaw-연동-m5)에 있다.

| 게이트웨이에서 | AgentEvent로 |
|---|---|
| `tools.catalog` 응답 | `inventory.snapshot` (툴, 플러그인). 연결할 때, 5분마다, 목록에 없는 툴이 보일 때 |
| `agent` lifecycle `start` | `session.start` (세션 키마다 처음 한 번) |
| `session.tool` `phase: start` | `tool.call` (`provider`는 툴 목록으로 플러그인·내장 구분) |
| `session.tool` `phase: result` | `tool.result`. 결과 텍스트는 아래 순서로 구한다 |
| `agent` `command_output` `end` | 셸 명령의 출력 → 위 `tool.result`의 `output_preview` |
| `chat.history` 응답 | 셸이 아닌 툴의 결과. 같은 세션의 다음 툴 호출·응답·실행 종료 **직전에** 가져온다 |
| `session.message` role `user` / `assistant` | `prompt.user` / `message.assistant` |

- **집행은 사후다.** 게이트웨이는 툴이 이미 시작된 뒤에 알려준다. 판정이 `block` 이상이면 `sessions.abort`로 그 실행을 중단하고,
  결과(`enforced`, 실패 사유)를 finding의 `response`에 담는다. 같은 실행은 한 번만 중단한다.
- **셸 명령은 실행 전에 막을 수 있다** (`--gate-exec`). OpenClaw의 exec 정책이 승인을 요구하도록 설정돼 있으면, 게이트웨이는 명령을 실행하기 전에
  `exec.approval.requested`를 보낸다. 센서는 그 명령을 `tool.call`(라벨 `openclaw.phase=exec-approval`)로 판정한다.

  | 판정 | 센서가 하는 일 | finding의 `response.detail` |
  |---|---|---|
  | `block` 이상 | `exec.approval.resolve {decision: deny}` | `pre-exec: exec.approval denied` |
  | `require_approval` | 아무것도 안 함. OpenClaw의 승인 창에서 사용자가 결정 | `left to the user: OpenClaw exec approval` |
  | `allow`, `alert` | 아무것도 안 함. 평소처럼 사람이 결정 | (alert면 기록만) |

  센서는 **거절만** 하고 허용은 하지 않는다. 허용까지 하면 사람이 보던 승인 창을 센서가 대신 닫아 버리기 때문이다.
  승인된 명령이 실제로 실행되면 `session.tool`로 한 번 더 들어오므로, 같은 명령이 두 번 판정된다(finding은 중복 제거되지만 빈도 룰은 두 번 센다).
- 그 밖의 툴에서 `require_approval`은 아직 집행하지 못한다(alert로 기록).
- 권한: 관측만 하면 `operator.read`, 중단까지 하면 `operator.write`, 셸 승인에 답하려면 `operator.approvals`.
- 연결이 끊기면 1초부터 최대 60초까지 늘려 가며 다시 붙는다.

### 게이트웨이에 붙는 방법 (프로토콜 v3·v4)

센서는 **자기 장치 신원**(Ed25519 키, `SGA_HOME/openclaw-device.json`, 0600)을 처음 실행할 때 만들고, 다른 외부 클라이언트처럼 페어링한다.
OpenClaw CLI의 키를 빌려 쓰지 않는다. 그래서 센서는 필요한 권한만 갖고, `openclaw devices list`에 따로 보이며, 따로 폐기할 수 있다.

```bash
openclaw configure --section gateway          # 1. 게이트웨이 공용 토큰 설정 (기본값은 실행마다 바뀌는 임시 토큰이라 외부 클라이언트가 못 붙음)
export OPENCLAW_GATEWAY_TOKEN=...             # 2. 처음 한 번, 공용 토큰으로 접속
sga-sensor run --openclaw                #    → "pairing required — openclaw devices approve <requestId>" 로그
openclaw devices approve <requestId>          # 3. 게이트웨이 호스트에서 승인 → 센서가 deviceToken을 받아 저장
sga-sensor run --openclaw                # 4. 이후에는 공용 토큰 없이 deviceToken으로 접속
```

- 접속할 때 프로토콜 3~4를 지원한다고 알린다. 2026.4.15(v3)와 2026.11.3(v4) 게이트웨이 모두에 붙는다.
- v4는 **`tool-events` 기능을 선언한 연결에만 툴 이벤트를 보낸다.** 선언하지 않으면 오류 없이 툴 이벤트만 빠진다. 센서는 `tool-events`, `exec-approvals`를 선언한다.
- 장치 증명의 서명 시각은 `connect.challenge`의 `ts`를 쓴다. 장치 ID는 공개키의 sha256이다(게이트웨이가 검사한다).
- `deviceToken`으로 접속할 때는 그 토큰이 발급된 권한만 요청한다. 권한을 늘리면 새 페어링 승인이 필요하다.

### 실제 게이트웨이 확인 (2026-11-11, OpenClaw 2026.11.3, 프로토콜 v4)

Codex 구독 모델 + OpenClaw 런타임으로 확인했다(실행 한 번에 약 10초).

| 항목 | 결과 |
|---|---|
| 프로토콜 협상, 센서 자체 장치 신원 | ✅ v4로 접속. 공용 토큰을 가진 루프백 클라이언트는 **페어링 없이** 요청한 권한을 전부 받았다(`hello-ok.auth.method: token`) |
| `tool-events` 선언 → 툴 이벤트 | ✅ `session.tool` start/result, `command_output` 수신 |
| Code Mode | ⚠️ 새 구조: 바깥 `exec`(JavaScript) 안에서 안쪽 `exec`(실제 셸 명령, `parentToolCallId`)가 돈다. 둘 다 `tool.call`로 내고 라벨로 잇는다. 명령은 JS에서 조립될 수 있으므로 안쪽 호출이 기준이다 |
| 대화 기록 메시지 | ⚠️ 같은 사용자 메시지가 **같은 ID로 두 번** 왔다 → 메시지 ID로 중복 제거 |
| 실행 중 `sessions.abort` | ❌ `unauthorized`. v4는 그 실행을 시작한 장치·연결이거나 `operator.admin`일 때만 중단을 허락한다 |
| 셸 실행 전 거절 (CLI) | CLI(`openclaw agent`)에서 시킨 실행은 대화형 승인을 요청할 수 없어 OpenClaw가 명령 자체를 막았다 |
| 셸 실행 전 거절 (Control UI, OpenClaw 런타임) | ❌ 승인 창은 떴지만 **센서에는 승인 요청이 오지 않았다**. v4는 승인 요청을 `operator.admin`, 요청한 본인, 지정된 승인 검토자 장치에게만 보여준다(`isApprovalRecordVisibleToClient`) |
| 같은 명령, Codex 런타임 | ⚠️ 승인이 **Codex 자체 경로**("Codex app-server command approval")로 처리됐다. 센서는 툴 호출(`bash`, `rm -rf …`)을 **실행 전에** 받아 block으로 판정했지만 막을 수단이 없었다 |
| 런타임 선택 | ⚠️ 런타임 고정은 **모델별**이다. 화면에서 고정하지 않은 모델을 고르면 Codex 런타임으로 바뀐다. 이미 Codex 스레드에 묶인 세션은 설정을 바꿔도 Codex로 남는다 |

**결론 (결정 B, 2026-11-11)**: v4에서 WebSocket 어댑터는 **관측과 탐지**를 맡는다. 실행 중단(`sessions.abort`)과 승인 거절은 `operator.admin` 없이는 할 수 없고,
admin을 센서에 주는 것은 너무 넓은 권한이다. **실행 전 차단은 M5c 게이트웨이 플러그인(`before_tool_call`)이 맡는다.**
플러그인은 게이트웨이 안에서 돌므로 이 권한 문제가 없고, 문서상 Codex 네이티브 툴도 차단할 수 있다.
`--gate-exec`는 v3 게이트웨이와 admin을 받은 배치에서만 효과가 있다.

v4 녹화 프레임은 [openclaw-2026.11.3-tool-run.jsonl](../tests/fixtures/openclaw-2026.11.3-tool-run.jsonl)에 회귀 테스트로 고정했다.

### 실제 게이트웨이 확인 (2026-11-10, OpenClaw 2026.4.15)

| 항목 | 결과 |
|---|---|
| 핸드셰이크, 장치 서명, `operator.approvals`까지 권한 요청 | ✅ 페어링 추가 승인 없이 연결 |
| `tools.catalog` → 인벤토리 | ✅ 코어 툴 32개, 플러그인 0개 |
| `agent` lifecycle, `session.message`(user/assistant) | ✅ 실제 프레임 모양이 매퍼 가정과 일치 |
| 셸 승인: 위험 명령 | ✅ 실제 `exec.approval.requested` → 센서가 `deny` → 요청자가 `decision: deny`를 받음 |
| 셸 승인: 평범한 명령 | ✅ 건드리지 않음 → 시간 만료(`decision: null`) |
| `session.tool` 툴 호출·결과 (qwen3:8b로 실제 실행) | ✅ `exec` 호출과 출력까지 수집 |
| 툴 결과 텍스트 | ⚠️ 가정과 달랐다: `toolResult` 메시지는 **푸시되지 않는다**. 셸은 `command_output`, 그 밖의 툴은 `chat.history`로 구하도록 고쳤다 |
| 실행 중 `sessions.abort` | ✅ 게이트웨이가 수락(`enforced: true`). ⚠️ 하지만 `rm -rf`는 이미 끝난 뒤였다. 빠른 명령은 사후 중단으로 못 막는다 → 셸은 `--gate-exec`가 필요한 이유 |
| 실제 에이전트 흐름에서 `--gate-exec` | ⏳ 미확인. OpenClaw의 exec 정책이 승인을 묻지 않는 설정이라, 승인 요청은 테스트 클라이언트로만 확인했다 |

녹화한 실제 프레임(호스트·사용자 정보 제거)은 [openclaw-2026.4.15-frames.jsonl](../tests/fixtures/openclaw-2026.4.15-frames.jsonl)(승인 요청)과
[openclaw-2026.4.15-tool-run.jsonl](../tests/fixtures/openclaw-2026.4.15-tool-run.jsonl)(툴 실행)에 회귀 테스트로 고정했다.
에이전트 한 번 실행에 qwen3:8b로 약 5분(첫 실행, MacBook Air M3)이 걸렸다.
`exec.approval.resolved`에는 결정자(`resolvedBy`)가 들어 있어, M7의 사용자 승인 감사에 그대로 쓸 수 있다.

### 대화 원문 최소화

`prompt.user`와 `message.assistant`는 룰에 걸린 것만 원문을 대기열에 넣는다. 나머지는 `withheld: true`와 글자 수(`text_chars`)만 남기고
`raw`도 뺀다. 탐지는 이미 원문으로 끝났으므로 영향이 없다. `sga-sensor run --keep-chat-text`로 끌 수 있다. 결정 배경과 한계는
[team-gateway.md](team-gateway.md#데이터-최소화)에 있다.

### egress 프록시 (M5d)

`sga-sensor run --egress-proxy 0.0.0.0:3128 [--egress-enforce] [--egress-internal-suffix .corp]`: HTTP 프록시(CONNECT 포함)로 동작하며
연결마다 `net.egress`(목적지, 내부/외부)를 만들어 룰로 판정한다. 기본은 감시 모드, `--egress-enforce`면 차단 판정에 403.
구성과 결정은 [team-gateway.md](team-gateway.md#egress-에이전트-망의-유일한-출구-m5d).

### 팀 게이트웨이 (M5b)

여러 직원이 쓰는 게이트웨이에서는 툴 호출을 시킨 사람으로 기록한다(`users.list`, 사용자 메시지의 `senderIdentity`, 대화 주인).
같은 호스트의 센서는 게이트웨이 비밀번호로 접속한다(`OPENCLAW_GATEWAY_PASSWORD` 또는 `--openclaw-password-file`, 0600).
감사 프록시는 `sga-sensor run --openclaw-audit-proxy HOST:PORT --openclaw-audit-upstream URL --audit-trusted-peer IP`로 띄운다.
구성과 실환경 결과는 [team-gateway.md](team-gateway.md)에 있다.

## OpenClaw 플러그인 (실행 전 차단, M5c)

[integrations/openclaw-plugin/](../integrations/openclaw-plugin/). 게이트웨이 안에서 `before_tool_call` hook으로 **모든 툴 호출을 실행 전에** 판정한다.
v4 게이트웨이는 외부 클라이언트에게 실행 중단·승인 열람을 `operator.admin` 없이는 허락하지 않으므로, 차단은 이 플러그인이 맡는다(결정 B).

```
OpenClaw agent ─ before_tool_call ─▶ 플러그인 ──JSON 한 줄──▶ unix 소켓 (SGA_HOME/sga.sock, 0600)
                                        ◀── {decision: allow | block | approve} ── 센서 데몬 (룰 엔진, 기록)
```

| 데몬 판정 | 플러그인이 하는 일 | finding의 `response.detail` |
|---|---|---|
| `block` 이상 | `{block: true}` — 툴이 실행되지 않는다 | `pre-exec: openclaw plugin blocked the tool call` |
| `require_approval` | `requireApproval` — OpenClaw 승인 창에서 **사용자**가 결정 (한 번 허용 / 거부만, 영구 허용은 막음) | `pre-exec: user approval requested through OpenClaw` |
| `allow`, `alert` | 아무것도 하지 않음 | (alert면 기록만) |

**판정할 수 없을 때** (방향 섹션의 단계적 처리):

| 상황 | 플러그인 동작 | 기록 |
|---|---|---|
| 데몬 정상 | 데몬 판정 (시퀀스·빈도 룰 포함) | 이벤트 `source.sensor = openclaw_plugin` |
| 데몬이 응답 없음 | `sga-sensor evaluate` 실행 → 서명된 정책 캐시로 판정 (상태 없는 룰만) | `labels.sga_verdict = degraded` |
| 캐시도 없음 | 읽기 전용 툴(`read`, `memory_search`, `memory_get`, `session_status`)만 통과, 나머지는 사용자 승인 | 기록 없음 (센서가 없으므로) |

`before_tool_call`은 핸들러가 예외를 던지거나 15초를 넘기면 OpenClaw가 그 호출을 **막는다**. 플러그인은 예외를 밖으로 내지 않고 위 순서로 직접 처리한다.

**우회 탐지**: 플러그인이 판정한 호출 ID는 데몬에 등록된다. WebSocket 어댑터는 등록된 호출을 다시 판정하지 않고(중복 방지),
플러그인이 최근 5분 안에 연결된 상태인데 등록되지 않은 호출을 보면 `labels.sga_plugin = missing`을 붙인다.
룰 `openclaw-plugin-bypass`(alert)가 이를 finding으로 만든다. 플러그인이 꺼졌거나 우회된 실행 경로를 보안팀이 알 수 있다.

### 승인 감사 (C)

룰이 `require_approval`이면 플러그인이 OpenClaw 승인 창을 띄운다. 사용자의 응답(`onResolution`)은 **세 경로 모두**
(데몬 판정, 캐시 정책 판정, 위험도 기본값) `approval.resolved` 이벤트로 남는다. 데몬이 없을 때 승인된 행동이야말로
감사가 필요한 것이라, 데몬에 못 보내면 `sga-sensor evaluate`(CLI)가 대기열에 바로 넣는다.

- 데몬은 승인 창을 띄운 호출의 맥락(원래 `tool.call` 이벤트 id, 그 finding id, 걸린 룰, 최고 심각도, 요청 시각)을 기억해 응답에 붙인다.
  데몬이 그 사이 재시작했으면 플러그인이 보낸 사본(룰, 심각도, 요청 시각)을 쓴다.
- OpenClaw는 **누가 승인 버튼을 눌렀는지** 플러그인에 알려 주지 않고, 내부에도 앱 이름(`openclaw-control-ui`)만 저장한다.
  개인 게이트웨이에서는 `approver`가 비어 있고, 실행을 시작한 요청자(`requester_channel`, `requester_senderid` 라벨)만 남는다.
  팀 게이트웨이에서는 신원 프록시 뒤의 **감사 프록시**가 승인한 사람을 `operator.action`으로 기록하고, 감사 API가 이를 `approver`로 붙인다
  ([team-gateway.md](team-gateway.md)).

| 응답 | 룰 (모두 `alert`, 보안팀 사후 감사) |
|---|---|
| high/critical 룰에 걸린 행동을 승인 | `user-approved-high-risk` (medium) |
| 한 사용자가 10분 안에 5번 승인 (세션 무관) | `approval-fatigue` (medium) |
| 거절, 시간 초과, 취소, medium 이하 승인 | 기록만 |

보안팀 조회: `GET /v1/admin/approvals`, `sga-server audit approvals` ([control-plane.md](control-plane.md)).

### 플러그인 신호 감시

플러그인은 60초마다 데몬에 인사(`hello`)를 보낸다. 데몬은 한 번이라도 인사를 받으면 그 뒤로 **이 장비에는 플러그인이 있어야 한다**고 기억한다
(`<home>/plugin-state.json`, 데몬을 재시작해도 유지). 그래서 플러그인을 끄고 기다리거나 데몬을 재시작해도 우회 탐지가 꺼지지 않는다.

| 상황 | 이벤트 | 룰 |
|---|---|---|
| 플러그인이 언로드되며 `bye`를 보냈고 30초 안에 새 인사가 없음 (10초마다 점검) | `sensor.health` `status: lost` | `openclaw-plugin-heartbeat-lost` (alert, high) |
| 마지막 인사 후 150초가 지남 (게이트웨이가 죽는 등 `bye`를 못 보낸 경우) | `sensor.health` `status: lost` (한 번만) | 같은 룰 |
| 끊긴 뒤 다시 인사가 옴 | `sensor.health` `status: recovered` | 없음 (기록만) |
| 신호가 끊긴 동안 실행된 툴 호출 | `tool.call` + `labels.sga_plugin: missing` | `openclaw-plugin-bypass` |

`sensor.health`는 이번에 추가한 이벤트 종류다. 툴 호출이 아니라 **통제 장치 자체의 상태**를 나타낸다.

플러그인은 OpenClaw가 인스턴스를 정리할 때(`api.lifecycle.onDispose`) 인사 타이머를 멈추고 `bye`를 보낸다.
OpenClaw는 플러그인의 타이머를 대신 멈추지 않으므로, 이걸 안 하면 판정 hook이 빠진 뒤에도 인사가 계속 간다(아래 실환경 결과).
`bye` 뒤 30초를 기다리는 이유는 정상적인 게이트웨이 재시작이나 플러그인 교체에서는 새 인스턴스가 몇 초 안에 인사하기 때문이다.

### 상시 운영

```bash
sga-sensor enroll --server http://127.0.0.1:18100 --device-id my-mac   # 센서 폴더: ~/.sg-advance
install -m 600 /dev/stdin ~/.sg-advance/openclaw-token <<< "<gateway token>"  # 토큰은 파일로 (0600 아니면 거부)
sga-sensor service install --openclaw     # macOS LaunchAgent: 로그인 시 시작, 죽으면 재시작
sga-sensor service status | uninstall
```

- 서비스 정의(plist)에는 비밀값이 들어가지 않는다. 게이트웨이 토큰은 `<home>/openclaw-token`에서 읽는다(`OPENCLAW_GATEWAY_TOKEN`이 있으면 그것을 우선).
- 로그는 `<home>/logs/sensor.log`. Linux는 `--dry-run`으로 systemd 사용자 유닛만 출력한다.
- 중앙 서버는 `docker compose up -d`(재시작 정책 `unless-stopped`)로 상시 띄운다.

### 실제 게이트웨이 확인 (2026-11-11, OpenClaw 2026.11.3)

같은 요청(`rm -rf /tmp/sentinel-test/junk`)을 Control UI에서 보냈다. 네 경우 모두 폴더는 지워지지 않았다.

| 경우 | 결과 |
|---|---|
| OpenClaw 런타임 (GPT-6-Luna) | ✅ 플러그인이 차단. 툴 출력에 `SG-Advance: 파괴적 셸 명령`. finding 집행 주체 `openclaw_plugin` |
| **Codex 런타임** (GPT-6.1-Sol, 런타임 고정 없음) | ✅ **Codex 네이티브 툴도 차단**. `codex_app_server.hook` 중계로 플러그인이 호출됐다. 지난 시험에서 "탐지만 하고 못 막던" T19 상황이 해소됐다 |
| 데몬 꺼짐 | ✅ 플러그인이 `sga-sensor evaluate`로 캐시 판정해 차단. `sga_verdict: degraded`로 대기열에 남았다가 데몬이 돌아오자 전송됐다 |
| 순서 경쟁 | ⚠️ 실제 게이트웨이는 툴 시작 이벤트를 플러그인 요청과 **같은 순간**에 보낸다. 처음엔 WS 어댑터가 먼저 판정해 우회로 오탐했다 → 어댑터가 최대 3초(`plugin_grace`) 플러그인 판정을 기다리도록 고쳤다 |

상시 운영 상태(LaunchAgent 데몬 + compose 중앙 서버)에서 플러그인을 끄고 다시 켰다.

| 시각 (KST) | 일어난 일 | 결과 |
|---|---|---|
| 16:07:30 | 마지막 인사 | |
| 16:07:47 | `openclaw plugins disable sg-advance` 후 게이트웨이 재시작 | WS 센서는 16:08:04에 자동 재연결 |
| 16:10:11 | 마지막 인사 후 161초 | ✅ `sensor.health lost` → `openclaw-plugin-heartbeat-lost` (high) |
| 16:10:52 | 에이전트가 `pwd` 실행 (플러그인 없이 그대로 실행) | ✅ `openclaw-plugin-bypass` (high) |
| 16:12:27 | `plugins enable` 후 게이트웨이 재시작, 인사 재개 | ✅ `sensor.health recovered` |

- ~~`plugins disable`만으로는 실행 중인 게이트웨이에서 플러그인이 내려가지 않는다~~ → **틀린 결론이었다**(아래 재시험).
  재시작 전까지 인사가 계속 온 것은 플러그인이 타이머를 정리하지 않았기 때문이고, 판정 hook은 이미 빠져 있었다.

재시험 (같은 날, 재시작 없이 `plugins disable`만):

| 시각 (KST) | 일어난 일 | 결과 |
|---|---|---|
| 17:46:01 | `plugins disable sg-advance` | 설정 파일 변경 |
| 17:46:02 | 설정 감시(M5d) | ✅ `openclaw-guard-plugin-disabled` (high), 1초 |
| 17:46:51 | 에이전트가 `pwd` 실행 | ⚠️ **판정 없이 실행됨**(hook은 즉시 빠진다). WS가 `openclaw-plugin-bypass`로 잡음 |
| 17:46:36~ | 인사 | ⚠️ 계속 옴 → "인사 = 판정 중"이 성립하지 않았다 |

`onDispose` 정리와 `bye`를 넣은 뒤 (게이트웨이 재시작으로 새 코드 로드, 다시 `plugins disable`만):

| 시각 (KST) | 일어난 일 | 결과 |
|---|---|---|
| 17:55:21.71 | 설정 감시 | ✅ `openclaw-guard-plugin-disabled` |
| 17:55:21.96 | 플러그인이 정리되며 `bye` | 데몬 로그 `openclaw plugin unloaded` |
| 17:56:01 | `bye` 후 30초 + 점검 주기 | ✅ `openclaw-plugin-heartbeat-lost` "unloaded by the gateway and did not return within 30s" |
| 이후 | 인사 | ✅ 멈춤 |

끄는 순간 설정 finding, 40초 안에 끊김 finding, 그 사이 실행된 툴은 우회 finding. 세 신호가 서로를 받쳐 준다.

## OpenClaw 설정 기준선 감시 (M5d)

`sga-sensor run --openclaw`은 게이트웨이와 함께 그 설정 파일(`~/.openclaw/openclaw.json`, `--openclaw-config`로 변경,
`--no-openclaw-config`로 끔)도 2초마다 확인한다. 보안에 관련된 값이 바뀌면 `config.snapshot` 이벤트를 보낸다(시작할 때 한 번 더).

- **허용 목록만 보낸다.** 설정 파일에는 게이트웨이 토큰과 계정 이메일이 들어 있다. 아래 값만 골라 보내고 원본은 보내지 않는다.
  토큰만 바뀐 경우처럼 이 값들이 그대로면 이벤트도 없다.
- 플러그인을 끄면 설정이 먼저 바뀌므로, **끄는 순간** 잡는다(신호 감시보다 빠르다).

| 필드 | 읽는 설정 | 룰 (모두 `alert`) |
|---|---|---|
| `guard_plugin` | `plugins.enabled`, `plugins.allow/deny`, `plugins.entries.sg-advance.enabled`, 설치·로드 경로 | `openclaw-guard-plugin-disabled` (high): `disabled` 또는 `missing` |
| `exec_policies[]` | `tools.exec.security/ask/mode/host`, `tools.elevated.enabled`, 에이전트별 `tools` | `openclaw-exec-policy-unsafe` (high): `full` 또는 `ask=off` / `openclaw-elevated-exec-enabled` (medium) |
| `runtimes[]` | 모델별 `agentRuntime.id` (에이전트 > 기본 에이전트 > 프로바이더 모델 > 프로바이더), 에이전트 `runtime.type: acp` | `openclaw-runtime-unapproved` (medium): `openclaw`, `codex` 외 전부 |
| `sandboxes[]` | `agents.defaults.sandbox`·에이전트별 `sandbox`(mode, workspaceAccess, scope), `agents.defaults.elevatedDefault`. 설정이 없으면 OpenClaw 기본값(mode `off`, elevatedDefault `on`)을 `mode_source: default`로 채움 | `openclaw-sandbox-off` (medium): 실제로 꺼져 있으면 (기본값 포함) |
| `plugins[]` | 플러그인 id·버전·켜짐 | (인벤토리용, 룰 없음) |

결정(2026-11-11): 대응은 알림만(설정을 건드리지 않음), exec는 위험한 값만 위반(기본값과 더 엄격한 값은 통과),
런타임은 플러그인 차단을 실환경에서 확인한 `openclaw`와 `codex`만 허용. `auto`, CLI 백엔드(`claude-cli` 등), ACP 하네스,
**고정하지 않은 모델**(`default`)은 위반이다. CLI 백엔드나 ACP 하네스에서는 툴이 게이트웨이 hook을 거치지 않을 수 있다.

오탐·미탐:
- 고정하지 않은 모델을 위반으로 보므로, OpenClaw 기본 설치는 처음에 `openclaw-runtime-unapproved`에 걸린다(기준선이 "모든 모델 고정").
- 점검·업그레이드로 잠시 플러그인을 꺼도 걸린다.
- `utilityModel`, `decisionModel`은 아직 보지 않는다(미탐 가능).
- 설정 파일을 거치지 않는 변경(실행 중 RPC로만 바꾼 값)은 보지 못한다.

## 설치된 코드 무결성 (M5d)

`sga-sensor run --openclaw`은 5분마다, 그리고 정책의 매니페스트가 바뀔 때마다 OpenClaw가 실제로 로드한 코드를 검사한다
(`--integrity-interval`, `--no-openclaw-integrity`).

1. `openclaw plugins list --json`으로 로드된 플러그인의 위치·출처(`bundled`/`global`/`config`)·버전을 받는다.
   **출처 표시는 참고만 한다.** OpenClaw가 스스로 말하는 값이라 본체가 변조되면 거짓일 수 있다.
2. 플러그인 폴더와 OpenClaw 본체를 해시한다(`integrity.dir_digest`, `node_modules` 제외). 본체 + 플러그인 45개에 약 3초.
3. 정책의 매니페스트(서버가 npm 서명·출처로 검증한 배포본의 해시, [control-plane.md](control-plane.md))와 비교해
   `integrity.report`를 보낸다(결과가 바뀔 때만).

| 결과 | 뜻 | 룰 |
|---|---|---|
| `verified` + `approved`/`trusted` | 서명된 배포본과 같은 파일 | 없음. 이름 기반 룰의 허용 목록에도 자동으로 들어간다(`allow_trusted: openclaw_plugins`) |
| `mismatch` | 배포본과 다르거나, 배포본에 없는 플러그인이 기본 플러그인 폴더에 있음 | `openclaw-plugin-tampered` (critical, **격리**: `openclaw plugins disable`) / 본체면 `openclaw-core-tampered` (critical, 알림) |
| `pending` | 이 버전의 매니페스트가 아직 없음 (서버가 자동 검증 중) | `openclaw-version-unapproved` (medium) |
| `verified` + `cooling` | 서명은 확인, 출시 3일 미만 | `openclaw-version-unapproved` (medium) |
| `unknown` | npm 출처가 아니고 고정(pin)도 없음 | 이름 기반 `unapproved-plugin-installed` (기존 S1 룰) |

- 격리는 **변조가 증명된 경우만**(결정 2026-11-11). SG-Advance 플러그인 자신은 끄지 않는다(통제만 사라지므로).
- 마지막 검증 결과(신뢰된 플러그인 id)는 `<home>/trusted.json`에 저장한다. 재시작 직후 첫 검사 전에 들어온 인벤토리가 오탐을 내지 않게 하려는 것이다.
- LaunchAgent는 설치할 때의 `PATH`를 가진다(launchd 기본 PATH로는 `openclaw`·`node`를 못 찾는다). 비밀값은 여전히 넣지 않는다.

실환경 (2026-11-11, OpenClaw 2026.11.3):

| 시각 (UTC) | 일어난 일 |
|---|---|
| 13:23:07 | 첫 검사: 본체·플러그인 44개 `pending` → `openclaw-version-unapproved` |
| 직후 | 서버가 `openclaw@2026.11.3`(구성요소 71개), `@openclaw/codex@2026.11.3`을 npm 서명 + Sigstore 출처로 자동 검증, 둘 다 `cooling` (11-13 이후 `trusted`) |
| 13:24:29 | 센서가 새 정책으로 재검사: 본체 + 플러그인 44개 **서명된 배포본과 일치**, 남은 것은 아직 고정하지 않은 `sg-advance`(`unknown`) |

보안팀 승인(`manifest approve` 2건 + `manifest pin sg-advance`) 뒤 14:52:21 재검사: 45개 모두 `verified` + `approved`,
신뢰 목록 45개 → 이후 센서 재시작에서 이름 기반 `unapproved-plugin-installed` 오탐이 더 나오지 않았다.

변조 시험 (같은 날, `talk-voice` 폴더에 파일 하나를 끼워 넣음):

| 시각 (UTC) | 일어난 일 | 결과 |
|---|---|---|
| 14:53:16 | `dist/extensions/talk-voice/sga-tamper-test.js` 추가, 센서 재시작(시작할 때 검사) | |
| 14:53:35 | 검사: `plugin:talk-voice` 해시가 배포본과 다름 | ✅ `openclaw-plugin-tampered` (critical) |
| 14:53:44 | 격리 | ✅ `openclaw plugins disable talk-voice` 실행, `enforced: true`. 설정 감시도 플러그인 변경을 기록 |
| 이후 | 파일 삭제 → 해시가 배포본과 다시 일치, `plugins enable talk-voice`로 복구 | |

한계: 확인한 순간의 파일만 보장한다(설치 폴더가 사용자 권한으로 쓰기 가능). `node_modules`(npm이 따로 설치한 의존성)는 보지 않는다.
설정에 따라 실행 중 메모리에만 있는 변경은 보지 못한다.

### 설치

```bash
openclaw plugins install --link "$PWD/integrations/openclaw-plugin" --force --accept-capabilities
openclaw plugins enable sg-advance --accept-capabilities
openclaw config set 'plugins.entries["sg-advance"].config.sensorHome' '"~/.sg-advance"' --strict-json
openclaw config set 'plugins.entries["sg-advance"].config.sensorCli' '"<venv>/bin/sga-sensor"' --strict-json
sga-sensor run --openclaw          # 데몬이 <home>/sga.sock을 연다 (--socket으로 바꿀 수 있음)
```

- `--force`는 ClawHub 검토를 받지 않은 로컬 소스라는 확인, `--accept-capabilities`는 서드파티 플러그인 권한 동의다. 회사 배포에서는 이 두 단계를 보안팀이 한다.
- unix 소켓 경로는 104바이트(macOS)를 넘을 수 없다. 센서 폴더가 깊으면 `--socket`과 플러그인 `socketPath`를 짧은 경로로 맞춘다.
- 테스트: `node --test integrations/openclaw-plugin/policy.test.ts`(Node ≥ 22.18), Python 쪽은 `tests/test_plugin_api.py`(실제 TypeScript 코드가 실제 데몬 소켓에 묻는 테스트 포함).


### 스킬 무결성

스킬(`SKILL.md` + 스크립트)도 플러그인과 같은 공급망 경로다(ClawHavoc, 2026). WS 어댑터가 에이전트별 인벤토리를 만들 때
기본 제공(`openclaw-bundled`)이 아닌 스킬 폴더를 해시하고(`integrity.dir_digest`), 정책의 스킬 매니페스트(`sga-server manifest skill`)와 비교한다.

| 결과 (`skills[].integrity`) | 뜻 | 효과 |
|---|---|---|
| `verified` | 보안팀이 승인한 해시와 같음 | `openclaw_skills` 신뢰 집합 → `openclaw-skill-unapproved`에서 빠짐 |
| `unknown` | 아무도 승인하지 않음 | 출처가 managed·workspace면 `openclaw-skill-unapproved` |
| `mismatch` | 승인된 스킬의 파일이 바뀜 | `openclaw-skill-tampered`(critical) → `openclaw config set skills.entries.<key>.enabled false`로 격리 |
| 없음 | 기본 제공 스킬(본체 무결성이 맡음), 또는 게이트웨이가 다른 호스트라 파일을 못 읽음 | 이름 기준 허용만 |

실환경(2026-11-12, 팀 게이트웨이): `research`의 작업 공간 스킬 `deploy-notes`가 `unknown` → 내용 검토 후 `--current`로 승인 → `verified`, 미허가 finding 사라짐
→ `SKILL.md`에 한 줄 추가 → `mismatch`, `openclaw-skill-tampered` + 자동 비활성화(`enforced: true, skills disabled: deploy-notes`) → 되돌려 다시 켬.

## 어댑터 계약

[adapters/base.py](../src/sg_advance/sensor/adapters/base.py)

```python
class Adapter(Protocol):
    name: str
    async def run(self, ctx: AdapterContext) -> None: ...   # 취소될 때까지

result = ctx.evaluate(event)          # 장비 ID 채우기 + 로컬 룰 → 판정 (아직 대기열에 안 넣음)
enforcement = ...                     # 어댑터가 판정에 따라 집행 (가능하면)
ctx.record(result, enforcement)       # 마스킹된 이벤트와 finding을 집행 결과와 함께 대기열로
```

판정과 기록을 나눈 이유는, 집행이 비동기(OpenClaw의 `sessions.abort`)일 때 **실제로 무슨 일이 일어났는지**를 finding에 남기기 위해서다.
관측만 하는 어댑터(`ReplayAdapter`)는 `enforcement` 없이 기록한다. OpenClaw 플러그인(M5c), Claude Code hook(M6), MCP 프록시(M8)는 툴 실행 전에 집행한다.
