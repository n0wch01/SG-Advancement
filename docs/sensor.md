# 센서 코어

직원 PC(엔드포인트)에 설치되는 부분이다([src/agent_sentinel/sensor/](../src/agent_sentinel/sensor/)).
UI 없이 CLI 하나(`sentinel-sensor`)로 동작하고, 서버용 패키지(FastAPI, SQLAlchemy)가 없어도 설치된다.
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
export SENTINEL_ENROLL_TOKEN=set_...          # 셸 기록과 프로세스 목록에 토큰이 남지 않게 환경 변수로
sentinel-sensor enroll --server http://127.0.0.1:8000 --device-id dev-bob
sentinel-sensor replay examples/events/claude_code.jsonl    # 이벤트 재생 → 판정 출력 → 전송
sentinel-sensor status                                       # 장비, 정책, 대기열 상태
sentinel-sensor sync                                         # 정책 갱신 + 대기열 전송
```

상태는 `~/.agent-sentinel/`(또는 `SENTINEL_HOME`, `--home`)에 저장된다.

| 파일 | 내용 | 권한 |
|---|---|---|
| `credentials.json` | 서버 주소, 장비 ID·토큰, 신뢰하는 정책 공개키 | 0600 |
| `policy.json` | 마지막으로 받은 서명된 정책 | 0600 |
| `spool.db` | 보내지 못한 이벤트·finding | 기본 |

## 정책 서명과 공개키

서버는 시작할 때 Ed25519 키를 만들거나 읽어서(`SENTINEL_SIGNING_KEY`) 정책 묶음에 서명한다.
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
| 400·403·413·422 (같은 내용으로는 절대 성공 못 함) | 배치를 반으로 나눠 가며 문제 항목만 찾아 `dead`로 격리한다. 나머지는 전송된다 |
| 오래 끊겨서 대기열이 가득 찼다 (기본 5만 건) | **낮은 등급의 오래된 이벤트부터** 버리고 finding은 지킨다. 등급별로 버린 개수가 `status`에 나온다 |

## 대기열 우선순위

[priority.py](../src/agent_sentinel/sensor/priority.py). 오래 끊겨 있을 때 무엇을 남기고 무엇을 먼저 보낼지 정한다.

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

## 로컬 데몬 (`sentinel-sensor run`)

[daemon.py](../src/agent_sentinel/sensor/daemon.py). 엔드포인트마다 하나 떠 있는 프로세스다.
룰 엔진을 데몬이 들고 있어서, 시퀀스·빈도 룰이 이 PC의 모든 어댑터에서 오는 이벤트를 함께 본다.

```bash
export OPENCLAW_GATEWAY_TOKEN=...                       # 게이트웨이 토큰은 환경 변수로만 받는다
sentinel-sensor run --openclaw                          # 기본 ws://127.0.0.1:18789
sentinel-sensor run --openclaw --observe-only           # 탐지·보고만, 실행 중단은 하지 않음
sentinel-sensor run --openclaw --gate-exec              # 셸 명령 승인 요청에 답한다 (위험하면 실행 전 거절)
sentinel-sensor run --openclaw --capture frames.jsonl   # 게이트웨이 원본 프레임을 마스킹해서 기록 (디버깅)
sentinel-sensor run --replay examples/events/*.jsonl    # 데모용: 파일을 재생
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

[adapters/openclaw.py](../src/agent_sentinel/sensor/adapters/openclaw.py). 설치: `agent-sentinel[openclaw]`(websockets).
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

센서는 **자기 장치 신원**(Ed25519 키, `SENTINEL_HOME/openclaw-device.json`, 0600)을 처음 실행할 때 만들고, 다른 외부 클라이언트처럼 페어링한다.
OpenClaw CLI의 키를 빌려 쓰지 않는다. 그래서 센서는 필요한 권한만 갖고, `openclaw devices list`에 따로 보이며, 따로 폐기할 수 있다.

```bash
openclaw configure --section gateway          # 1. 게이트웨이 공용 토큰 설정 (기본값은 실행마다 바뀌는 임시 토큰이라 외부 클라이언트가 못 붙음)
export OPENCLAW_GATEWAY_TOKEN=...             # 2. 처음 한 번, 공용 토큰으로 접속
sentinel-sensor run --openclaw                #    → "pairing required — openclaw devices approve <requestId>" 로그
openclaw devices approve <requestId>          # 3. 게이트웨이 호스트에서 승인 → 센서가 deviceToken을 받아 저장
sentinel-sensor run --openclaw                # 4. 이후에는 공용 토큰 없이 deviceToken으로 접속
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
| 셸 실행 전 거절 | ⏳ CLI(`openclaw agent`)에서 시킨 실행은 대화형 승인을 요청할 수 없어 OpenClaw가 명령 자체를 막았다. Control UI나 채팅 채널에서 확인해야 한다 |

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

## 어댑터 계약

[adapters/base.py](../src/agent_sentinel/sensor/adapters/base.py)

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
