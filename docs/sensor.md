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
| 2 높음 | 에이전트가 **한 일**과 **할 수 있는 것** | `tool.call`, `net.egress`, `inventory.snapshot`, 세션 시작·종료 |
| 1 보통 | 에이전트가 **본 것** | `tool.result`, `prompt.user` |
| 0 낮음 | 맥락용 대화 | `message.assistant`, `llm.call` |

- **버릴 때**: 낮은 등급부터, 같은 등급에서는 오래된 것부터 버린다. finding은 버리지 않는다.
- **보낼 때**: 높은 등급부터 보낸다. 같은 등급에서는 이벤트를 finding보다 먼저 보낸다(콘솔이 증거를 바로 찾을 수 있게).
- **증거 승격**: 시퀀스 룰은 앞 단계 이벤트가 그 자체로는 평범하다(예: 문서를 읽은 `tool.result`).
  finding이 생기는 순간 그 앞 단계 이벤트들을 긴급으로 올려서, 대기열이 넘쳐도 증거가 사라지지 않게 한다.
- 등급표는 지금 코드에 있다. M9에서 중앙 정책으로 옮겨 그룹별로 바꿀 수 있게 할 수 있다.

## 어댑터 계약

[adapters/base.py](../src/agent_sentinel/sensor/adapters/base.py)

```python
class Adapter(Protocol):
    name: str
    def events(self) -> Iterator[AgentEvent]: ...
    def enforce(self, verdict: Verdict) -> None: ...
```

M4에는 JSONL 파일을 재생하는 `ReplayAdapter`만 있다. OpenClaw(M5)는 관측과 사후 abort를,
Claude Code hook(M6)과 MCP 프록시(M8)는 사전 차단을 `enforce`로 구현한다.
