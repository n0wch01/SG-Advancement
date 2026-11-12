# Control Plane API

중앙 서버([src/sg_advance/server/](../src/sg_advance/server/))가 하는 일은 세 가지다.
장비를 등록하고, 센서가 보낸 이벤트와 finding을 저장하고, 정책을 내려준다.
API 문서 전체는 서버를 띄운 뒤 `http://127.0.0.1:8000/docs`(Swagger)에서 볼 수 있다.

## 실행

```bash
uv run sga-server                      # 로컬. 관리자 토큰을 안 주면 실행할 때마다 새로 만들어 출력한다
SGA_ADMIN_TOKEN=... uv run sga-server

cp .env.example .env                        # Docker. .env에 SGA_ADMIN_TOKEN을 적는다
docker compose up -d --build
```

| 환경 변수 | 기본값 | 설명 |
|---|---|---|
| `SGA_ADMIN_TOKEN` | (없음) | 관리자 API 토큰. M7에서 콘솔 로그인으로 바뀐다 |
| `SGA_DB_URL` | `sqlite:///data/sga.db` | SQLAlchemy URL. Postgres로 갈 때 이 값만 바꾼다 |
| `SGA_RULES_DIR` | `rules` | 정책 v0으로 내려줄 룰 디렉터리 |
| `SGA_SIGNING_KEY` | `data/policy_signing_key.pem` | 정책 서명용 Ed25519 개인키. 없으면 처음 시작할 때 만든다 (0600) |
| `SGA_MAX_BATCH` | `500` | 한 번에 받는 이벤트/finding 최대 개수 |
| `SGA_PORT` | `8000` | compose에서 호스트에 여는 포트 (8000이 이미 쓰이고 있을 때) |
| `SGA_RELEASE_COOLDOWN_DAYS` | `3` | 서명·출처가 검증된 릴리스를 자동 신뢰하기까지의 대기 기간 |
| `SGA_AUTO_VERIFY` | `1` | 센서가 보고한 버전을 서버가 npm에서 받아 자동 검증 (`0`이면 관리자 명령만) |
| `SGA_NPM_REGISTRY` | `https://registry.npmjs.org` | 패키지 메타데이터·서명·출처를 받을 레지스트리 |

## 인증

토큰은 세 종류이고, 모두 `Authorization: Bearer <token>` 헤더로 보낸다.

| 토큰 | 접두어 | 누가 쓰나 | 수명 |
|---|---|---|---|
| 관리자 토큰 | (자유) | 보안팀, 나중에 콘솔 | 서버 설정값 |
| 등록 토큰 | `set_` | 센서를 설치하는 사람 | 기본 1회용, 24시간 |
| 장비 토큰 | `sdt_` | 등록을 마친 센서 | 폐기 전까지 (폐기는 M12) |

- 서버에는 등록 토큰과 장비 토큰의 **sha256 해시만** 저장한다. DB가 유출돼도 토큰을 쓸 수 없다.
  토큰이 256비트 난수라서 bcrypt처럼 느린 해시는 필요 없다.
- 센서는 **자기 장비에 대해서만** 보고할 수 있다. 배치 안의 `endpoint.device_id`가 하나라도
  인증된 장비와 다르면 배치 전체를 403으로 거부한다. 등록된 장비 하나가 다른 직원 PC를 사칭해
  가짜 이벤트를 넣는 것을 막는다.
- 등록 토큰이 없거나, 다 썼거나, 만료됐으면 모두 같은 401 메시지를 준다. 어떤 토큰이 유효한지 추측할 단서를 주지 않기 위해서다.

## 흐름

```
관리자 ─ POST /v1/admin/enrollment-tokens ─▶ set_… (설치 담당자에게 전달)
센서   ─ POST /v1/enroll  (Bearer set_…)  ─▶ { device_id, device_token: sdt_…, policy_public_key }   ← 토큰은 한 번만 보여줌
센서   ─ GET  /v1/policy  (Bearer sdt_…, If-None-Match) ─▶ 200 bundle | 304
센서   ─ 로컬 탐지 → redact ─ POST /v1/events, /v1/findings ─▶ { accepted, duplicates }
관리자 ─ GET /v1/admin/devices | events | findings
```

| 메서드 | 경로 | 인증 | 설명 |
|---|---|---|---|
| GET | `/healthz` | 없음 | 상태, 현재 정책 버전, 서명 키 지문(`policy_key_id`) |
| POST | `/v1/enroll` | 등록 토큰 | 장비 등록. `device_id`를 생략하면 서버가 `dev-xxxxxxxx`로 만든다. 중복이면 409 |
| GET | `/v1/policy` | 장비 | 정책 묶음. `ETag`가 정책 버전이다 |
| POST | `/v1/events` | 장비 | `{"events": [AgentEvent, ...]}` |
| POST | `/v1/findings` | 장비 | `{"findings": [Finding, ...]}` |
| POST | `/v1/admin/enrollment-tokens` | 관리자 | `{label, max_uses=1, ttl_hours=24}` |
| GET | `/v1/admin/devices` | 관리자 | 장비 목록. `policy_current`는 이 장비가 최신 정책을 받아 갔는지 여부 |
| GET | `/v1/admin/events` | 관리자 | 필터: `device_id`, `user_id`, `session_id`, `kind`, `limit`, `offset`. 최신순 |
| GET | `/v1/admin/findings` | 관리자 | 필터: 위 항목들 + `rule_id`, `category`, `min_severity` |
| GET | `/v1/admin/policy` | 관리자 | 현재 정책 버전, 룰 개수, 서명 공개키(설치 시 고정용) |
| POST | `/v1/admin/policy/reload` | 관리자 | `rules/`를 다시 읽는다. 룰 파일이 깨져 있으면 422를 주고 기존 정책을 유지한다 |

## 정책 v0

[src/sg_advance/policy.py](../src/sg_advance/policy.py)의 `PolicyBundle`이다.

- `rules/*.yaml`의 룰 전체를 JSON으로 바꾸고, 그 정규화된 JSON의 sha256을 `version`으로 쓴다.
  룰 내용이 바뀔 때만 버전이 바뀐다. 파일 순서나 주석, 들여쓰기는 버전에 영향이 없다.
- 센서는 `If-None-Match: "<version>"`으로 물어보고, 바뀌지 않았으면 304를 받아 본문을 다시 받지 않는다.
- `PolicyBundle.to_ruleset()`은 해시를 다시 계산해 보고, 맞지 않으면 거부한다. 전송 중 깨진 정책으로 엔진을 만들지 않기 위해서다.
  해시만으로는 위조를 막지 못하므로, 서버가 `version`에 Ed25519로 서명하고(`key_id`, `signature`) 센서가 검증한다.
  자세한 내용은 [sensor.md](sensor.md#정책-서명과-공개키).
- 이 모듈은 서버 의존성이 없어서 센서(M4)가 그대로 가져다 쓴다.

## 저장

[src/sg_advance/server/db.py](../src/sg_advance/server/db.py), SQLAlchemy 2.0.

- 이벤트와 finding은 **원문 JSON 전체**(`doc`)와, 콘솔이 필터로 쓰는 몇 개 컬럼(시각, 장비, 사용자, 세션, 종류, 심각도)을 함께 저장한다.
  스키마에 필드가 추가돼도 테이블을 바꿀 필요가 없다.
- 시각은 항상 UTC로 저장하고, 시간대 정보가 붙은 값으로 돌려준다. SQLite는 시간대를 버리기 때문에 `UTCDateTime` 타입이 그 차이를 감춘다.
- SQLite는 WAL 모드로 연다. 읽기가 쓰기를 막지 않는다. 쓰기는 여전히 한 번에 하나라서, 병목이 생기면 Postgres로 옮긴다.
- 테이블은 서버가 시작할 때 만든다. 마이그레이션 도구(Alembic)는 M9에서 들인다.

## 수집 규칙

- **중복 제거는 `event_id`/`finding_id`로 한다.** 같은 배치를 다시 보내도 `duplicates`로 세고 무시한다.
  그래서 센서는 전송에 실패하면 같은 배치를 안심하고 다시 보낼 수 있다(M4의 재시도 큐).
  단, 센서가 **보내기 전에 ID를 정해 둬야** 한다. ID 없이 보내면 서버가 받을 때마다 새 ID를 만들기 때문에 중복을 알아볼 수 없다.
- **서버도 한 번 더 마스킹한다.** 센서가 이미 마스킹하지만, 마스킹은 여러 번 해도 결과가 같아서 비용이 거의 없다(심층 방어).
- `received_ts`는 서버가 기록한다. 센서 시계가 틀려도 언제 도착했는지는 남는다.

## 패키지 매니페스트 (M5d)

서버는 에이전트 패키지의 **정본 해시**(매니페스트)를 만들어 서명된 정책에 넣는다. 센서는 설치된 파일의 해시를 이것과 비교한다
([sensor.md](sensor.md) "설치된 코드 무결성").

검증 순서 (`server/supply.py`), 하나라도 실패하면 `rejected`:
1. **npm 레지스트리 서명**: npm이 `이름@버전:integrity`에 ECDSA P-256으로 서명한 값을 `/-/npm/v1/keys`의 공개키로 확인
2. **출처(SLSA, Sigstore)**: 인증서가 GitHub Actions에서 신뢰하는 저장소(`openclaw/openclaw`)로 발급됐는지, 투명성 로그, 대상 해시가 패키지와 같은지
3. **패키지 파일**: 내려받아 sha512가 `integrity`와 같은지

| 상태 | 뜻 | 정해지는 방법 |
|---|---|---|
| `cooling` | 검증됨, 출시 3일 미만 | 자동 (변조 검사는 이미 동작) |
| `trusted` | 검증됨, 출시 3일 경과 | 자동 (정책 요청 때 기간이 지났으면 다시 서명) |
| `approved` | 보안팀 승인 | `manifest approve` (긴급 패치처럼 기다릴 수 없을 때) |
| `revoked` | 보안팀 철회 | `manifest revoke` (악성으로 드러난 버전) |
| `rejected` | 검증 실패 | 자동 |

```bash
export SGA_ADMIN_TOKEN=...   # 출력하지 않는다
sga-server manifest list
sga-server manifest add openclaw@2026.11.3 [--approve] [--by 이름]   # 지금 검증
sga-server manifest approve|revoke openclaw@2026.11.3 --by 이름
sga-server manifest pin sg-advance --dir integrations/openclaw-plugin --version 0.1.0   # npm에 없는 사내 플러그인
```

- 센서가 처음 보는 버전을 보고하면 서버가 **백그라운드에서 자동 검증**한다(작업자 하나가 순서대로, 패키지 하나에 수십~수백 MB).
  신뢰하는 배포자가 없는 이름(`openclaw-tools` 같은 유사 이름 포함)은 내려받지 않는다.
- 서버는 npm 레지스트리와 Sigstore(신뢰 루트 갱신)에 나가는 연결이 필요하다.
- 출시 대기 기간을 두는 이유: 악성 npm 릴리스는 보통 며칠 안에 발견돼 내려간다. 배포자의 CI가 뚫려 서명까지 된 악성 버전이 나와도
  대기 기간 안에 철회(`revoke`)할 수 있다.

## 승인 감사 (C)

결정(2026-11-11): 위험한 행동은 사용자가 승인하고, 보안팀은 사후 감사하다가 이상하면 조치한다. 감사 화면(M7 콘솔)이 쓸 API를 먼저 둔다.

`GET /v1/admin/approvals?approved=true&user_id=&device_id=&decision=&since=` (최신순): 각 응답(`approval.resolved`)에

- `held_call`: 승인 창에 걸렸던 원래 호출(툴, 마스킹된 인자)
- `asked_by`: 승인을 요구한 finding (예: `destructive-sql`)
- `flagged`: 그 응답이 일으킨 감사 finding (`user-approved-high-risk`, `approval-fatigue`)
- `requester`, `judged_by`(데몬/캐시/기본값), `wait_ms`
- `approver`, `approver_source`: 실제로 승인한 사람. 팀 게이트웨이의 감사 프록시가 본 `operator.action`이 있으면 그 사람(`audit_proxy`),
  없으면 에이전트가 보고한 값(`agent`), 둘 다 없으면 비어 있다. 요청자(`user_id`)와 다를 수 있다(보안팀이 대신 승인)

를 묶어 보여 준다.

```bash
sga-server audit approvals              # 승인한 것만
sga-server audit approvals --all --user alice
sga-server audit --server http://127.0.0.1:$SGA_PORT approvals   # compose (--server는 approvals 앞에)
```
