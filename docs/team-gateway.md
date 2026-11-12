# 팀 게이트웨이 (M5b)

회사가 운영하는 **공용 OpenClaw 게이트웨이**에 여러 직원이 접속하는 환경을 Docker Compose로 재현한다.
SG-Advance가 이 환경에서 하는 일은 네 가지다.

- 직원별 **사용자 구분**: 툴 호출, 결과, 프롬프트를 그 일을 시킨 사람의 이름으로 기록한다.
- **승인자 기록**: 누가 승인 버튼을 눌렀는지, 누가 실행을 중단했는지, 누가 대화를 보관·삭제했는지 남긴다.
- **위임 사슬**: 하위 에이전트가 한 일을 위임한 사람에게 연결하고, 부모·뿌리 세션과 깊이를 남긴다.
- **에이전트별 인벤토리**: 에이전트마다 모델, 런타임, 기본 권한 모드, 툴, 스킬을 기록하고 미허가 스킬과 넓은 권한을 알린다.
- **최소 권한**: 직원은 서로의 대화를 볼 수 없다. 보안팀만 전체를 본다.
- **데이터 최소화**: 대화 원문은 룰에 걸린 것만 관제 서버로 보낸다.

## 구성

```
브라우저 (직원별 포트 18801~18804)
   │
   ▼
team-proxy (nginx, 172.28.0.10)          신원 프록시. 포트별로 x-forwarded-user를 찍는다
   │  HTTP (화면 파일)          │  WebSocket (대화·승인·중단)
   │                            ▼
   │                   team-audit (172.28.0.11)     SG-Advance 감사 프록시: 제어 메시지만 읽고 그대로 중계
   ▼                            │
team-gateway (172.28.0.20) ◀────┘                   OpenClaw 공식 이미지 + SG-Advance 센서·플러그인
   │  (같은 컨테이너)
   ├─ sg-advance 플러그인: 모든 툴을 실행 전에 판정 (M5c)
   └─ sga-sensor: WS 관측, 사용자 구분, 판정 데몬
        │
        ▼
control-plane (corp-net)                            이벤트·finding 저장, 서명된 정책 배포
```

- **신원 프록시**는 Cloudflare Access나 SSO 프록시 역할을 대신한다. 데모에서는 포트마다 사람을 고정했다
  (18801 alice, 18802 bob, 18803 carol, 18804 secops). 브라우저가 클라이언트에서 보낸 신원 헤더는 덮어쓴다.
- 게이트웨이는 `trusted-proxy` 인증을 쓴다. `gateway.trustedProxies`에 신원 프록시와 감사 프록시만 등록한다.
  같은 호스트의 서비스(센서)는 게이트웨이 비밀번호로 접속한다.
- 게이트웨이는 호스트 포트를 열지 않는다. 직원은 반드시 프록시를 거쳐 들어온다.

## 실행

```bash
# .env (git 제외, 0600)에 필요한 값
#   OPENCLAW_TEAM_PASSWORD   게이트웨이 비밀번호 (같은 호스트 서비스용)
#   SGA_TEAM_ENROLL_TOKEN    게이트웨이 센서 등록 토큰
#   SGA_AUDIT_ENROLL_TOKEN   감사 프록시 등록 토큰
docker compose --profile team up -d --build

# 모델 로그인: 실행 중인 trusted-proxy 게이트웨이에서는 안 되므로 게이트웨이를 멈추고 한 번 실행한다
docker compose --profile team stop team-gateway
docker compose --profile team run --rm -it --no-deps --entrypoint node team-gateway \
  /app/openclaw.mjs models auth login --provider openai --device-code --set-default
docker compose --profile team up -d
```

- 등록 토큰은 1회용이다. 관리자 API(`POST /v1/admin/enrollment-tokens`)로 발급해 `.env`에 넣는다.
- 회사 기준 설정은 [team-config.json5](../deploy/team-gateway/team-config.json5)이고, **시작할 때마다 다시 적용**한다.
  화면에서 바꾼 값 중 이 파일에 있는 키는 재시작하면 되돌아간다. 파일에 없는 설정은 건드리지 않는다.
- 접속 주소는 반드시 `http://localhost:1880x`다. `127.0.0.1`은 브라우저가 다른 출처로 보기 때문에 허용된 출처(`controlUi.allowedOrigins`)에 걸린다.

### 역할 배정

| 역할 | 다른 사람 대화 | 권한 | 대상 |
|---|---|---|---|
| `member` (기본) | 안 보임 (`none`) | 읽기, 쓰기, 자기 승인, 질문 | 일반 직원 |
| `security` | 보기 (`view`) | 위 권한 + `operator.admin` (모든 승인 창, 남의 실행 중단, 바로 삭제) | 보안팀 |

OpenClaw는 이메일로 역할을 미리 정하는 설정이 없고(GitHub 로그인 기준만 있음), 프로필은 첫 로그인 때 생긴다.
그래서 첫 로그인 후 아래처럼 배정한다.

```bash
docker compose exec team-gateway /opt/sga/venv/bin/python /opt/sga/set-role.py secops@corp.test security
docker compose exec team-gateway /opt/sga/venv/bin/python /opt/sga/set-role.py bob@corp.test default   # 배정 해제
```

`identityScopes`로 관리자 권한을 줘도 **역할의 권한 상한이 먼저 적용된다**. 처음에는 secops가 `member` 상한에 걸려 관리자 권한이 잘려 나갔고,
그래서 남의 대화도 승인 창도 보이지 않았다(2026-11-12 실환경).

## 사용자 구분

플러그인이 받는 툴 맥락(`requester`)에는 채널과 발신자 id만 있고 **게이트웨이 프로필이 없다**. 그래서 센서가 WebSocket 쪽에서 사람을 알아내
같은 프로세스 안의 플러그인 판정에도 붙인다([openclaw_people.py](../src/sg_advance/sensor/adapters/openclaw_people.py)).

| 출처 | 알 수 있는 것 |
|---|---|
| `users.list` (읽기 권한으로 충분) | 프로필 id → 이메일, 표시 이름, 역할 |
| `presence` 이벤트 | 방금 로그인한 사람의 프로필 id → 이메일 |
| 사용자 `session.message`의 `__openclaw` | `senderIdentity`(프로필 id), `idempotencyKey: "<runId>:user"` → **그 run을 시킨 사람** |
| 세션 정보(`sessions.list`, `sessions.changed`) | `owner.actor` → 대화 주인 |

- 판단 순서는 **run을 보낸 사람 → 위임 사슬 → 대화 주인 → 센서 기본 사용자(`--user`)**다. 개인 게이트웨이에서는 결과가 예전과 같다.
- `principal.user_id`는 이메일이고, 이메일을 모르면 `openclaw-profile:<id>`로 남긴다. 역할은 `principal.groups`(`openclaw-role:member`)에 들어간다.
- 라벨 `openclaw.attribution`(`sender` / `session_owner`)으로 근거를 남긴다. 남의 공유 대화에 쓴 경우에는 `openclaw.session_owner`도 함께 남긴다.
- **사람이 시키지 않은 실행**(하트비트, 크론, 재시작 복구)은 대화 주인으로 기록하고 `session_owner` 라벨로 구분한다(결정 A).
  플러그인 맥락에는 실행 이유(`trigger`)가 없어서, 센서가 사람 메시지를 놓친 경우와는 구분하지 못한다.
- 사람 목록은 `~/.sg-advance/openclaw-people.json`(0600)에 저장한다. 재시작 직후 WS가 다시 붙기 전(실측 약 2초)에도 플러그인 판정에 사람이 붙는다.

실환경(2026-11-12): alice와 bob이 각자 새 대화에서 셸 명령을 시켰고, 툴 호출·결과·프롬프트가 각각 `alice@corp.test`, `bob@corp.test`로 기록됐다.

## 위임 사슬 (하위 에이전트)

에이전트는 `sessions_spawn` 툴로 하위 에이전트를 만든다. 자식 세션은 **사람이 아니라 에이전트 소유**다
(`createdActor {type: agent}`, `createdVia: "spawn"`, `spawnedBy`·`parentSessionKey`, `spawnDepth`). 그래서 소유자만 보면
자식이 한 일이 아무에게도 연결되지 않는다(처음 실환경에서는 `team-gateway`로 기록됐다).

- 부모 run 안의 `sessions_spawn` 결과(`childSessionKey`)로 **자식 세션 → 위임한 run**을 기억한다. 자식의 툴 호출은 그 run을 보낸 사람이다.
  결과를 놓쳤으면 부모 세션의 기록을 따라 올라간다(손자 세션도 맨 위 사람까지). 근거 라벨은 `openclaw.attribution: delegation`이다.
- 모든 이벤트의 `agent`에 `parent_session_id`, `root_session_id`, `spawn_depth`를 붙이고, 자식 세션 시작은 `session.start reason: spawned`로 남긴다.
- 사람이 연 새 대화에도 `parentSessionKey`(에이전트의 기본 대화)가 붙지만 `createdVia: operator`라서 위임으로 보지 않는다.
- 위임 관계는 사람 목록 파일에 함께 저장해 센서가 재시작해도 이어진다. 순환이 생겨도 멈추지 않는다(최대 16단계).

실환경(2026-11-12): secops가 하위 에이전트에게 `pwd`를 맡겼다. 자식 세션의 `exec` 두 건(Code Mode 바깥과 안쪽)이 `secops@corp.test`,
`delegation`, `spawn_depth: 1`로 기록됐다.

### 위임을 통한 인젝션 전파 (T18)

하위 에이전트는 세션이 따로라서, 세션 단위 S2 시퀀스("인젝션을 읽은 뒤 같은 세션에서 민감 행동")로는 전파가 보이지 않는다.

| 룰 | 언제 | 응답 |
|---|---|---|
| `cross-agent-injection-propagation` (critical) | 같은 위임 트리 안에서 한 세션이 인젝션 의심 텍스트를 읽고, **다른 세션**이 10분 안에 민감 파일 접근이나 외부 전송을 시도 | block |
| `injection-relayed-to-agent` (high) | `sessions_spawn`의 작업 지시나 `sessions_send` 메시지에 인젝션 문구가 실림 (넘기는 순간, 실행 전) | 사람 승인 |

예시: [openclaw_team.jsonl](../examples/events/openclaw_team.jsonl)에서는 하위 에이전트가 오염된 위키 페이지를 읽고, 위임한 총괄 에이전트가 `.env`를 보낸다.

```bash
uv run sga-detect examples/events/openclaw_team.jsonl
# … cross-agent-injection-propagation (block)
#   injected-content(tool.result …) @agent:main:subagent:… → sensitive-action(tool.call … curl …) @agent:main:dashboard:…
```

한계(FN): 패턴 기반이라 바꿔 쓴 인젝션은 놓친다. 센서가 모르는 위임(게이트웨이 밖, 센서가 꺼져 있던 동안의 오래된 트리)은 묶이지 않는다.
오탐 후보: 인젝션 샘플 분석을 일부러 맡기는 보안 업무(전달 룰), 같은 트리에서 사람이 시킨 정상 전송이 10분 안에 이어지는 경우.

### 직원은 하위 에이전트를 쓸 수 없다 (OpenClaw 2026.11.3)

자식 세션이 에이전트 소유라서, 관리자가 아닌 직원에게는 자기가 만든 자식도 **남의 대화**가 되고 공개 범위가 그대로 적용된다.

| 직원 역할의 `sessions.others` | 결과 (실험, 2026-11-12) |
|---|---|
| `none` (운영 설정) | 실패: `Session "agent:main:subagent:…" was not found` (alice) |
| `view` (bob에게만 임시 역할로 시험 후 되돌림) | 실패: `session is shared for this connection` |
| `write` 또는 `operator.admin` | 성공 (secops) |

위임한 세션(`controlOwnerSessionKey`)을 근거로 접근을 허용하지 않는 것은 OpenClaw 쪽 빈틈으로 보인다.
직원에게 모든 대화의 쓰기 권한을 줄 수는 없으므로 **결정(2026-11-12): `none`을 유지하고 직원은 위임을 쓰지 않는다.**
위임 기능과 에이전트 간 인젝션 전파(T18) 데모는 보안팀 계정으로 한다.

운영 지침: 하위 에이전트가 꼭 필요한 팀은 **게이트웨이를 따로 둔다.** OpenClaw는 게이트웨이 하나를 신뢰 경계 하나로 보므로,
팀원끼리 대화를 공유해도 되는 팀만 별도 게이트웨이에서 `write`를 쓴다. 데모 환경에는 만들지 않았다.

## 에이전트별 인벤토리

게이트웨이 하나에 에이전트가 여럿일 수 있다(에이전트마다 작업 공간, 모델, 스킬이 다르다). 센서는 `agents.list`를 읽고
에이전트마다 `tools.catalog {agentId}`와 `skills.status {agentId}`를 물어 `inventory.snapshot`을 따로 보낸다(세션 `inventory:<agentId>`).

| 필드 | 출처 |
|---|---|
| `agent_id`, `model`, `runtime`, `permission_mode` | `agents.list` (`model.primary`, `agentRuntime.id`, `defaultPermissionMode`) |
| `tools`, `plugins` | `tools.catalog` |
| `skills[]` (`name`, `source`, `ref`, `enabled`, `eligible`, `model_visible`, `description`) | `skills.status` |

| 룰 | 내용 | 응답 |
|---|---|---|
| `openclaw-skill-unapproved` (high) | `openclaw-bundled`(이미지 기본)과 `openclaw-extra`(설치된 플러그인의 스킬) 밖의 스킬: ClawHub 설치(`openclaw-managed`), 작업 공간(`openclaw-workspace`). 보안팀이 해시로 승인한 스킬은 제외 | 알림 |
| `openclaw-skill-tampered` (critical) | 승인된 스킬의 파일이 승인 당시와 다름 ([sensor.md](sensor.md#스킬-무결성)) | 격리 (스킬 비활성화) |
| `mcp-tool-description-poisoning` | 툴뿐 아니라 스킬 설명의 숨은 지시도 검사 | 격리 |
| `openclaw-agent-permission-full` (medium) | 에이전트 기본 권한 모드가 `full` (`read-only` < `guarded` < `workspace` < `full`). 결정 A(2026-11-12): 경보만, 실제로 낮출지는 추후 | 알림 |

데모 에이전트 추가(관리자 RPC `agents.create`, 실환경 2026-11-12):

```bash
# research 에이전트 (모델 gpt-6-luna, 작업 공간 ~/.openclaw/workspace-research)
#   agents.create {name: research, model: openai/gpt-6-luna}
# 미허가 스킬 시험용: 작업 공간 skills/<이름>/SKILL.md (아무 명령도 실행하지 않는 설명 파일)
```

실환경 결과: `main`과 `research` 각각 인벤토리가 나왔다(툴 76개, 스킬 51개·52개). `research`의 작업 공간 스킬 `deploy-notes`만
`openclaw-skill-unapproved`로 걸렸고, 두 에이전트 모두 `permission_mode: full`이라 `openclaw-agent-permission-full`이 났다.
에이전트와 스킬은 게이트웨이 볼륨(`team-openclaw`)에 남으므로, 볼륨을 새로 만들면 다시 추가해야 한다.

## egress: 에이전트 망의 유일한 출구 (M5d)

게이트웨이는 **인터넷 경로가 없는 내부망**(`team-net`, `internal: true`)에만 붙어 있다. 밖으로 나가는 길은 SG-Advance egress 프록시
(`team-egress`, 172.28.0.12:3128) 하나뿐이고, 게이트웨이에는 `HTTP(S)_PROXY`와 `NODE_USE_ENV_PROXY=1`, OpenClaw `tools.web.fetch.useTrustedEnvProxy`를 설정했다.
환경 변수를 무시하는 프로그램은 프록시를 우회하는 게 아니라 **아예 나가지 못한다**.

```
team-gateway ──(team-net, 내부망)──▶ team-egress ──(corp-net)──▶ 인터넷
      │  직접 연결: 경로 없음                │ 연결마다 net.egress 이벤트, egress-unapproved-host로 판정
```

- 프록시는 `CONNECT host:port`(TLS)와 평문 HTTP 요청을 받는다. 목적지(호스트, 포트, 메서드, 평문이면 URL)만 기록하고 **TLS 안은 읽지 않는다.**
- 판정은 서명된 정책의 `egress-unapproved-host`(허용 도메인 목록)다. `SGA_EGRESS_MODE=monitor`는 기록·경보만, `enforce`는 403으로 거절한다.
- 사람 단위 귀속은 없다. 네트워크 계층에서는 어느 직원의 실행이 보낸 요청인지 알 수 없어서 `egress:<게이트웨이 IP>`로 남는다.
- 관제 서버(`control-plane`)는 내부망에도 붙어 있어 센서들이 프록시 없이 보고한다(`NO_PROXY`).

실측과 결정(2026-11-12):

| 목적지 | 무엇 | 결정 |
|---|---|---|
| `chatgpt.com` | 모델 호출 (구독 로그인 방식이라 `api.openai.com`이 아님) | 허용 목록에 추가 |
| `www.gravatar.com` | 사용자 아바타 | **차단**: 직원 이메일 해시가 외부 서비스로 나감 (아바타는 기본 이미지) |
| 그 밖 (`example.com` 등) | | 차단 |

감시 모드에서는 대화 한 번만 관찰하고 차단 모드로 바꿨다. 쓰이지 않은 기능(이미지 생성, 웹 검색 등)이 새 도메인을 쓰면 막히므로,
막힌 목적지는 `egress-unapproved-host` finding을 보고 룰 허용 목록에 사례부터 추가한다.

확인: 게이트웨이에서 직접 `curl https://example.com` → 경로 없음. 프록시 경유 → 차단 모드에서 `example.com`, `www.gravatar.com` 403(`egress BLOCK`), `chatgpt.com` 200.
주의: 관제 서버와 프록시가 동시에 재시작되면 프록시가 **이전 정책 캐시**로 시작하고, 다음 동기화(최대 60초)까지 이전 허용 목록을 쓴다.

## 감사 프록시: 누가 승인하고, 중단하고, 지웠나

OpenClaw는 승인한 사람을 기록하지 않는다. 내부 DB(`operator_approvals.resolver_id`)와 승인 이벤트(`resolvedBy`) 모두 앱 이름인
`openclaw-control-ui`만 남기고, 플러그인에는 결정값만 전달한다. OpenClaw 소스를 고치면 자체 포크를 계속 맞춰야 하고,
SG-Advance의 코어 무결성 검증(T22)에도 변조로 걸린다.

대신 **신원 프록시 바로 뒤에 감사 프록시**를 둔다([openclaw_audit_proxy.py](../src/sg_advance/sensor/adapters/openclaw_audit_proxy.py)).
이 프록시는 연결마다 그 사람이 누구인지 알고 있다.

| 직원 화면이 보낸 요청 | 기록 (`operator.action`) |
|---|---|
| `plugin.approval.resolve`, `exec.approval.resolve` | `approval.resolve`: 결정, 승인 id, **어떤 툴 호출인지**(내려온 승인 요청에서 알아낸 값) |
| `chat.abort`, `sessions.abort` | `run.abort`: 대상 세션, run |
| `sessions.patch` / `sessions.patchMany`의 `archived` | `session.archive` / `session.unarchive` (대상마다 한 건) |
| `sessions.delete` | `session.delete`: 보관된 것만 삭제했는지(`archived_only`), 대화 기록까지 지웠는지 |
| `sessions.patch` / `sessions.patchMany`의 권한 필드 (`permissionMode`, `sandboxMode`, `exec*`, `elevatedLevel`, `toolOverrides`) | `session.privilege`: `changes`에 `필드=값`. 권한을 넓히는 변경이 받아들여지면 `openclaw-session-privilege-raised`(high) |

실환경(2026-11-12): alice가 대화 권한을 `workspace`로 바꿨다가 기본값으로 되돌림 → `session.privilege` 두 건, 경보 없음.
secops가 `full`을 고름 → `openclaw-session-privilege-raised` (high, `secops@corp.test`).

- 이벤트의 `principal`은 **행동한 사람**이고, 게이트웨이의 응답(허용, 거부와 오류 코드)도 함께 남긴다. 접속 IP는 라벨 `openclaw.client_ip`에 남긴다.
- **대화 메시지는 읽지 않는다.** 위 메서드 이름이 들어 있지 않은 메시지는 해석하지 않고 그대로 넘긴다(테스트로 바이트 단위 동일 확인).
- 신원 프록시 IP에서 온 연결만 받고, 신원 헤더가 없으면 403으로 거부한다.
- 승인 감사 API(`GET /v1/admin/approvals`)는 같은 툴 호출의 `operator.action`을 찾아 `approver`에 실제 승인자를 넣고, 근거로 `approver_source: audit_proxy`를 붙인다.
- 감사 프록시가 멈추면 직원 화면의 WebSocket도 끊긴다. 기록 없이 계속 쓰게 두는 대신 **멈추는 쪽**을 택했다.

실환경(2026-11-12):

```
04:36:31  alice@corp.test  allow-once  exec  rules=destructive-sql  by=alice@corp.test   FLAG user-approved-high-risk
04:32:19  alice@corp.test  allow-once  exec  rules=destructive-sql  by=secops@corp.test  FLAG user-approved-high-risk
02:52:31  alice@corp.test  allow-once  exec  rules=destructive-sql  by=?                 (감사 프록시 도입 전)
```

보관·삭제도 같은 방식으로 확인했다. alice가 자기 대화를 보관한 뒤 삭제(`archived_only: true`)했고, secops가 bob의 대화를 바로 삭제(`archived_only: false`)했다.
alice가 보관하지 않은 대화를 바로 지우려 하자 화면이 요청을 아예 보내지 않았다. 화면을 거치지 않은 직접 요청이라면 거부된 시도로 기록된다.

## OpenClaw 다중 사용자 정책 (2026.11.3에서 확인)

| 동작 | 누가 할 수 있나 | 근거 |
|---|---|---|
| 승인 창 보기·응답 | 요청을 보낸 기기, `operator.admin` | `isApprovalRecordVisibleToClient`. 실환경: bob에게는 alice의 승인 창이 안 보였고 secops에게는 보였다 |
| 실행 중단 | 그 실행을 시작한 기기나 연결, `operator.admin` | `canRequesterAbortChatRun`. 새로고침해 연결이 바뀌면 본인도 `unauthorized`가 난다 |
| 대화 바로 삭제 | `operator.admin` | `resolveSessionsDeleteRequiredScope` |
| 보관된 대화 삭제 | `operator.write` (보관 → 삭제) | 같은 함수, `archivedOnly: true` |
| 남의 대화 보기 | 역할의 `sessions.others` (`none`/`suggest`/`view`/`write`) | 데모는 `member: none`, `security: view` |
| 하위 에이전트 만들기 | `operator.admin` 또는 `sessions.others: write` (자식이 에이전트 소유라서) | 위 실험 |
| 대화 실행 권한 `full` 고르기 | 관리자만 (직원 화면에서는 잠김). 단 **고르지 않으면 에이전트 기본값**을 따르고 기본값이 `full`이면 그대로 전체 액세스 | Control UI 실행 권한 메뉴, 2026-11-12 |

대화 삭제는 사고 조사에서 보면 증거 삭제다. 그래서 OpenClaw 기본값(직원은 보관을 거쳐야 함)을 그대로 두고 모든 시도를 기록한다.

## 데이터 최소화

- **대화 공개 범위** (결정, 2026-11-12): 직원 사이는 `none`이다. 업무 대화에도 개인정보와 고객 데이터가 섞이고,
  직원 대화 열람은 고지와 목적 제한이 필요한 영역이라 최소 권한으로 둔다. 함께 써야 하는 대화만 따로 공유한다.
- **원문 전송** (결정, 2026-11-12): `prompt.user`와 `message.assistant`는 **룰에 걸렸을 때만** 원문을 보낸다.
  나머지는 `text: ""`, `withheld: true`, `text_chars`(글자 수)만 보내고, 원본 프레임(`raw`)도 뺀다. 탐지는 센서가 원문으로 이미 끝냈고,
  관제 서버는 룰을 다시 돌리지 않으므로 탐지는 줄지 않는다. `--keep-chat-text`로 끌 수 있다.
  - 한계(FN 쪽): 시퀀스 룰에서 앞 단계 프롬프트가 그 자체로는 안 걸렸다면, 나중에 finding이 나도 그 프롬프트의 원문은 없다.
  - 툴 결과(`tool.result.output_preview`)는 인젝션 탐지의 핵심 증거라 이번 결정 범위에서 뺐다.
- 감사 프록시는 제어 메시지만 읽는다. 누가 어떤 대화를 열었는지 같은 열람 기록은 남기지 않는다.

## 알려진 한계와 후속

- **컨테이너 안 무결성**: 공식 이미지는 소스 빌드(`/app`)라 npm 배포본 해시와 비교할 수 없다. 게이트웨이 센서는 `--no-openclaw-integrity`로 돈다.
  이미지 다이제스트와 서명·출처 확인으로 대신하는 것이 후속 과제다.
- **대화 단위 권한 변경**: 감사 프록시가 `sessions.patch`의 권한 필드를 기록한다(위 표). 감사 프록시를 거치지 않는 변경
  (게이트웨이 내부, 같은 호스트의 CLI)은 보이지 않는다.
- **샌드박스**: 데모 팀 게이트웨이는 샌드박스를 설정하지 않아 OpenClaw 기본값 `off`로 돈다(`openclaw-sandbox-off` 경보). 컨테이너 자체가
  1차 격리지만, 회사 기준으로는 `agents.defaults.sandbox.mode: all`이 맞다. 실제로 켤지는 추후 결정(샌드박스 백엔드가 Docker라 컨테이너 안에서 추가 설정 필요).
- **Control UI 기본 대화**: 기본 대화 `agent:main:main`은 처음 만든 사람의 것이다. `none`에서는 다른 직원 화면에 "Session not found"가 반복된다.
  기능에는 영향이 없고, 직원은 새 대화에서 작업한다.
