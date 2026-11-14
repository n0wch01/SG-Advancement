# SG-Advance

**사내 코딩 에이전트의 위험한 행동을 실행 직전에 막고, 중앙에서 연결해 조사·대응하는 관제 플랫폼**

회사가 쓰는 AI 에이전트(Claude Code, OpenClaw, 사내 MCP 서버에 붙는 에이전트)와 직원이 몰래 설치한 에이전트(섀도 AI)를 한 정책으로 다룬다.

- **막는 곳은 엔드포인트다.** 툴 호출 하나하나를 실행 전에 같은 서명된 룰로 판정한다. 대상은 셸 명령, 파일, 웹 요청, MCP 호출이다.
- **보는 곳은 중앙이다.** 행동을 사람·대화·위임 사슬로 묶어 사고를 조사하고, 이후 실행을 원격으로 막는다.
- **중심 위협은 두 가지다.** 직원의 실수와, 외부 콘텐츠로 들어오는 프롬프트 인젝션이다.

허가된 툴도 영원히 믿지 않는다. 호출마다, 그리고 그 뒤에 에이전트가 하는 일까지 계속 확인한다. 금융보안원 AI 에이전트 평가기준이 말하는 **실행 계층**(실행 권한·격리, 도구 실행·승인, 작업 범위·결과 확인, 자율 실행 중단)이 중심이다.

> 팀 프로젝트 [ajou-samsung-giants](https://github.com/n0wch01/ajou-samsung-giants)(OpenClaw 하나를 대상으로 한 보안 가시화 MVP)에서 출발해, 다중 에이전트·중앙 관제 구조로 혼자 다시 설계했다. 바뀐 점은 [docs/from-sg.md](docs/from-sg.md)에 있다.

## 구조

```
                         ┌──────────── 관제 서버 (control plane) ────────────┐
                         │ 장비 등록·폐기 · 서명된 정책(공통 + 팀) · Finding 수집  │
                         │ 상관 분석(캠페인, 사람 위험도) · 원격 대응 · 감사 체인    │
                         │ SGA-Dashboard (읽기 전용 콘솔)                       │
                         └──────▲───────────────────────────────┬──────────┘
                     이벤트·Finding │                      정책·차단 목록 │
 ┌──────────────────────────────┴───────────────────────────────▼──────────┐
 │ 엔드포인트 센서 (sga-sensor): 서명된 정책 캐시 + 로컬 판정 엔진 + 전송 대기열     │
 │                                                                          │
 │  Claude Code ── PreToolUse/PostToolUse hook ──┐                          │
 │  OpenClaw ───── 게이트웨이 플러그인(TS) ────────┼─▶ 같은 룰로 실행 전 판정     │
 │  모든 MCP 클라이언트 ── MCP 게이트웨이 ──────────┘   (차단 · 사용자 승인 ·      │
 │  팀 게이트웨이의 에이전트 망 ── egress 프록시(허용 도메인)    보안팀 보류 · 결과 가림)│
 │  섀도 AI 스캔: Claude Code·Cursor·Codex·Gemini·OpenClaw 설치와 MCP 설정       │
 └──────────────────────────────────────────────────────────────────────────┘
```

- 모든 어댑터는 공통 이벤트 하나(`AgentEvent` v1)로만 말한다. 룰은 에이전트별 원시 형식을 모른다.
- 비밀값은 엔드포인트를 떠나기 전에 가린다. 보호 데이터는 솔트 해시로만 다룬다.
- 집행 지점은 상태를 라벨(`labels.sga_*`)로만 붙이고, 판단은 서명된 룰이 한다.

설계 상세는 [docs/architecture.md](docs/architecture.md), KISA 「에이전틱 AI 제로트러스트 안내서」의 PDP·PEP 구조와의 대응은 [docs/zero-trust.md](docs/zero-trust.md)에 있다.

## 원칙

| 원칙 | 무엇 | 문서 |
|---|---|---|
| Fail closed | 데몬 꺼짐, 정책 만료, 판정 실패, 출처 기록 손상 13가지 경우가 모두 막히거나 보류된다. 사용자 승인만으로 넘어가지 않는다 | [fail-closed.md](docs/fail-closed.md) |
| 승인 원칙 | 사용자가 먼저 승인하고(되돌릴 수 없는 3-1 포함, 전용 경고 문구), 공격 진행 신호와 외부 유출만 바로 차단하며, 보안팀은 사후 검토 큐로 확인한다 | [zero-trust.md](docs/zero-trust.md#승인-원칙-2026-11-14) |
| 결과를 나눠 기록 | 탐지, 승인 요청, 보류, 단건 차단, 세션 중단, 실제 적용 확인을 따로 남긴다. 차단은 실제 부작용이 없었을 때만 성공으로 센다 | [fail-closed.md](docs/fail-closed.md#2-결과-기록-모델-enforcement) |
| 승인과 요청 묶기 | 승인한 요청과 실행하는 요청이 같은지 다이제스트로 확인하고, 실행 직전에 차단 조건을 다시 본다 | [fail-closed.md](docs/fail-closed.md) |
| 등급은 방식만 정한다 | 가역성 등급은 승인 방식만 정한다. 신원·권한·작업 범위 확인을 대신하지 않는다 | [zero-trust.md](docs/zero-trust.md) |

## 다루는 시나리오

| 시나리오 | 무엇을 막나 | 문서 |
|---|---|---|
| 테스트 DB 보호 데이터 → 미승인 외부 전송 | 민감도와 목적지를 함께 판정한다(양은 안 봄). 조회와 전송은 보호 값의 솔트 해시로 잇는다. 에이전트가 붙인 "안전" 표시는 무시한다. 콘솔에서 출처 조회 → 전송 → 판정 → 실제 결과가 한 흐름으로 보인다 | [lineage.md](docs/lineage.md) |
| 외부 입력 뒤 파괴적 행동 | 툴 결과에 출처 라벨을 붙인다. 인젝션 뒤 행동은 차단하고, 외부 입력 뒤 행동은 사용자 승인으로 따로 기록한다 | [external-input.md](docs/external-input.md) |
| 임시 경로에 받은 파일 실행 | 내려받은 경로·출처를 기억했다가 실행할 때 사용자 승인을 받는다. `curl \| sh`도 같다 | [downloaded-exec.md](docs/downloaded-exec.md) |
| 부모보다 큰 권한의 하위 에이전트 | Claude Code 하위 에이전트 정의와 OpenClaw `sessions_spawn` 대상의 모드·샌드박스를 부모와 비교한다 | [delegation-permissions.md](docs/delegation-permissions.md) |
| 인젝션 결과를 모델에 넘기기 | 입력 PEP: 인젝션이 든 툴 결과는 모델에 넘기지 않는다(Claude Code, MCP 게이트웨이) | [zero-trust.md](docs/zero-trust.md) |
| MCP 공급망 | 등록된 서버만 쓴다. 툴 설명 변조를 숨긴다. 알려진 악성 패키지·도메인 목록을 둔다. 사내 서버 자격증명은 중앙 게이트웨이만 갖는다 | [sensor.md](docs/sensor.md#mcp-게이트웨이-m8), [rules/threat_intel.yaml](rules/threat_intel.yaml) |
| 섀도 AI | 설치 흔적, 관리 여부(hook·플러그인), 게이트웨이를 거치지 않는 MCP 서버를 찾는다 | [sensor.md](docs/sensor.md) |
| OpenClaw 팀 운영 | 사람 단위 기록(누가 시켰고 누가 승인했나)과 위임 사슬을 남긴다. 무결성(npm 서명 + Sigstore), egress 격리, 원격 차단을 한다 | [team-gateway.md](docs/team-gateway.md), [response.md](docs/response.md) |

실제 사건과 룰의 연결은 [docs/incidents.md](docs/incidents.md), 위협 모델은 [docs/threat-model.md](docs/threat-model.md)에 있다.

## 평가

같은 공격·우회 시도·정상 작업 묶음을 세 집행 지점의 **실제 판정 코드**에 넣었다(`scripts/evaluate.py`). MCP 게이트웨이는 서버가 요청을 받지 않았는지까지 확인한다.

| | Claude Code hook | OpenClaw 플러그인 | MCP 게이트웨이 |
|---|---|---|---|
| 공격 17종: 설계대로 처리 | 16/16 | 12/12 | 6/6 |
| 공격 + 우회 시도에서 멈춘 비율 | 74% | 67% | 100% |
| 정상 작업 오탐 | 0/40 | 0/38 | 0/2 |
| 판정 지연 중앙값 | 0.9 ms | 0.9 ms | 2.1 ms(서버 왕복 포함) |

- 공격 묶음은 룰을 만든 사람이 짰다. 그래서 "설계대로"는 탐지 성능이 아니라 **설계대로 구현됐다는 확인**이다.
- 그래서 우회 시도 7종을 함께 넣었다. 7종 모두 문서에 적은 한계대로 통과했다. 상세는 [docs/evaluation.md](docs/evaluation.md)에 있다.
- 운영 기록 3,489건을 지금 룰로 다시 돌려 오탐 2건을 찾아 고쳤다.

기준 문서 대응:

| 기준 | 결과 | 문서 |
|---|---|---|
| 금융보안원 AI 에이전트 평가기준(안) 17개 점검항목 | 충족 7 · 부분 9 · 범위 밖 1 | [docs/fsi-17.md](docs/fsi-17.md) |
| KISA 에이전틱 AI 제로트러스트 안내서 보안 기능 53개 | 향상 24 · 초기 23(향상 일부 15) · 기존 3 · 범위 밖 3 · 최적화 0, 시나리오 5개 대응 | [docs/kisa-53.md](docs/kisa-53.md) |

## 해 보기

인프라 없이:

```bash
uv sync
uv run python demo/demo_runner.py all            # 공격 시나리오를 단계별로 재생하며 판정을 보여 줌
uv run python scripts/evaluate.py --out /tmp/eval.md   # 세 집행 지점 비교 표
uv run sga-detect examples/events/*.jsonl        # 예시 이벤트에 걸리는 룰과 그 이유
```

전체 데모 환경(관제 서버, 팀 게이트웨이, 섀도 AI PC, 중앙 MCP 게이트웨이):

```bash
cd dashboard && npm ci && npm run build && cd ..
cp .env.example .env                             # 토큰 값을 채운다
docker compose --profile team --profile shadow --profile mcp --profile lan up -d --build
open http://localhost:8000/dashboard/            # SGA_DASHBOARD_TOKEN(읽기 전용)으로 로그인
```

발표용 순서는 [docs/demo.md](docs/demo.md)에 있다. 이 Mac의 Claude Code·OpenClaw에 센서를 붙이는 방법은 [docs/sensor.md](docs/sensor.md), 다른 PC 설치는 [docs/multi-host.md](docs/multi-host.md)에 있다.

## 개발

```bash
uv run pytest                                    # Python 시험(626개: 룰 케이스, demo/ 포함)
uvx ruff check .
uv run python scripts/export_schema.py           # src/sg_advance/schema/ 변경 후
cd dashboard && npm ci && npm test && npm run build
cd integrations/openclaw-plugin && npm test      # OpenClaw 플러그인
```

룰을 바꿀 때는 `tests/rule_cases/`에 케이스를 먼저 넣는다([docs/detection.md](docs/detection.md)).

## 저장소 구조

| 경로 | 내용 |
|---|---|
| `src/sg_advance/schema/` | 공통 이벤트 `AgentEvent` v1, `Finding` ([docs/schema.md](docs/schema.md)) |
| `src/sg_advance/detect/` | 로컬 판정 엔진, `sga-detect` |
| `src/sg_advance/sensor/` | 센서: 등록, 서명 정책 캐시, 데몬, Claude Code hook, MCP 게이트웨이, egress 프록시, 섀도 AI 스캔, 출처 추적 ([docs/sensor.md](docs/sensor.md)) |
| `src/sg_advance/server/` | 관제 서버(FastAPI + SQLAlchemy, Alembic) ([docs/control-plane.md](docs/control-plane.md)) |
| `integrations/openclaw-plugin/` | OpenClaw 게이트웨이 플러그인(TypeScript, 실행 전 판정) |
| `dashboard/` | SGA-Dashboard(React + Vite + TypeScript) ([docs/dashboard.md](docs/dashboard.md)) |
| `rules/` | 선언형 룰 77개(서명돼 배포) |
| `tests/rule_cases/` | 룰별 오탐·미탐 회귀 케이스 |
| `eval/`, `scripts/evaluate.py` | 평가 묶음과 실행기 |
| `compose.yaml`, `deploy/` | 데모 구성과 이미지 |
| `demo/` | 시나리오 재생(선택, `rm -rf demo/` 해도 core는 동작) |
| `docs/` | 설계·결정·한계 기록(한국어). 진행 상황은 [docs/roadmap.md](docs/roadmap.md) |

## 한계

숨기지 않고 각 문서에 적었다. 큰 것만 모으면 다음과 같다.

- **패턴 판정의 우회**: 값이나 문구를 바꾸면 놓친다. 예: base64로 바꾼 보호 데이터, 문구를 바꾼 인젝션, 스크립트 안의 삭제. 평가의 우회 시도 E01~E07이 그 예다.
- **제품 내부는 직접 다루지 않는다**: 에이전트의 장기 메모리, 대화창 인증, 에이전트 간 채널 암호화, 확인 창의 모양은 각 제품에 맡긴다.
- **Claude Code hook과 OpenClaw 플러그인은 판정을 에이전트에게 넘긴다**: 실제로 막혔는지는 "미확인"으로 기록한다. 길목에 있는 MCP 게이트웨이와 egress 프록시만 "확인됨"이다.
- **MCP 게이트웨이는 서로 다른 서버의 호출을 잇지 못한다**: 대화 식별자가 없기 때문이다.
- **샌드박스는 점검만 한다**: 강제하지 않는다. 피지컬 리소스, 모델 학습 데이터, 사람 단위 SSO는 범위 밖이다.
- **실제 Claude Code와 Windows 노트북 확인이 남아 있다**: hook은 실제 `sga-hook`과 데몬으로 확인했지만, 실제 Claude Code 안에서의 동작 확인은 노트북 실설치 때 한다.

## 주의

연구·포트폴리오용 데모다. 공격 시나리오용 목업(악성 플러그인, 악성 MCP 서버, 유출 수신 서버)은 격리된 Docker 네트워크와 가짜 주소(`*.internet-sim`)에서만 쓴다.
