# 제로트러스트 구조 (2026-11-13)

근거 문서:

- 과기정통부·KISA 「에이전틱 AI 제로트러스트 안내서」(2026-11). 이하 "안내서".
- 금융보안원 「금융분야 AI 에이전트 보안 평가기준」 보도자료(2026-10-07)의 17개 점검항목. 이하 "금융보안원 ①~⑰".

SG-Advance를 안내서의 PDP·PEP 구조에 맞춰 정리하고, 빈 곳을 메운 기록이다.
평가 대응표(17개 항목, 보안 기능 53개 성숙도 자가 진단, 시나리오 재현)는 평가 단계에서 따로 만든다.

## PDP와 PEP

PDP(정책 결정 지점)는 다음 두 가지다.

- 관제 서버의 서명된 정책(공통 기준선과 팀별 강화)
- 엔드포인트의 로컬 판정 엔진(같은 룰)

PEP(정책 시행 지점)는 판정을 집행만 한다. PEP는 상태를 라벨로 붙이고(`labels.sga_*`), 판단은 서명된 룰이 한다.

| 안내서 PEP | SG-Advance | 수준 |
|---|---|---|
| 내부 PEP (도구 호출 의도 검증) | Claude Code hook, OpenClaw 플러그인, MCP 게이트웨이 `tools/call` | 실행 전 차단·승인 |
| 외부경계 PEP | egress 프록시(허용 목록), MCP 게이트웨이(등록 서버만, 변조 툴 숨김) | 차단 |
| 입력 PEP | MCP 게이트웨이: 인젝션 high 이상 결과를 모델에 넘기지 않음. hook·플러그인은 탐지만 함 | 게이트웨이만 차단 |
| 위임 PEP | OpenClaw 위임 사슬 기록, 위임 전파 탐지(T18) | 기록·탐지 |
| 피지컬 PEP | — | 범위 밖 |

## 가역성·실시간성 등급 (안내서 표 2-5)

행동(`tool.call`)을 판정하는 룰에는 `grade:<등급>` 태그를 단다. 상태나 사람을 기준으로 판단하는 룰은 `action-independent`로 표시한다.

- 결정(2026-11-13): 응답은 사용자가 정한다. 등급과 응답이 어긋나면 시험이 알려 주고, 자동으로 바꾸지 않는다(`tests/test_rule_cases.py`).
- 2-1과 3-1 등급은 사람의 명시적 승인 이상이어야 한다.
- 3-1 등급을 사람이 승인하는 경우 사후 감사가 붙어야 한다. 그래서 severity는 high 이상이어야 하고, `user-approved-high-risk`가 감사한다.

| 등급 | 룰 |
|---|---|
| 0 (조회) | `sensitive-file-access` |
| 2-1 (에이전트 간 전달) | `cross-agent-injection-propagation`, `injection-relayed-to-agent` |
| 3-1 (영구 삭제·외부 유출) | `destructive-shell-command`, `destructive-sql`, `destructive-cloud-command`, `sensitive-file-exfil-command`, `secret-in-tool-arguments`, `injection-then-sensitive-action` |

2-2와 3-2 등급(실시간이라 사전 승인 정책 안에서 자동 실행)은 해당하는 행동이 없어 쓰지 않는다.

## 접근 결정 ([rules/zero_trust.yaml](../rules/zero_trust.yaml))

| 룰 | 근거 | 조건 | 응답 |
|---|---|---|---|
| `policy-stale-state-changing-tool` | 안내서 2장 4절 3): 캐시 정책 유효기간 | 관제 서버가 정책을 72시간(`SGA_POLICY_MAX_AGE_HOURS`) 확인해 주지 못함 + 읽기 전용이 아닌 툴 | 사람 확인 |
| `sensitive-resource-from-degraded-device` | P2-1·P2-2: 상태 미달 기기의 민감 데이터 접근 제한 | PC 상태 `degraded`(hook 없는 Claude Code, 통제 밖 에이전트) + 민감 리소스 | 차단 |
| `sensitive-resource-by-elevated-risk-user` | P1-4·C1-7: 위험도 지속 재평가 | 관제 서버가 고위험으로 내려보낸 사람 + 민감 리소스 | 보안팀 승인 |

- **민감 리소스**는 정책이 정한다. 지금은 MCP 서버 `crm`, `hr-db`, `payments`(예시)이고, 두 룰이 같은 목록을 쓴다.
- **PC 상태**는 센서 점검으로 정해진다. Claude Code hook 위치 점검과 설치 탐지 결과를 합친다.
  - 라벨: `sga_posture`(ok / degraded / unknown)와 `sga_posture_reasons`
  - 상태가 고쳐지면 다음 점검에서 자동으로 풀린다.
- **사람의 위험도**([server/risk.py](../src/sg_advance/server/risk.py)):
  - 최근 24시간 동안 critical 1건 이상, 또는 high 3건 이상이면 고위험이다.
  - **에이전트의 행동에서 나온 Finding만** 센다: 툴 호출·결과, 프롬프트, 응답, 승인.
  - 설치·설정·인벤토리·무결성처럼 PC 설정에서 나온 Finding은 세지 않는다. 그쪽은 PC 상태 룰이 처리한다.
  - 각 PC는 **그 PC를 쓴 사람의 위험도만** 받는다. 고위험자 명단 전체를 뿌리지 않는다.
- 위험도 반영 경로: 센서는 flush 주기마다 `GET /v1/risk`를 호출하고, 결과를 `elevated_risk_users` 집합에 넣는다. 관제 서버와 연결이 끊겨도 위험도를 낮추지 않는다.
- 알려진 공백:
  - 상태가 `unknown`이면 막지 않는다. 점검을 끈 센서이거나, 시작 직후 첫 점검 전인 경우다.
  - 위험도 기준값(1/3건, 24시간)은 코드 상수다.
  - 인젝션된 페이지를 읽은 것(tool.result)도 행동으로 센다. 피해자도 위험도가 올라간다.

## 감사 로그 변조 방지 (안내서 C1-6, 금융보안원 ⑰)

[server/audit_chain.py](../src/sg_advance/server/audit_chain.py)가 다음 기록을 순서대로 해시 체인에 묶는다.

- 대상: Finding, 원격 대응과 그 결과, 보안팀 승인 결정, 정책 변경
- 연결식: `hash = sha256(prev | seq | kind | ref_id | digest | ts)`
- 검증 명령: `sga-server audit chain`
  - 기록을 바꾸거나, 지우거나, 순서를 바꾸면 그 지점부터 깨진다.
  - 끝부분을 잘라 내면 짧지만 유효한 체인이 남는다. 그래서 체인 머리(`GET /v1/admin/audit/chain`)를 밖에 보관해 두고 `--expect-head`로 비교한다.

## 승인 피로 지표 (안내서 C2, 금융보안원 ⑭)

`GET /v1/admin/approvals/metrics?days=7`의 결과를 대시보드 승인 감사 화면 위쪽에 보여 준다.

- 사용자 승인과 보안팀 승인을 나눠서 다음을 계산한다.
  - 요청 수와 반려율
  - 승인 소요 시간(중앙값, 상위 10%)
  - 5초 안에 승인한 비율
- 같은 룰과 툴로 5번 이상 요청됐고 95% 이상 승인된 유형은 **자동화·룰 조정 후보**로 표시한다. 조정 여부는 사용자가 정한다.

## 실환경 확인 (2026-11-13)

- 마이그레이션 0007 적용 전에 DB를 백업했다(`/data/sga.db.pre-zt`). 적용 후에도 기존 Finding 223건이 그대로였다.
- **위험도 오탐 수정**: 첫 배포에서는 설정 경보만으로 5명이 고위험이 됐다. 팀 게이트웨이의 서비스 계정에는 high가 51건 잡혀 있었다.
  - 행동 Finding만 세도록 고쳤다(시험 추가).
  - 고친 뒤 고위험자는 2명이었고, 둘 다 오늘 시험한 공격 호출에서 나온 것이다.
- **시험 센서로 확인**: 임시 HOME에 가짜 `~/.cursor`를 두었다. 실제 설정은 건드리지 않았다.

  | 순서 | 상황 | 결과 |
  |---|---|---|
  | 1 | Cursor가 있는 상태(degraded)에서 `crm` 호출 | **차단**: "보안 상태 미달 PC에서 민감 리소스 접근" |
  | 2 | `.cursor`를 지움 | 다음 점검에서 상태가 ok가 되고 같은 호출이 **통과** |
  | 3 | 인젝션이 든 위키 문서를 읽음 | 결과를 **모델에 넘기지 않음**(입력 PEP) |

  관제 서버에 Finding이 집행됨으로 기록됐고, 감사 체인 검증도 통과했다(14건). 시험 장비 `zt-mac-test`는 폐기했다.
