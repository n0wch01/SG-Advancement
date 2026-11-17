# 정책 관리 (M9)

정책은 세 층이다. 센서는 자기 장비가 속한 층까지 합친 결과를 **서명된 묶음 하나**로 받는다. 묶음 형식은 M4와 같아서 센서는 바뀐 것이 없다.

| 층 | 누가 | 바꿀 수 있는 것 | 기록 |
|---|---|---|---|
| 저장소 룰 (`rules/*.yaml`) → DB의 확정 룰 | 개발자, 코드 리뷰 후 명시적 반영 | 전부 | git, DB 확정본 |
| **공통 정책** (`scope=common`) | 보안팀 | 룰 켜기·끄기, 대응 단계 올리기·내리기, 허용 목록 바꾸기 (완화 가능) | 변경 이력 |
| **팀 정책** (`scope=<팀>`) | 보안팀(팀 요청) | **더 엄격하게만**: 룰 켜기, 대응 올리기, 허용 목록 줄이기 | 변경 이력 |

결정(2026-11-12, 모두 추천안):
- 장비 배정: 등록 토큰에 팀을 지정하면 그 토큰으로 등록한 장비가 팀에 들어가고, 관리자가 나중에 옮길 수 있다. 팀이 없으면 공통만.
- 편집: 대시보드(관리자 토큰으로 로그인했을 때만 편집 버튼)와 CLI. 읽기 전용 대시보드 토큰은 보기만.
- 덮어쓸 수 있는 값: 켜기/끄기, 대응 단계, 허용 목록(허용 목록 룰만). 심각도·임계값은 아직 아니다.
- 스키마 변경은 Alembic 마이그레이션으로.

## "더 엄격하게만"을 지키는 방법

1. **저장할 때 검사**(`policy_layers.check`): 팀이 룰을 끄거나, 대응을 공통보다 낮추거나, 공통 목록에 없는 허용 항목을 넣으면 422.
   허용 항목은 공통 목록에 그대로 있거나, 와일드카드가 없는 이름이 공통의 와일드카드에 포함되면 좁힌 것으로 본다(`api.openai.com` ⊂ `*.openai.com`).
2. **묶음을 만들 때 다시 합침**(`apply_group`): 저장된 값과 관계없이 대응은 공통과 팀 중 더 센 쪽, 허용 목록은 공통에 포함되는 것만 남긴다.
   그래서 팀 값을 쓴 뒤 공통이 더 엄격해져도 팀 정책이 공통보다 느슨해지지 않는다.
3. 팀 정책 취소(`clear`)는 공통으로 돌아가는 것이라 허용한다. 공통 정책 자체를 완화하는 것은 보안팀의 일이고 이력에 남는다.

## 변경 이력

모든 쓰기(팀 생성, 장비 배정, 덮어쓰기 설정·취소)는 `policy_changes`에 한 줄씩 남는다: 누가(`by`, 필수), 왜(`reason`, 필수), 이전 값과 이후 값, 시각.
줄 번호가 **정책 리비전**이다. 관리자 토큰은 하나를 같이 쓰므로 "누가"는 입력값이다(실제 신원 확인은 SSO가 붙는 M12).
거절된 시도(422)는 이력에 남지 않는다.

## 사용법

```bash
export SGA_SERVER=http://127.0.0.1:18100 SGA_ADMIN_TOKEN=...   # 출력하지 않는다
sga-server policy group data-team --description 데이터팀 --by secops --reason "데이터팀 강화"
curl -X POST .../v1/admin/enrollment-tokens -d '{"group":"data-team"}'   # 이 토큰으로 등록하면 data-team
sga-server policy assign dev-7 data-team --by secops --reason "..."     # 이미 등록된 장비 옮기기 (--common: 팀에서 빼기)
sga-server policy set data-team destructive-sql --response block --by secops --reason "운영 DB 접근이 잦음"
sga-server policy set common exhaustion-keyword-prompt --disable --by secops --reason "오탐이 많음"
sga-server policy set data-team egress-unapproved-host --allow "api.openai.com,chatgpt.com" --by secops --reason "..."
sga-server policy clear data-team destructive-sql --by secops --reason "..."
sga-server policy scopes | rules --scope data-team --changed | log
```

대시보드 **정책** 화면: 범위(공통·팀) 탭, 룰마다 저장소 기본 → 적용 결과와 덮어쓰기, 바뀐 룰만 보기, 장비 배정, 변경 이력.
관리자로 로그인하면 룰마다 편집기가 열린다. 팀 범위에서는 처음부터 더 엄격한 선택지만 보인다(끄기 없음, 대응은 현재 이상, 허용 목록은 공통 항목 중에서 고르기).

## API

| 메서드 | 경로 | 권한 |
|---|---|---|
| GET | `/v1/admin/policy/scopes` (공통·팀별 장비 수, 버전, 덮어쓰기 수, 리비전) | 읽기 |
| GET | `/v1/admin/policy/rules?scope=` (저장소 기본, 공통·팀 덮어쓰기, 적용 결과) | 읽기 |
| GET | `/v1/admin/policy/changes?scope=` | 읽기 |
| POST | `/v1/admin/policy/groups` | 관리자 |
| PUT | `/v1/admin/devices/{id}/group` | 관리자 |
| PUT | `/v1/admin/policy/overrides` | 관리자 |
| POST | `/v1/admin/policy/overrides/clear` | 관리자 |

센서의 `GET /v1/policy`는 장비의 팀 묶음을 준다. 응답 헤더 `X-SGA-Policy-Group`에 팀 이름이 실린다(묶음 본문에는 넣지 않았다: 실행 중인 예전 센서가 모르는 필드로 묶음을 거부하지 않도록).

## 실환경 확인 (2026-11-12)

- 기존 관제 서버 DB(이벤트 1,277건)를 백업(`/data/sga.db.pre-m9`)한 뒤 첫 마이그레이션: `0001`로 표시 → `0002` 적용, 데이터 그대로.
- CLI로 `demo-team` 생성 → `destructive-sql`을 차단으로 → 같은 룰을 알림으로 낮추기는 422(이력에 안 남음) → `carol-pc`를 `demo-team`에 배정.
  60초 안에 carol-pc 센서가 팀 묶음(서명 검증)을 받았고, 나머지 4대는 공통 묶음 그대로.
- 테스트 관제 서버에서 대시보드 정책 화면(관리자): 범위 탭, 바뀐 룰 3개, 팀 편집기의 선택지가 더 엄격한 것만 나오는 것, 변경 이력 확인.
- 처음 구현은 허용 목록을 글자 그대로만 비교해서 `*.openai.com` 아래의 `api.openai.com`으로 좁히는 것도 거절했다 → 와일드카드 포함 검사로 고쳤다.

## 단계적 배포와 적용 시작 시각 (2026-11-16)

Microsoft의 에이전트 정책 묶음(PolicyPack)이 `version`, `effectiveFrom`, `priority`를 갖는 것과 같은 이유로 넣었다. 새 룰을 바로 모든 장비에 보내지 않는다.

```bash
sga-server policy stage my-mac --by me --reason "rm -rf 차단 시험"         # rules/의 지금 내용을 my-mac에만
sga-server policy rollout                                                   # 지금 정책과 시험 중인 정책
sga-server policy promote --from 2026-11-18T09:00:00+09:00 --by me --reason "확인 끝"   # 모두에게, 이 시각부터
sga-server policy discard --by me --reason "오탐 많음"                       # 시험 중인 정책 버림, 시험 장비는 원래대로
```

- **시험 장비(canary)만 새 룰을 받는다.** 나머지는 지금 정책을 유지한다. 시험 장비가 팀에 속해 있으면 새 룰 위에 그 팀의 강화가 그대로 얹힌다.
- **정책의 기준은 DB 확정본이다(2026-11-17 결정).** `policy_state`가 비어 있는 최초 기동 때만 `rules/`를 읽어 기준을 만든다. 이후 파일 수정이나 서버 재시작은 정책을 바꾸지 않는다. 파일은 명시적인 `reload` 또는 `stage` 때 읽으며, `promote`는 파일을 다시 읽지 않고 DB에 저장한 시험 정책을 승격한다. 시험 중에는 `reload`를 거부한다(먼저 promote나 discard).
- **적용 시작 시각(`effective_from`)은 서명 범위 안에 있다.** 정책 버전(해시)에 포함되므로 중간에서 바꾸면 서명 검증에 실패한다.
  - 센서는 시각 전이면 정책을 **검증만 하고 기다린다**(`scheduled`). 시각이 지난 다음 동기화(60초 주기)에서 설치한다. 모든 장비가 같은 시각에 바뀐다.
  - 정책이 아예 없는 센서는 기다리지 않고 바로 설치한다. 정책이 없는 것보다 서명된 정책이 낫다.
- **기록:** `rollout.stage`, `rollout.promote`, `rollout.discard`가 변경 이력과 감사 체인에 남는다.
- **시험 상태도 DB에 저장한다.** 시험 룰·대상 장비·적용 시작 시각, 확정 룰·확정 시작 시각을 재시작 후 복구한다. 다른 서버 인스턴스에서도 같은 시험 상태를 보고 승격·취소할 수 있다.
- **서버별 캐시는 DB 세대를 확인한다.** 정책 관련 요청마다 `policy_state.generation`을 확인한다. 공통·팀 덮어쓰기와 매니페스트 변경도 다른 인스턴스의 캐시를 무효화한다. 시험 배포·승격·취소·reload가 준비 중에 다른 변경과 충돌하면 409를 반환해 새 상태를 읽고 다시 시도하게 한다.
- **호환:** 시작 시각이 없는 정책은 예전과 똑같은 모양으로 내려간다(빈 필드 생략). 이전 버전 센서도 받는다. 시작 시각이 있는 정책은 이전 센서가 받지 못하고 기존 캐시를 유지한다.
- 시험: `tests/test_staged_rollout.py`, `tests/test_policy_persistence.py`(다른 인스턴스 반영, 재시작 복구, 시작 시각 보존, 미배포 파일 무시, 변경 충돌).

## DB 정책 기준 도입 시 주의

- 마이그레이션 `0011`은 정책 상태 테이블을 추가하며 기존 이벤트·장비·덮어쓰기를 유지한다.
  상태가 아직 없는 첫 기동은 **그때의 파일을 확정 기준으로 가져오므로**, 도입 전 DB를 백업하고
  `rules/`가 마지막 검토본인지 확인한다. 이전 버전의 메모리에만 있던 시험 배포는 자동 복구할 수 없다.
- 이후 코드 이미지 재배포나 서버 재시작만으로 새 룰이 반영되지는 않는다. 룰 변경은 검증 후
  `stage → 확인 → promote` 또는 명시적인 reload API로 배포한다.
- 시험 장비·시작 시각도 DB 백업에 포함된다. 복구 시 정책 서명 키와 장비 CA 등 기존 키 자료도
  함께 유지해야 센서가 같은 신뢰 기준으로 정책을 검증할 수 있다.
- 이번 검증은 SQLite의 여러 앱 인스턴스와 재시작을 대상으로 한다. 다중 프로세스 마이그레이션,
  감사 체인 동시 봉인 등 관제 서버 전체의 수평 확장 검증을 대신하지 않는다.

## 한계

- "누가"는 입력값이다. 관리자 토큰을 같이 쓰는 동안은 사람 신원을 증명하지 못한다(M12에서 SSO·개인 토큰).
- 변경 이력은 DB 안에 있다. 해시 체인·외부 보관은 감사 로그 등급 과제(이후 과제)에서 다룬다.
- 저장소 룰(`rules/`)을 고치면 공통·팀 덮어쓰기는 룰 id로 다시 붙는다. 룰이 사라지면 그 덮어쓰기는 효과가 없다(목록에서 보이지 않음).
