# 정책 관리 (M9)

정책은 세 층이다. 센서는 자기 장비가 속한 층까지 합친 결과를 **서명된 묶음 하나**로 받는다. 묶음 형식은 M4와 같아서 센서는 바뀐 것이 없다.

| 층 | 누가 | 바꿀 수 있는 것 | 기록 |
|---|---|---|---|
| 저장소 룰 (`rules/*.yaml`) | 개발자, 코드 리뷰 | 전부 | git |
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

## 한계

- "누가"는 입력값이다. 관리자 토큰을 같이 쓰는 동안은 사람 신원을 증명하지 못한다(M12에서 SSO·개인 토큰).
- 변경 이력은 DB 안에 있다. 해시 체인·외부 보관은 감사 로그 등급 과제(이후 과제)에서 다룬다.
- 저장소 룰(`rules/`)을 고치면 공통·팀 덮어쓰기는 룰 id로 다시 붙는다. 룰이 사라지면 그 덮어쓰기는 효과가 없다(목록에서 보이지 않음).
