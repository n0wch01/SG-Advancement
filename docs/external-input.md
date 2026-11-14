# 후속 시나리오 ①: 외부 입력 뒤의 파괴적 행동 (2026-11-14)

CLAUDE.md 후속 시나리오의 첫 번째다. 외부에서 들어온 콘텐츠(웹 페이지, 외부 MCP 서버, 검색 결과, GitHub 이슈)를 읽은 직후 같은 대화에서 되돌릴 수 없는 명령이 실행되려는 경우를 다룬다.

## 판정 (승인 원칙 2026-11-14에 맞춤)

| 앞선 입력 | 뒤의 행동 | 룰 | 처리 |
|---|---|---|---|
| 인젝션 문구가 든 결과 | 파괴적 명령 | `injection-then-destructive-action` | **바로 차단**(공격 진행 신호, critical) |
| 외부 출처 결과(인젝션 문구 없음) | 파괴적 명령 | `destructive-after-external-input` | **사용자 승인**. critical로 따로 기록되어 보안팀 검토 큐에서 눈에 띈다 |
| 로컬·사내 출처 | 파괴적 명령 | `destructive-shell-command` 등 | 평소대로 사용자 승인 |

- 파괴적 명령: `rm -rf`, `mkfs`, `dd`, force push, 조건 없는 `DELETE`·`DROP`·`TRUNCATE`, `terraform destroy`, 클라우드 일괄 삭제.
- 시간 창: 10분, 같은 대화 안에서만.
- 두 시퀀스 룰의 파괴적 명령 패턴은 기존 세 룰(셸·SQL·클라우드)을 합친 것이다. 시험(`test_every_destructive_case_is_also_caught_after_external_input`)이 기존 룰의 양성 케이스가 모두 여기에도 걸리는지 확인한다.

## 관측·집행 지점

| 무엇 | 어디서 | 비고 |
|---|---|---|
| 입력의 출처 | 센서가 툴 호출을 볼 때 그 호출이 말을 건 곳을 기억한다. 그 호출의 결과에 `labels.sga_input_source`를 붙인다 | 출처는 호출 인자에서 읽는다: URL 호스트, `mcp:<서버>`, `search`, `github.com`(`gh issue`·`gh pr` 등), `local`, `file:<경로>`. 에이전트나 어댑터가 붙인 같은 이름 라벨은 지운다 |
| 무엇이 외부인가 | 서명된 룰(`destructive-after-external-input` 1단계) | 사내 목록: `local`, `file:*`, `mcp:testdb`·`mcp:reports`·`mcp:crm`, `*.corp.internal`. 나머지는 외부 |
| 인젝션 문구 | 서명된 룰(`injection-then-destructive-action` 1단계) | `injection-then-sensitive-action`의 1단계와 같은 패턴 |
| 실행 전 차단·승인 | Claude Code PreToolUse hook, OpenClaw 플러그인, MCP 게이트웨이 | 시퀀스는 데몬의 엔진이 기억한다 |

### MCP 게이트웨이의 한계와 보완

- 게이트웨이는 서버마다 대화를 따로 본다(`mcp:<서버>:<MCP 세션>`). MCP 프로토콜에 에이전트의 대화 식별자가 없어서, "웹 서버에서 읽고 DB 서버에서 삭제"를 하나의 흐름으로 잇지 못한다.
- 보완 1: Claude Code는 모든 MCP 툴을 한 대화에서 부르므로 **hook이 잇는다**(`mcp__web__…` 결과 → `mcp__testdb__…` 호출).
- 보완 2: 게이트웨이를 지나는 파괴적 SQL은 이 시나리오와 상관없이 **보안팀 사전 승인**으로 간다. 기다릴 수 없으면 차단한다(사람에게 물을 수 없는 지점). 시험에서 DB 서버가 요청을 받지 않았음을 확인했다.

## 확인

### 시험 (`tests/test_external_input.py`, 룰 케이스 8개)

- 차단: 인젝션 문구 → `rm -rf`, 인젝션 문구 → DB 툴 `DROP TABLE`(hook에서 MCP 툴끼리 연결).
- 사용자 승인으로 따로 기록: 외부 문서 → `terraform destroy`, GitHub 이슈 → force push.
- 해당 없음: 로컬 파일·사내 위키·사내 MCP 뒤, 파괴적이지 않은 명령, 10분이 지난 경우, 다른 대화.
- 위조: 결과에 `sga_input_source=local`을 붙여 보내도 센서가 지우고 다시 계산한다.
- 실제 부작용: 게이트웨이로 보낸 `DROP TABLE`을 DB 서버가 받지 않았다.

### 실환경 (임시 관제 서버, 실제 `sga-hook`·센서 데몬)

에이전트 역할 스크립트가 Claude Code처럼 hook JSON을 실제 `sga-hook`에 보냈다. hook이 허용할 때만 명령을 실행하게 했고, 지울 대상으로는 실제 폴더를 만들었다.

| 대화 | 흐름 | hook 결정 | 폴더 | 관제 서버 기록 |
|---|---|---|---|---|
| A | 웹 페이지(인젝션 문구) → `rm -rf` | 거부 | 남음 | `injection-then-destructive-action` 차단(critical). 인젝션 결과는 모델에 넘기지 않음(`result_withheld`) |
| B | 웹 페이지(평범) → `rm -rf` | 사용자 확인 | 남음(승인 전) | `destructive-after-external-input`(critical, 승인 요청) + `destructive-shell-command` |
| C | 로컬 파일 → `rm -rf` | 사용자 확인 | 남음(승인 전) | `destructive-shell-command`만 |

hook의 차단은 Claude Code가 따르는 것이라 기록은 "적용 미확인"이다. 폴더가 남은 것은 에이전트 역할 스크립트가 결정을 따랐기 때문이다. 실제 Claude Code에서의 확인은 노트북 실설치 때 한다.

## 한계

- **문구를 바꾼 인젝션**: 첫 룰이 놓친다. 외부 출처라면 두 번째 룰(사용자 승인 + 보안팀 검토)로만 잡힌다.
- **위임**: 부모가 읽고 하위 에이전트가 지우는 경우는 잇지 않는다. 위임 통제는 따로 다룬다(`cross-agent-injection-propagation`은 인젝션 → 민감 행동만).
- **데몬이 없을 때**: hook 단독으로는 시퀀스를 기억하지 못한다(상태 없는 룰만).
- **출처를 모르는 결과**: 센서를 다시 시작하기 전에 나간 호출의 결과, 또는 호출 없이 들어온 결과에는 출처 라벨이 없다. 이 경우 외부로 보지 않는다.
- **출처 추출 범위**: URL·MCP 서버·검색·`gh`만 본다. 스크립트 안에서 받아 오는 것(`python fetch.py`)은 `local`로 본다.
- **파일로 들어온 외부 입력**: 받아 둔 파일을 나중에 읽는 경우는 `local`이다. 다음 시나리오(임시 경로에 받은 파일 실행)에서 다룬다.
