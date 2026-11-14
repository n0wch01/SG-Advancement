# 후속 시나리오 ③: 부모보다 큰 권한을 받은 하위 에이전트 (2026-11-14)

CLAUDE.md 후속 시나리오의 세 번째다. 위임 통제로 다루며, 데이터 출처 추적(`lineage.py`)과는 따로 만들었다(`sensor/delegation.py`).

## 무엇이 문제인가

Claude Code 하위 에이전트는 정의 파일(`.claude/agents/*.md`)의 frontmatter로 권한을 정한다.

| 필드 | 뜻 |
|---|---|
| `permissionMode` | `plan` < `dontAsk` < `default` < `acceptEdits` < `auto` < `bypassPermissions` |
| `tools`, `disallowedTools` | 쓸 수 있는 툴 |
| `mcpServers` | 하위 에이전트가 직접 띄우는 MCP 서버 |

공식 문서(2026-11-14 확인)에 따른 동작:

- 부모가 `default`일 때 `acceptEdits`나 `auto`인 하위 에이전트는 **부모보다 넓게 실행된다**(수정이 확인 없이 적용됨).
- 하위 에이전트도 하위 에이전트를 만들 수 있다(기본 3단계). 그래서 툴이 제한된 하위 에이전트가 더 많은 툴을 가진 하위 에이전트를 만들 수 있다.
- 정의 파일은 작업 폴더에서 읽힌다. 내려받은 저장소가 자기 정의를 가지고 올 수 있다.

## 판정 (승인 원칙 2026-11-14에 맞춤)

| 시점 | 룰 | 무엇 | 처리 |
|---|---|---|---|
| 하위 에이전트를 만들기 전(Task/Agent 호출) | `delegation-grants-more-permission` | 정의가 부모보다 넓은 권한 모드, 부모(하위 에이전트일 때)에 없는 툴, 스스로 띄우는 MCP 서버를 준다 | **사용자 승인**(high, 2-1) |
| 하위 에이전트 실행 중 | `subagent-above-parent-permission` | 하위 에이전트가 보고한 권한 모드가 최상위 대화보다 넓다 | 읽기 전용이 아닌 행동마다 **사용자 승인**(부모였다면 물었을 것을 물음) |
| 위임 지시에 인젝션 문구 | `injection-relayed-to-agent`(기존) | | **바로 차단** |

라벨 `labels.sga_delegation_escalation`에는 더 받은 것이 적힌다.

- `mode:default→acceptEdits`
- `tools:+Bash,Write`
- `mcp:+pastebin`
- `runtime-mode:default→acceptEdits`

정의 파일 경로는 `sga_delegation_def`에 남는다. 보안팀 검토 큐에서 어느 파일이 권한을 줬는지 바로 보인다.

## 관측·집행 지점과 근거

| 무엇 | 어디서 오나 | 왜 믿나 |
|---|---|---|
| 부모의 권한 모드 | Task/Agent를 부르는 hook 입력의 `permission_mode`(Claude Code가 넣음) | 모델이 쓴 값이 아니다. 데몬이 없어도 호출 자체에 있어 판정된다 |
| 부모의 툴 | 메인 대화는 모든 툴. 부모가 하위 에이전트면 그 정의(hook의 `agent_type`) | Claude Code가 hook에 넣는 값으로 정의를 찾는다 |
| 하위 에이전트의 권한 | 정의 파일. 프로젝트(`<cwd>/.claude/agents`), 사용자(`~/.claude/agents`), 기본 형식(Explore·Plan은 읽기 전용, general-purpose는 상속) 순서로 찾는다 | 센서가 직접 읽는다. 내용은 비교만 하고 따르지 않는다 |
| 실행 중 모드 | 하위 에이전트 호출의 hook `permission_mode`와, 데몬이 기억한 최상위 대화의 마지막 모드 | 같은 Claude Code가 넣는 값 |

**실제 모드 계산.** Claude Code 문서의 규칙을 따른다.

- 부모가 `bypassPermissions`·`acceptEdits`·`auto`이면 하위 에이전트는 부모 모드로 실행된다(넓어지지 않음).
- 부모가 `plan`이면 하위 에이전트도 `plan`이다.
- 부모가 `default`·`dontAsk`이면 하위 에이전트 자신의 모드를 쓴다.

예외: `default` 부모 아래 `bypassPermissions` 요청은 v2.1.267 이상에서는 부모 모드로 묶이지만, 더 예전 버전에서는 묶이지 않는다. 그래서 이 경우는 넓어지는 것으로 센다(fail closed).

## 확인

### 시험 (`tests/test_delegation_permissions.py`, 룰 케이스 4개)

- 묻는 경우:
  - `default` 부모 → `acceptEdits` 하위 에이전트
  - `default` 부모 → `bypassPermissions` 요청
  - Read·Grep만 가진 하위 에이전트가 Bash·Write를 가진 하위 에이전트를 만듦
  - 스스로 MCP 서버(`pastebin`)를 띄우는 정의
- 묻지 않는 경우:
  - `acceptEdits` 부모 → `acceptEdits` 하위 에이전트(넓어지지 않음)
  - `plan` 부모 → `bypassPermissions` 요청(plan으로 묶임)
  - 툴이 더 좁은 하위 에이전트
  - 기본 형식 Explore
- 실행 중: `default` 메인 대화 아래 `acceptEdits`로 도는 하위 에이전트의 Write는 묻고 Read는 그대로 둔다. 부모와 같은 모드인 하위 에이전트는 그대로 둔다.
- 위조: 라벨을 비우거나 다른 값을 붙여 보내도 센서가 지우고 다시 계산한다.

### 실환경 (임시 관제 서버, 실제 `sga-hook`·센서 데몬)

`fixer`(`permissionMode: acceptEdits`) 정의가 든 작업 폴더에서, 에이전트 역할 스크립트가 hook이 허용할 때만 파일을 썼다.

| 호출 | hook 결정 | 결과 |
|---|---|---|
| 메인 대화 Read (`default`) | 허용 | - |
| 메인 대화 Task Explore | 허용 | - |
| 메인 대화 Task fixer | 사용자 확인 | `delegation-grants-more-permission`, `mode:default→acceptEdits`, 정의 `fixer.md` |
| fixer의 Write (`acceptEdits`) | 사용자 확인 | 파일 그대로("original"). `subagent-above-parent-permission`, `runtime-mode:default→acceptEdits` |
| fixer의 Read | 허용 | - |

## 한계

- **하위 에이전트의 `permission_mode`**: hook 입력의 이 값이 하위 에이전트 자신의 모드인지 문서에 명시되어 있지 않다. 실행 중 확인은 그렇다고 가정한다. 노트북의 실제 Claude Code에서 확인해야 한다.
- **`ask`와 `bypassPermissions`**: 부모가 `bypassPermissions`이면 하위 에이전트도 같은 모드라 이 룰은 걸리지 않는다. 그 경우는 기존 `claude-code-bypass-default`·`agent-safety-bypass`가 본다. `bypassPermissions` 대화에서 hook의 `ask`가 실제로 확인 창을 띄우는지도 실제 Claude Code에서 확인해야 한다.
- **정의를 못 찾는 하위 에이전트**: 플러그인 에이전트(문서상 `permissionMode`가 무시됨), `--agents`로 실행 중에 넘긴 정의, 이름이 파일과 다른 경우는 비교하지 않는다(`sga_delegation_def=unknown`).
- **메인 대화의 툴 제한**: 관리 설정의 `permissions.deny` 같은 메인 대화의 제한은 보지 않는다. 메인 대화는 모든 툴을 가진 것으로 본다.
- **데몬이 없을 때**: 만들기 전 비교는 hook 단독으로도 되지만, 실행 중 비교는 최상위 대화의 모드를 기억해야 해서 데몬이 있어야 한다.
- **OpenClaw**: 아래 "OpenClaw" 절을 본다.

## OpenClaw (2026-11-14 추가)

설치된 OpenClaw 2026.11.3의 문서로 확인한 동작:

- **툴**: 하위 에이전트는 부모의 툴 한도를 물려받는다(`tools/subagents/tool-policy`). 그래서 툴은 비교하지 않는다.
  - 예외: 운영자 설정 `agents.entries.<id>.subagents.delegateToolsTo`. 이 설정이 있으면 요청한 에이전트의 `tools.deny`가 그 대상에게는 풀린다.
- **권한 모드**: 새 세션은 모드를 정하지 않으면 그 에이전트의 설정을 따른다(`gateway/permission-modes`). 그래서 `sessions_spawn`의 `agentId`로 다른 에이전트를 고르면, 자식은 **그 에이전트의 기본 모드**로 시작한다.
  - 모드 순서: `read-only` < `guarded` < `workspace` < `full`.
- **샌드박스**: `sessions_spawn`의 `sandbox`는 기본 `inherit`이다. 대상 에이전트가 샌드박스 밖이면 자식도 밖에서 돈다. `require`를 주면 샌드박스 안에서만 만든다.

| 시점 | 무엇 | 근거 | 처리 |
|---|---|---|---|
| `sessions_spawn` 호출(실행 전, 플러그인) | 대상 에이전트의 기본 모드가 부모 에이전트보다 넓음(`mode:workspace→full`), 부모는 샌드박스 안인데 자식은 밖(`sandbox:on→off`) | 부모 에이전트는 대화 키(`agent:<id>:…`). 에이전트별 기본 모드는 인벤토리(`inventory.snapshot`), 샌드박스는 설정 스냅샷 | `delegation-grants-more-permission` 사용자 승인 |
| 하위 세션 실행 중 | 다른 에이전트의 하위 세션이 최상위 대화의 에이전트보다 넓은 모드 | 위임 사슬(`root_session_id`, M5b)과 인벤토리 | `subagent-above-parent-permission`: 읽기 전용이 아닌 툴은 사용자 승인 |
| 설정 | `delegateToolsTo` | 설정 감시(`config.snapshot`의 `delegation_grants`, 새 칸) | `openclaw-delegate-tools-grant` 경보 |

확인:

- 시험(`tests/test_delegation_permissions.py`의 OpenClaw 4개):
  - `workspace` → `full` 에이전트는 묻는다. 더 좁은 에이전트와 같은 에이전트는 묻지 않는다.
  - 샌드박스 밖으로 나가면 묻고, `sandbox: require`면 묻지 않는다.
  - 실행 중인 하위 세션의 `write`는 묻고 `read`는 그대로 둔다.
  - 설정에서 `delegateToolsTo`를 읽는다.
- 실환경:
  - 실제 센서 데몬 소켓에 플러그인과 같은 형식(`op: tool_call`)으로 보냈다. `research`(`workspace`)가 `ops`(`full`)로 하위 세션을 만들면 `approve`(`mode:workspace→full`)였고, 같은 에이전트면 `allow`였다.
  - 지금 운영 중인 에이전트(이 PC의 `main`, 팀 게이트웨이의 `main`·`research`)는 모두 `full`이라 상승이 일어날 수 없다. 대신 `openclaw-agent-permission-full` 경보가 이미 나고 있다.
  - 이 PC의 실제 설정에는 `delegateToolsTo`가 없다.

한계(OpenClaw):

- **세션별 모드 변경**: `sessions.patch`로 한 세션의 모드만 바꾼 경우는 보지 않는다. 에이전트 기본 모드만 비교한다.
- **인벤토리 전**: 센서가 시작하고 첫 인벤토리를 받기 전에는 비교하지 못한다(보통 연결 직후 몇 초).
- **ACP·클라우드 하위 에이전트**: OpenClaw 자체의 상속 규칙을 따른다고 보고 따로 보지 않는다.
