# 도구 호출의 행동 구조 해석

센서는 도구 호출을 제한된 문법으로 해석해 `sga_act_*` 라벨을 붙인다.
판정은 기존 서명된 룰이 한다. 일반 셸이나 Git 설정 전체를 해석하는 파서는 아니다.

## 원문 검사와 구조 검사의 관계

| `sga_act_parse` | 의미 | `normalized-by:sga_act` 룰의 검사 대상 |
|---|---|---|
| `ok` | 지원하는 문법과 명령으로 호출 전체를 해석함 | 행동 라벨 |
| `partial` | 일부 명령이나 실행 설정의 의미를 해석하지 못함 | 원문과 행동 라벨 |
| `unsupported` | 동적 명령·명령 치환 등 문법을 해석하지 못함 | 원문과 행동 라벨 |

예를 들어 `r''m -rf build`는 따옴표를 처리한 뒤 삭제 행동으로 판정한다.
`echo 'rm -rf build'`는 문자열을 출력하므로 삭제 행동으로 판정하지 않는다.
반대로 실행될 수 있는 부분을 이해하지 못했다면 `ok`를 붙여 원문 검사를 생략해서는 안 된다.
해석 상태 자체가 허용·차단을 결정하지는 않으며, 기존 룰의 승인·차단 기준이 적용된다.

## 왜 필요했나 (재현, 2026-11-17)

변경 전 `destructive-shell-command`는 툴 인자 전체(`payload.arguments`)를 정규식으로 봤다. 같은 행동인데 표기만 다르면 판정이 갈렸다.

| 명령 | 변경 전 | 변경 후 |
|---|---|---|
| `r''m -rf ~/projects`, `'rm' '-rf' ~/projects`, 줄을 이어 쓴 `rm -r \` / `-f` | 허용(미탐) | 사용자 승인 |
| `echo 'never run rm -rf / on prod'`, `grep -rn 'rm -rf' docs/`, 커밋 메시지 속 `rm -rf` | 사용자 승인(오탐) | 허용 |
| 히어독으로 파일에 쓰기(`cat > clean.sh <<'EOF'` … `rm -rf build`) | 사용자 승인(오탐) | 허용(파일 쓰기로 기록) |
| `Write` 툴로 문서에 쓴 `rm -rf build/` | 사용자 승인(오탐) | 허용 |
| `git push origin +main`, `dd of=… if=…`, `git checkout HEAD -- .` | 허용(미탐) | 사용자 승인 |
| `R=rm; $R -rf ~/projects`, `rm -rf $(cat list)`, `eval …`, `python3 -c "shutil.rmtree(…)"`, `./cleanup.sh` | 변경 전과 같음 | 변경 전과 같음(원문 정규식, 해석 실패로 기록) |

재현: `tests/test_actions.py`, `tests/rule_cases/tool_misuse.yaml`의 "(구조)" 케이스.

## 지원 범위

**셸 문법(제한된 POSIX 부분집합, `sh-subset/1`)**: 작은따옴표·큰따옴표, 백슬래시, 줄 이어 쓰기, `;` `&&` `||` `|` `&` 줄바꿈, 괄호 묶음, 리다이렉트(`>` `>>` `2>&1` `<<<`), 따옴표 친 히어독, 주석, `if`·`while`·`for` 안의 명령, 앞에 붙은 변수 대입.

**래퍼(뒤의 명령을 판정)**: `sudo`, `doas`, `env`, `command`(`-v` 제외), `builtin`, `exec`, `nohup`, `time`, `nice`, `ionice`, `stdbuf`, `timeout`, `xargs`(대상은 `<stdin>`), `bash`·`sh`·`zsh`·`dash`·`ksh -c '문자열'`과 셸에 넣는 따옴표 친 히어독.

**구조화된 툴**: 셸 툴의 문자열 명령과 argv 목록(Codex의 `["bash", "-lc", "…"]`), 파일 쓰기 툴(`Write`·`Edit` 등, 내용은 데이터), `apply_patch`의 `*** Delete File:`, 읽기 전용 툴.

**지원하지 않음**: PowerShell, 다른 언어(OpenClaw Code Mode의 자바스크립트, `python -c` 등), 스크립트 파일 안, 변수의 실제 값, 사용자 셸의 별칭·함수, git 별칭, `$(…)`·백틱, `case`, 함수 정의, ANSI-C 따옴표(`$'…'`), 2만 자 넘는 명령. MCP·웹 툴은 라벨을 붙이지 않는다(원문 룰만).

## 라벨

센서가 `Sensor.stamp`에서 붙인다(데몬, 데몬 없는 hook의 캐시 정책 경로 모두). 이벤트에 같은 이름의 라벨이 들어오면 지우고 다시 계산한다(`core._OWN_LABELS`).

| 라벨 | 값 |
|---|---|
| `sga_act_parse` | `ok` / `partial` / `unsupported` |
| `sga_act_unknown` | 이유: `unmodelled:npm`, `script:./x.sh`, `inline:python3`, `dynamic-command`, `command-substitution`, `git-config`, `language:javascript` … |
| `sga_act_ops` | 해석한 부분에서 찾은 동작: `delete`, `write`, `exec`, `read` |
| `sga_act_destroy` | 파괴적 행동의 종류(아래), 쉼표로 구분 |
| `sga_act_targets` | 대상(쓴 그대로, `$DIR`은 풀지 않음, 500자) |

파괴적 행동 종류(`actions.KINDS`, 변경 전 정규식의 갈래와 대응): `rm-recursive-force`, `rm-recursive`, `find-delete`, `find-exec-rm`, `shred-file`, `git-clean-force`, `git-reset-hard`, `git-checkout-all`, `git-restore-all`, `git-push-force`, `mkfs-format`, `dd-raw-write`, `chmod-777-root`.
`rm-recursive`(강제 없는 `rm -r`)도 사용자 승인이다(2026-11-17 사용자 결정, 2026-11-15의 "재귀와 강제가 함께" 기준을 바꿈).
- 이유: 에이전트는 터미널 없이 실행하므로 `rm -r`도 묻지 않고 지운다.
- 오탐: `rm -r build` 같은 정리 작업에도 승인 창이 뜬다.
- 해소된 미탐: Windows 평가 WE01(PowerShell 별칭 `rm -r C:\...`)이 함께 잡히게 됐다(Windows 우회 시도 탐지 82% → 88%).
- 원문 정규식에서는 `git rm`을 뺐다(`git rm -r --cached`는 추적 해제).

- **`ok`인 경우**: 모든 명령이 모델에 있거나, 인자를 데이터로만 쓰는 명령(`echo`, `grep`, `cat`, `git commit` …)이다.
- **찾은 것은 해석 상태와 관계없이 사실이다**: `npm test && r''m -rf dist`는 `partial`이지만 삭제는 기록된다.
- **없다는 결론은 `ok`일 때만 의미가 있다.**

## 룰과의 연결

`destructive-shell-command`(v2)와 `*destructive`를 공유하는 시퀀스 룰 세 개(`injection-then-destructive-action` v4, `classifier-injection-then-destructive-action` v2, `destructive-after-external-input` v2)에 `normalized-by:sga_act` 태그를 달았다.

- 엔진(`detect/engine.py`)은 `sga_act_parse=ok`이면 이 룰들의 `labels.sga_act_*` 칸만 본다.
- 그 밖이면 원문과 라벨을 모두 본다. 응답(사용자 승인·차단)은 바뀌지 않았다.
- 태그는 예전 센서가 무시하므로, 예전 센서는 원문으로 판정한다(호환).

## 외부 입력 직후 해석할 수 없는 명령 (2026-11-17 사용자 결정)

구조로 읽지 못한 명령은 원문 정규식이 판정하므로, 원문에도 위험 패턴이 없으면 허용된다(`R=rm; $R -rf`, `python3 -c "shutil.rmtree(…)"`, `./cleanup.sh`). 인젝션은 이런 형태로 실행 내용을 숨길 수 있다.

새 시퀀스 룰 `unparsed-command-after-external-input`(high, 사용자 승인):
- **조건**: 외부 입력을 읽은 뒤 10분 안에, 같은 대화에서 `sga_act_unknown`이 실행 내용을 숨길 수 있는 이유인 명령이 오면 사용자 승인을 받는다.
- **대상 이유**: 동적 명령, `eval`, 명령·프로세스 치환, 확장되는 히어독, 동적 `bash -c`, 스크립트, 인라인 코드, 셸 표준입력 실행, git 실행 설정.
- **뺀 것**: 모델에 없는 명령(`npm`·`docker`, 원문 룰이 내용을 봄), PowerShell 전체(항상 해석 불가), Code Mode 바깥 호출.
- **오탐**: 외부 문서를 읽은 직후의 `cd $(git rev-parse --show-toplevel)`, `./gradlew build`, `python -c`도 묻는다.
- **미탐**: 외부 입력이 없을 때, 10분 뒤, 다른 대화·하위 에이전트로 넘어간 경우, 라벨이 없는 예전 센서.
- **실제 기록 재생**: 새로 걸린 사례는 0건이다. 기록의 셸 명령이 21건뿐이라 소음 측정 근거로는 약하다.
- **다음 단계(같은 결정)**: 같은 대화에서 직접 쓴 스크립트의 내용을 기억해 두었다가, 실행할 때 분석한다.

## Git 실행 설정의 우회 수정 (2026-11-17)

Git은 `core.editor`로 편집기 명령을 실행하고, `core.sshCommand`로 SSH 호출을 바꿀 수 있다.
근거: [Git 설정 문서](https://git-scm.com/docs/git-config).

수정 전에는 `git -c core.editor='rm -rf ...' commit`의 `-c`를 건너뛴 뒤
`commit`을 아는 명령으로 처리했다. 전체 호출이 `ok`가 되어, 설정값 안의 명령을 검사하지 않았다.

이제 다음 옵션이 있으면 `partial`로 처리하고 기존 원문 검사를 유지한다.

- `-c name=value`, 붙여 쓴 `-cname=value`: `sga_act_unknown=git-config`
- `--config-env=name=ENV_VAR`: `sga_act_unknown=git-config-env`

`git -c color.ui=false status` 같은 일반 명령은 기존 룰에 위험 패턴이 없으면 허용된다.
설정값의 `rm -rf`가 탐지되면 기존 `destructive-shell-command` 정책에 따라 사용자 승인을 요청한다.
공격 진행 신호 등 더 강한 차단 룰이 함께 걸리면 그 판정이 우선한다.
승인 정책이나 룰의 정규식을 바꾸는 수정은 아니다.

## 검증과 한계

- `tests/test_actions.py`는 일반 Git 작업, `-c`의 두 표기와 설정 내 위험 명령을 검사한다.
- 임시 Git 저장소의 `core.editor`에 삭제 명령을 넣었다. 보호 없이 실행하면 임시 파일이 삭제되는
  양성 대조를 확인한 뒤, 센서가 승인을 요청하면 같은 작업이 실행되지 않아 파일이 남는지 검사한다.
  데몬과 서명된 캐시 정책 경로를 모두 사용한다.
- 이 시험은 실제 Git 명령과 hook/데몬을 사용하지만, 승인 판정을 따르는 시험용 실행기를 이용한다.
  실제 Claude Code 제품이 판정을 따르는지는 별도의 실환경 검증 대상이다.
- Git 설정값, 환경변수의 실제 값, 기존 저장소의 hook·별칭·필터·스크립트 내용까지 추적하지 않는다.
  원문에 드러나지 않는 명령이나 난독화된 설정값은 기존 패턴 검사에서 놓칠 수 있다.
- `-c`가 있으면 원문 검사도 유지하므로, 무해한 커밋 메시지에 위험 명령을 설명한 경우에도
  승인이 요청될 수 있다. 이 경우의 정밀 분석과 오탐 조정은 별도 범위다.

## 과거 기록 재생

`scripts/replay_history.py --normalize`는 저장된 행동 라벨을 현재 센서 기준으로 다시 계산한다.
툴 호출 외 이벤트와 다른 메타데이터는 유지하며, 입력 DB는 읽기 전용으로 연다.
예전 기록에 라벨이 없거나 오래된 라벨이 있어도 현재 구조 판정으로 비교할 수 있다.
원문이 이미 마스킹·축약된 기록의 한계는 복원하지 못한다.

```bash
uv run python scripts/replay_history.py COPY.db --normalize --baseline none
```

## 실행한 검증과 미검증 (2026-11-17)

- **부작용 확인**: 임시 폴더를 만들고, 판정이 허용일 때만 실제로 실행하는 시험용 실행기로 확인했다. 데몬 경로와 데몬 없는 캐시 정책 경로 모두에서 다음을 확인했다(`test_only_allowed_commands_touch_files_through_the_daemon`, `test_the_same_decisions_without_the_daemon`).
  - 표기를 바꾼 삭제는 승인 대기 상태로 남고 폴더가 남는다.
  - `echo`는 실제로 실행되고 아무것도 지워지지 않는다.
  - 대조군 `rm 파일`은 실제로 지워진다.
- **위조**: 에이전트가 `sga_act_parse=ok`를 붙여 보내도 지우고 다시 계산한다. 출처 라벨을 함께 위조해도 같다(`test_forged_action_and_source_labels_are_dropped`).
- **실제 기록 재생** (`--normalize`, 변경 전 룰 `22d2c54` 대비): 판정이 바뀐 사례는 0건이다.
  - 기록의 툴 호출은 219건이고, 셸은 Bash 8건과 OpenClaw `exec` 92건뿐이다.
  - `exec` 92건 중 79건은 Code Mode 자바스크립트라 지금은 해석하지 않는다(`unsupported`). PowerShell은 24건이다.
  - 실제로 구조로 판정된 셸 명령은 21건(`ok` 15, `partial` 6)이다.
  - 그래서 이 결과는 "실제 작업에서 오탐이 늘지 않았다"는 약한 근거일 뿐이고, 개선 효과의 근거는 아니다.
- **미검증**: 실제 Claude Code·Codex 제품이 이 판정을 따르는지는 시험용 실행기와 별개다. 별도의 실환경 검증 대상이다(로드맵 1, 2).

