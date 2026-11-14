# 후속 시나리오 ②: 임시 경로에 받은 파일 실행 (2026-11-14)

CLAUDE.md 후속 시나리오의 두 번째다. 에이전트가 인터넷에서 파일을 임시 경로에 내려받은 뒤 그 파일을 실행하는 경우와, 내려받은 스크립트를 파일 없이 바로 셸에 넘기는 경우를 다룬다.

## 판정 (승인 원칙 2026-11-14에 맞춤)

| 흐름 | 룰 | 처리 |
|---|---|---|
| 외부에서 임시 경로·다운로드 폴더로 받은 파일을 실행 | `run-downloaded-file` | **사용자 승인**. critical로 따로 기록되어 보안팀 검토 큐에 오른다 |
| 내려받아 바로 셸·인터프리터로 실행(`curl … \| sh`, `bash <(curl …)`, `iwr … \| iex`) | `pipe-download-to-shell` | **사용자 승인**(high). 상태가 필요 없어 데몬 없이도 잡힌다 |
| 인젝션 문구를 읽은 뒤의 내려받기 | `injection-then-sensitive-action`(기존) | **바로 차단**(공격 진행 신호) |

- 공격 진행 신호나 외부 유출이 아니므로 바로 막지 않고 사람에게 묻는다(사용자 결정 2026-11-14: 사람에게 묻는 것이 맞음).

## 관측·집행 지점

| 무엇 | 어디서 | 비고 |
|---|---|---|
| 무엇을 어디에 받았나 | 센서가 셸 호출을 볼 때 기억한다: `curl -o/-O/> 파일`, `wget -O/-P/기본 이름`, `Invoke-WebRequest -OutFile`, `git clone`. 같은 명령의 `cd <폴더>`도 반영한다 | 경로와 출처 호스트를 24시간, 최대 2000개 둔다(데몬 메모리) |
| 받은 파일을 실행하나 | 이후 셸 호출이 그 경로(또는 그 아래 파일)를 실행하는 형태인지 본다. 형태: 직접 실행, `./이름`, 인터프리터(`sh`, `python`, `node`, `pwsh`, `source` 등), PowerShell `&`·`Start-Process`. 같은 명령 안의 받기 → 실행(`curl -o x && sh x`)도 포함한다 | 맞으면 `labels.sga_runs_downloaded = "<호스트> <경로>"`. 에이전트가 붙인 같은 이름 라벨은 지운다 |
| 임시 경로·외부 출처인가 | 서명된 룰(`run-downloaded-file`) | 임시 경로: `/tmp`, `/var/tmp`, `/private/tmp`, `/private/var/folders`(macOS), `/dev/shm`, `$TMPDIR`, `%TEMP%`·`$env:TEMP`, `AppData\Local\Temp`. 다운로드 폴더(결정 2026-11-14): `~/Downloads`, `$HOME/Downloads`, `/Users/<이름>/Downloads`, `/home/<이름>/Downloads`, `C:\Users\<이름>\Downloads`, `%USERPROFILE%\Downloads`. 사내(`*.corp.internal`)에서 받은 것은 제외 |
| 실행 전 승인 | Claude Code PreToolUse hook, OpenClaw 플러그인 | 셸 툴만 본다 |

## 확인

### 시험 (`tests/test_downloaded_exec.py`, 룰 케이스 4개)

- 사용자 승인: `curl -o /tmp/setup.sh` 뒤 `chmod +x && 실행`, `cd /tmp && wget` 뒤 `./tool.bin`, `git clone … /tmp/tools` 뒤 `bash /tmp/tools/install.sh`, `curl … > /tmp/a.py` 뒤 `python3`, 한 명령 안의 받기 → 실행.
- 해당 없음: 사내 저장소에서 받은 것, 받은 파일을 읽기만 하거나 지우는 것, 받은 적 없는 파일.
- 위조: 라벨에 사내 출처라고 적어도, 무관한 명령에 라벨을 붙여도 센서가 지우고 다시 계산한다.
- 데몬 없음: `curl | sh`는 hook 단독(캐시 정책)으로도 사용자 승인이 된다.
- **실제 부작용**: 로컬 HTTP 서버에서 스크립트를 실제로 내려받고(파일 생김), 실행은 승인 대기 상태로 두었다. 스크립트가 만들었어야 할 표시 파일이 생기지 않았다.

### 실환경 (임시 관제 서버, 실제 `sga-hook`·센서 데몬)

에이전트 역할 스크립트가 hook이 허용할 때만 명령을 실행했다.

| 대화 | 명령 | hook 결정 | 결과 | 관제 서버 기록 |
|---|---|---|---|---|
| A | `curl -fsS -o /tmp/sga-live-setup.sh http://127.0.0.1:18897/install.sh` | 허용 | 파일 받아짐 | - |
| A | `chmod +x /tmp/sga-live-setup.sh && /tmp/sga-live-setup.sh` | 사용자 확인 | 스크립트 실행 안 됨 | `run-downloaded-file`(critical, 승인 요청, `127.0.0.1 /tmp/sga-live-setup.sh`) |
| B | `curl -fsS http://127.0.0.1:18897/install.sh \| sh` | 사용자 확인 | 스크립트 실행 안 됨 | `pipe-download-to-shell`(high, 승인 요청) |

hook의 결정은 Claude Code가 따르는 것이라 "적용 미확인"으로 기록된다. 실제 Claude Code 확인은 노트북 실설치 때 한다.

## 한계

- **경로를 직접 쓰지 않는 경우**: 변수로 만든 경로(`F=/tmp/x; bash $F`)는 연결되지 않는다.
- **다른 방법으로 받은 파일**: 다른 프로그램(python, 브라우저, 에이전트의 웹 툴)으로 받은 파일, 압축을 푼 뒤의 파일은 추적하지 않는다.
- **에이전트가 직접 쓴 파일**: 에이전트가 Write로 쓴 스크립트는 "내려받은 것"이 아니라서 대상이 아니다.
- **데몬 재시작**: 데몬이 다시 시작하기 전에 받은 파일은 기억하지 못한다. 데몬 없이 hook만 있으면 `pipe-download-to-shell`만 동작한다.
- **셸이 아닌 실행**: 셸이 아닌 툴로 실행하는 경우(MCP 툴, 플러그인의 전용 실행 툴)는 보지 않는다.
- **경로 목록**: 임시 경로와 다운로드 폴더 밖(예: 작업 폴더)에 받은 경우는 걸리지 않는다. 목록은 룰에서 넓힐 수 있다.
