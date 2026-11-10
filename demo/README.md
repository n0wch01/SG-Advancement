# 시나리오 데모

공격 스토리를 단계별로 재생하면서, 로컬 탐지 엔진이 각 단계에서 어떤 판정을 내리는지 보여준다.
이 폴더는 독립적이다. core(`src/`, `tests/`, `scripts/`)는 이 폴더를 참조하지 않는다.

```bash
uv run python demo/demo_runner.py --list          # 시나리오 목록
uv run python demo/demo_runner.py S2              # 한 편 재생 (터미널에서는 단계 사이 0.8초 멈춤)
uv run python demo/demo_runner.py all --pause 0   # 전부, 멈춤 없이
```

마지막 줄에 `PASS`/`FAIL`이 나온다. 각 단계의 `expect`와 실제 판정이 모두 일치하면 PASS다.
`uv run pytest`를 돌리면 모든 시나리오가 PASS인지도 함께 확인한다([test_demo.py](test_demo.py)).

## 시나리오 추가

`scenarios/`에 YAML 파일 하나를 추가하면 끝이다. 코드는 고칠 필요가 없다.

```yaml
id: S4                                   # 유일해야 함
title: 한 줄 제목
summary: 무슨 일이 벌어지는지 두세 문장
actor: {user: erin, device: dev-erin, agent: gemini_cli, session: gm-01}   # 이벤트 기본값
steps:
  - say: 화면에 보일 설명
    at: 0                                # 시작 기준 초 (생략하면 순서대로)
    event: {kind: tool.call, tool: run_shell_command, arguments: {command: "cat ~/.aws/credentials"}}
    expect: {action: alert, rules: [sensitive-file-access]}   # 또는 expect: allow
```

- `event`에는 payload만 적는다. `sensor`, `session`, `user`, `device`를 같이 적으면 그 단계만 actor 값을 덮어쓴다(예: `sensor: egress_proxy`).
- `expect.action`은 그 단계의 최종 판정이다. 걸린 룰들의 response 중 가장 강한 것이다. `expect.rules`에 적은 룰은 반드시 걸려야 하고, 나머지 룰이 추가로 걸리는 것은 허용된다.
- 룰 하나의 오탐·미탐을 검증하는 용도라면 시나리오 말고 `tests/rule_cases/`에 케이스를 추가한다.

## 삭제

```bash
rm -rf demo/
```

이것만으로 끝난다. `pyproject.toml`의 `testpaths`에 남는 `"demo"` 항목은 경로가 없으면 무시되고, 린트(`ruff check .`)도 그대로 통과한다.
깔끔하게 정리하고 싶다면 `pyproject.toml`에서 `"demo"` 두 군데(testpaths, ruff src)만 지우면 된다.
