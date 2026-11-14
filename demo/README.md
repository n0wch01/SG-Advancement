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

## 발표용 이야기 (콘솔)

[live_story.py](live_story.py)는 실제 Claude Code hook 입력 형식으로 한 사람의 이야기(테스트 DB 조회 → 유출 차단 → 인젝션 → 파괴적 명령 차단 → 악성 패키지·도메인 차단, 다른 사람의 3-1 승인)를 지금 시각으로 만든다. 센서로 재생하면 출처 추적 라벨까지 붙어 콘솔에 그대로 보인다. 순서와 예상 결과는 [docs/demo.md](../docs/demo.md).

```bash
uv run python demo/live_story.py > /tmp/story.jsonl
uv run sga-sensor --home /tmp/demo-laptop replay /tmp/story.jsonl
```

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

## OpenClaw 실시간 관제 (M5)

실제 OpenClaw나 LLM 없이, 가짜 게이트웨이([fake_openclaw_gateway.py](fake_openclaw_gateway.py))가 공격 시나리오를
실제 게이트웨이와 같은 모양의 프레임으로 재생한다. 센서 데몬이 이를 관제하다가 `sessions.abort`로 실행을 중단하는 것을 보여준다.

```bash
# 터미널 1: 중앙 서버
SGA_ADMIN_TOKEN=demo-admin uv run sga-server

# 터미널 2: 센서 등록
export SGA_ENROLL_TOKEN=$(curl -s -X POST http://127.0.0.1:8000/v1/admin/enrollment-tokens \
  -H "Authorization: Bearer demo-admin" -H 'content-type: application/json' -d '{}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
uv run sga-sensor --home /tmp/alice enroll --server http://127.0.0.1:8000 --device-id dev-alice

# 터미널 3: 가짜 게이트웨이 (S1 악성 플러그인 / S2 README 인젝션)
uv run python demo/fake_openclaw_gateway.py S2

# 터미널 2: 센서 데몬
OPENCLAW_GATEWAY_TOKEN=demo uv run sga-sensor --home /tmp/alice run --openclaw --user alice
```

터미널 3에 `✋ sessions.abort {'key': 'agent:main:main', 'runId': 'r2'}`가 찍히고,
`curl -s http://127.0.0.1:8000/v1/admin/findings -H "Authorization: Bearer demo-admin"`에는
`"enforced": true, "detail": "post-hoc: sessions.abort"`가 담긴 finding이 보인다.

셸 명령 사전 거절을 보려면 터미널 3에서 `EXEC` 시나리오를, 터미널 2에서 `run --openclaw --gate-exec`를 쓴다.
`🛑 exec.approval.resolve {'id': 'ap-2', 'decision': 'deny'}`가 찍히고, 평범한 명령(`ap-1`)은 건드리지 않는다.

## 삭제

```bash
rm -rf demo/
```

이것만으로 끝난다. `pyproject.toml`의 `testpaths`에 남는 `"demo"` 항목은 경로가 없으면 무시되고, 린트(`ruff check .`)도 그대로 통과한다.
깔끔하게 정리하고 싶다면 `pyproject.toml`에서 `"demo"` 두 군데(testpaths, ruff src)만 지우면 된다.
