# 원격 대응 (M11)

보안팀이 대시보드나 CLI에서 장비에 대응을 보내면, 센서가 몇 초 안에 받아 실행하고 결과를 보고한다.

## 결정 (2026-11-12, 추천안)

- **게이트웨이 플러그인으로 차단·격리**한다. 센서에는 OpenClaw 관리자 권한을 주지 않는다(결정 B 유지).
  실행 중단은 시도만 하고, 권한이 없어 거절되면 그대로 "실패"로 기록한다.

## 흐름

```
대시보드(관리자) / sga-server action ──POST /v1/admin/actions──▶ 관제 서버 remote_actions (pending)
센서 데몬 (5초마다) ──GET /v1/actions──▶ delivered ──실행──▶ POST /v1/actions/{id}/result ──▶ done | failed
```

푸시 채널은 없다. 센서가 전송 주기(5초)마다 가져간다. 장비는 자기 장비의 대응만 받고 보고할 수 있다.

| 대응 | 센서가 하는 일 | 효과 |
|---|---|---|
| `block_session` / `unblock_session` | 집합 `remote_blocked_sessions`에 넣기/빼기 | 룰 `remote-blocked-session`(block): 그 대화와 **위임된 하위 에이전트 대화**(parent/root)의 이후 툴 호출을 플러그인이 실행 전에 차단 |
| `block_user` / `unblock_user` | 집합 `remote_blocked_users` | 룰 `remote-blocked-user`(block): 그 사람에게 귀속되는 모든 대화의 툴 호출 차단 |
| `abort_session` | WS 어댑터가 `sessions.abort` | v4 게이트웨이는 실행을 시작한 클라이언트나 admin에게만 허락 → 팀 게이트웨이에서는 대개 "refused"로 실패 기록. 차단은 따로 걸어야 한다 |
| `disable_plugin` / `disable_skill` | `openclaw plugins disable` / `skills.entries.<key>.enabled=false` | 그 장비에서 격리 |

- 집합은 센서의 다른 집합과 함께 저장(`trusted.json`)되어 **재시작해도 유지**된다.
- 차단 룰은 정책에 들어 있어 정책 화면에 보이고, 다른 룰처럼 Finding을 남긴다(`response:remote` 태그).
- 대응 표(`remote_actions`)가 감사 기록이다: 누가(`by`), 왜(`reason`), 근거 Finding, 받은 시각, 결과.

## 사용법

```bash
sga-server action block-session team-gateway agent:main:dashboard:… --by secops --reason "인젝션 의심" [--finding <id>]
sga-server action block-user team-gateway mallory@corp.test --by secops --reason "계정 침해 의심"
sga-server action unblock-user team-gateway mallory@corp.test --by secops --reason "확인 끝"
sga-server action abort team-gateway agent:main:dashboard:… --by secops --reason "..."
sga-server action list [--device team-gateway]
```

대시보드: Finding 상세의 **원격 대응** 카드(관리자 로그인 시: 이 대화 차단 — 위임 사슬의 맨 위 대화, 이 사람 차단, 실행 중단 시도),
**대응** 화면(지금 차단 중인 대상과 해제, 대응 이력과 결과).

## 실환경 확인 (2026-11-12, 팀 게이트웨이)

- `block-user team-gateway alice@corp.test` → 센서가 3초 안에 실행(`done · person blocked`).
- alice가 "작업 폴더 파일 목록"을 요청 → 에이전트가 "조회 도구가 차단돼 확인하지 못했다"고 답함.
  관제 서버에 `remote-blocked-user` Finding(대응 block, 집행됨, 집행 주체 openclaw_plugin, "pre-exec").
- `unblock-user` → `done · person unblocked`.

## 한계

- 대응이 닿는 데 최대 5초(전송 주기)가 걸린다. 그 사이의 호출은 막지 못한다.
- 대상 장비는 Finding이 온 장비다. 팀 게이트웨이의 대화는 게이트웨이 장비로 보내야 효과가 있다(감사 프록시 장비로 보낸 차단은 막을 툴 호출이 없다).
- 실행 중인 턴 자체는 끊지 못한다(관리자 권한 없음). 차단은 다음 툴 호출부터 걸린다.
