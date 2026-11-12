# SGA-Dashboard (M7 콘솔)

보안팀이 브라우저로 보는 관제 화면이다. 관제 서버의 `/v1/admin` API를 읽기만 하고, 정책·등록·승인을 바꾸는 일은 계속 CLI(`sga-server`)로 한다.

## 실행

```bash
cd dashboard && npm ci && npm run build      # dashboard/dist 생성 (install 스크립트는 .npmrc로 꺼 둠)
# .env에 SGA_DASHBOARD_TOKEN을 넣고 (값은 출력하지 않는다)
docker compose up -d control-plane           # dashboard/dist를 읽기 전용으로 마운트해 /dashboard로 제공
open http://localhost:${SGA_PORT}/dashboard/  # 대시보드 토큰으로 로그인
```

개발할 때는 `npm run dev`(포트 5173)를 쓴다. Vite가 `/v1`을 관제 서버(`SGA_API`, 기본 `http://127.0.0.1:18100`)로 넘겨서 운영과 같은 출처로 동작한다.

## 로그인과 권한

- **읽기 전용 대시보드 토큰**(`SGA_DASHBOARD_TOKEN`, 2026-11-12 결정): 브라우저에는 관리자 토큰이 들어가지 않는다.
  같은 `/v1/admin` 경로를 쓰지만 GET만 되고, POST·PUT·DELETE는 403이다(`auth.require_admin`).
- 토큰은 탭의 `sessionStorage`에만 둔다. 탭을 닫으면 사라지고, URL이나 로그에는 실리지 않는다(Bearer 헤더).
- 관리자 토큰으로도 로그인은 되지만, 화면 위에 대시보드 토큰을 쓰라는 안내가 뜬다.
- 화면은 관제 서버와 같은 출처에서 제공한다(CORS 없음). `/dashboard` 응답에는 CSP(`default-src 'self'`, 외부 스크립트·프레임 금지),
  `nosniff`, `no-referrer`를 붙인다.

## 화면 (v1)

| 화면 | 내용 | API |
|---|---|---|
| 개요 | 기간(24시간·7일·30일·전체)별 Finding 수, 긴급·높음, 장비(최근 15분 동기화 / 전체, 최신 정책), 이벤트 수, 심각도별 막대, 사람별(가장 높은 심각도 순), 많이 걸린 룰, 최근 Finding | `GET /v1/admin/summary?since=` |
| Finding 목록 | 심각도(이상·정확히), 룰, 사람으로 거르기, 50개씩 더 보기. 대응과 집행 여부 표시 | `GET /v1/admin/findings` (`severity` 추가) |
| Finding 상세 | 메시지·권장 조치, 근거(룰, 사람, 장비, 대화, 위임 사슬, 대응, 태그), 증거 이벤트(마스킹된 원본), 같은 대화의 흐름(Finding까지, 증거 강조), 같은 대화의 다른 Finding | `GET /v1/admin/findings/{id}` |

- 심각도 색은 상태 색(긴급 빨강, 높음 주황, 보통 노랑, 낮음·정보 회색)이고 **항상 글자 라벨과 함께** 보인다. 색만으로 구분하지 않는다.
- 대화 원문을 보내지 않은 이벤트(룰에 걸리지 않은 대화)는 `(원문 미전송 · N자)`로만 보인다. 대시보드가 원문을 따로 가져오는 길은 없다.
- 라이트·다크 모드를 따로 정의했다(시스템 설정을 따름).

## 구조

`dashboard/`: React 18 + Vite 5 + TypeScript (버전 고정, `package-lock.json`). 라우터 라이브러리 없이 해시 경로(`#/findings/<id>`)를 쓴다.

| 파일 | 역할 |
|---|---|
| `src/api.ts` | 토큰 보관, `/v1/admin` 호출, 오류 |
| `src/format.ts` | 심각도·대응 라벨, 시간, 이벤트 한 줄 요약, 해시 경로 (단위 테스트 `format.test.ts`) |
| `src/pages/` | 개요, Finding 목록, Finding 상세 |
| `src/styles.css` | 색·간격 토큰(라이트/다크), 레이아웃 |

서버 쪽은 `src/sg_advance/server/dashboard.py`(whoami, summary, finding 상세)와 테스트 `tests/test_dashboard_api.py`.
CI는 `dashboard` 작업에서 `npm ci`, `npm test`, `npm run build`를 돌린다.

## 실환경 확인 (2026-11-12)

- 관제 서버(compose)에서 `/dashboard/` 200, 대시보드 토큰은 `viewer`, 같은 토큰의 등록 토큰 발급(POST)은 403.
- 예시 이벤트를 넣은 테스트 관제 서버에서 로그인 → 개요 → 목록(높음 이상) → T18 상세(증거 2개, 대화 흐름에서 증거 강조, 같은 대화의 다른 Finding)까지 확인. CSP 위반 없음.

## 다음 (M7 남은 화면)

승인 감사 목록(이미 있는 `GET /v1/admin/approvals`), 장비·설치·에이전트 인벤토리, 사람·대화 기준 타임라인(위임 트리 포함).
