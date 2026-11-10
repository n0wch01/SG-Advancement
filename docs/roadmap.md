# 로드맵

각 마일스톤은 1~2개 작업 세션 분량이고, 끝나면 **데모 가능한 상태**가 되도록 쪼갰다.

## 방향 (2026-11-10 확정)

- **목적**: 취업 면접용 포트폴리오. 팀 프로젝트(SG)를 다시 이해하고 한 단계 발전시키는 것이 출발점이다.
- **넓이보다 깊이**: 에이전트 종류를 늘리기보다 차단·정책·상관 분석을 깊게 한다. Gemini CLI·Codex CLI는 선택 과제로 내렸다.
- **SG 연결 유지**: OpenClaw 어댑터는 앞쪽에 두고 SG 코드를 최대한 재사용한다. 무엇을 왜 바꿨는지 문서로 남긴다.
- **센서는 단순하게, 콘솔은 공들여**: 센서는 UI 없는 CLI/데몬으로, 설치는 한 줄로 한다. 콘솔은 별도 웹 앱으로 만든다.
- **콘솔 스택**: React + Vite + TypeScript로 새 앱을 만들고, SG `security-viz`에서 쓸 만한 컴포넌트만 가져온다.
- **저장소**: SQLAlchemy로 추상화하고 SQLite로 시작한다. 동시 쓰기 병목이 실제로 생기면(M10·M12 예상) Postgres로 바꾸고, 그때는 접속 URL만 교체한다.
  마이그레이션 도구(Alembic)는 스키마가 자주 바뀌는 M9에서 도입하고, 그 전에는 테이블을 바로 생성한다.
- **가상 직원 LLM**: 기본은 로컬 Ollama(외부 API 불필요)로 하고, 직원마다 모델 백엔드를 설정으로 바꿀 수 있게 한다.
  개발 머신은 Mac 16GB이므로 Ollama는 호스트에서 직접 실행하고(Docker 안에서는 Metal GPU를 못 쓴다), 7~8B급 모델 하나를 직원들이 공유한다.
  동시에 움직이는 직원은 2~3명으로 잡고, 나머지는 일과 스케줄로 순서를 나눈다.

## 마일스톤

| # | 마일스톤 | 완료 기준 | 상태 |
|---|---|---|---|
| M1 | 저장소 뼈대 + 공통 스키마 v1 | `AgentEvent`/`Finding` 모델, JSON Schema, 6개 센서 예시 이벤트, 테스트 | ✅ |
| M2 | 로컬 탐지 엔진 | SG `detect.py` 룰 타입 이전(regex/rate/loop/sequence/inventory diff), redaction, S1~S3 룰 통과 | ✅ |
| M3 | Control Plane API | FastAPI + SQLAlchemy(SQLite): 장비 등록(토큰), 이벤트·finding 수집, 정책 v0(`rules/` 묶음 + 해시) 조회, compose 뼈대, 위협 모델 초안(`docs/threat-model.md`) | ✅ |
| M4 | Sensor core | 어댑터 인터페이스, 정책 pull·캐시(중앙이 끊기면 마지막 정책 사용), 정책 서명(Ed25519) 검증, 전송 큐·재시도, 등록 CLI. 예시 이벤트 replay로 센서 → 중앙 엔드투엔드 | ⏳ |
| M5 | OpenClaw 어댑터 | SG ingest/respond 이전, 사후 abort 집행, SG 대비 변경점 문서(`docs/from-sg.md`) | |
| M6 | Claude Code hook 어댑터 | PreToolUse에서 로컬 정책으로 deny(첫 사전 차단), 두 종류 에이전트 동시 관제 | |
| M7 | Console v1 | 장비/사용자 인벤토리, 위협 타임라인, finding 상세(룰 근거, 마스킹된 증거) | |
| M8 | MCP 프록시 + 악성 MCP 시나리오 | tool poisoning, 미허가 MCP 서버 차단 | |
| M9 | 정책 관리 | 정책 버전·그룹별 대상·응답 단계, 콘솔 편집기, 센서 pull 반영, 변경 감사 로그 | |
| M10 | 가상 직원 (LangGraph + Ollama) | 페르소나·일과 기반 LLM 직원 다수, 녹화/재생 모드, `docker compose up`으로 전체 데모 | |
| M11 | 원격 대응 + 상관 분석 | 원격 abort/quarantine, 다중 사용자 캠페인 탐지 | |
| M12 | 멀티 호스트 | 다른 PC/VM에 센서 한 줄 설치 + 등록 토큰(LAN 또는 Tailscale), TLS, 토큰 폐기 | |
| M13 | 평가 + 포트폴리오 마감 | 시나리오별 탐지율·오탐률 표, 위협 모델 완성, 데모 영상, README·설계 문서 정리 | |

## 선택 과제

| # | 과제 | 비고 |
|---|---|---|
| X1 | Gemini CLI / Codex CLI 어댑터 | 각 CLI의 hook·설정 사양 조사 후 연동. hook이 없으면 MCP 프록시(M8) 경로로만 관측 |
