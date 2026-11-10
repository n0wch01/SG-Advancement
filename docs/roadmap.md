# 로드맵

각 마일스톤은 1~2개 작업 세션 분량이고, 끝나면 **데모 가능한 상태**가 되도록 쪼갰다.

| # | 마일스톤 | 완료 기준 | 상태 |
|---|---|---|---|
| M1 | 저장소 뼈대 + 공통 스키마 v1 | `AgentEvent`/`Finding` 모델, JSON Schema, 6개 센서 예시 이벤트, 테스트 | ✅ |
| M2 | 로컬 탐지 엔진 | SG `detect.py` 룰 타입 이전(regex/rate/loop/sequence/inventory diff), redaction, S1~S3 룰 통과 | ⏳ |
| M3 | Control Plane API | FastAPI + SQLite/Postgres: 장비 등록(토큰), 이벤트·finding 수집, 정책 조회 | |
| M4 | OpenClaw 어댑터 | SG ingest를 어댑터로 이전 → 중앙까지 엔드투엔드 | |
| M5 | Console v1 | 장비/사용자 인벤토리, 위협 타임라인, finding 상세 | |
| M6 | Claude Code hook 어댑터 | PreToolUse에서 로컬 정책으로 deny, 두 종류 에이전트 동시 관제 | |
| M7 | MCP 프록시 + 악성 MCP 시나리오 | tool poisoning, 미허가 MCP 서버 차단 | |
| M8 | LangGraph/Ollama 가상 직원 + Docker Compose | `docker compose up`으로 전체 데모 | |
| M9 | 정책 관리 | 정책 버전·그룹별 대상·응답 단계, 콘솔 편집기, 센서 pull 반영 | |
| M10 | Gemini CLI / Codex CLI 어댑터 | 각 CLI의 hook·설정 사양 조사 후 연동, 5종 에이전트 관제 | |
| M11 | 원격 대응 + 상관 분석 | 원격 abort/quarantine, 다중 사용자 캠페인 탐지 | |
| M12 | 멀티 호스트 | 다른 PC/VM 센서 등록(Tailscale 또는 LAN), TLS/mTLS | |
| M13 | 포트폴리오 마감 | 데모 영상, README, 설계 문서 정리 | |
