# agent-sentinel

**AI 에이전트를 위한 중앙 정책·위협 관제 플랫폼 (EDR/MDM for AI Agents)**

조직 구성원이 각자 다른 AI 에이전트(OpenClaw, Claude Code, Gemini CLI, Codex CLI, LangGraph 기반 사내 에이전트 등)를 쓰더라도
**정책은 중앙에서 한 번 정의해 배포**하고, **위협은 한 화면에서** 확인·대응할 수 있게 하는 것이 목표입니다.

> 이 프로젝트는 팀 프로젝트 [ajou-samsung-giants](https://github.com/n0wch01/ajou-samsung-giants)
> (OpenClaw 단일 게이트웨이 대상 보안 가시화 MVP)에서 출발해, 다중 에이전트·중앙 관제 구조로 단독 재설계한 것입니다.

## 아키텍처

```
┌──────────────────────── Control Plane ────────────────────────┐
│  Policy Server        Telemetry Collector      Threat Console │
└───────┬──────────────────────▲───────────────────────┬────────┘
        │ policy pull          │ AgentEvent / Finding   │ remote response
┌───────▼──────────────────────┴───────────────────────▼────────┐
│ Endpoint (container / VM / PC)                                 │
│  Sentinel sensor = policy cache + local detection + enforcement│
│   ├ OpenClaw gateway adapter     ├ Claude Code hooks adapter   │
│   ├ Gemini CLI hooks adapter     ├ Codex CLI adapter           │
│   ├ LangGraph callback adapter   └ MCP proxy / egress proxy    │
└────────────────────────────────────────────────────────────────┘
```

자세한 설계는 [docs/architecture.md](docs/architecture.md), 공통 이벤트 스키마는 [docs/schema.md](docs/schema.md),
진행 계획은 [docs/roadmap.md](docs/roadmap.md)를 참고하세요.

## 개발

```bash
uv sync                                   # Python 3.12 환경 구성
uv run pytest                             # 테스트
uvx ruff check src tests scripts          # 린트
uv run python scripts/export_schema.py    # schemas/*.json 재생성 (스키마 변경 시)
```

## 저장소 구조

| 경로 | 내용 |
|---|---|
| `src/agent_sentinel/schema/` | 와이어 스키마 v1 (`AgentEvent`, `Finding`) |
| `schemas/` | 위 모델에서 생성한 JSON Schema (콘솔·비 Python 센서용) |
| `examples/events/` | 센서별 예시 이벤트 (테스트 픽스처) |
| `docs/` | 아키텍처·스키마·로드맵 |

## 주의

랩/교육용 데모입니다. 공격 시나리오용 목업(악성 플러그인, 악성 MCP 서버 등)은 격리된 Docker 네트워크에서만 실행하세요.
