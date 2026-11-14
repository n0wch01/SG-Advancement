"""Evaluation (1-week plan item 5): the same attacks and normal work through the three enforcement points'
real decision code, compared with what the design says should happen.

    uv run python scripts/evaluate.py                         # markdown to stdout
    uv run python scripts/evaluate.py --out docs/evaluation-results.md

Points: the Claude Code hook (judge_event, as the daemon runs it), the OpenClaw plugin (judge), and the
MCP gateway (a real gateway in front of fake company servers; a block counts only when the server did
not receive the call). Runs against an in-process control plane with the repository's rules, in a temp
directory. Needs the ``server`` extra. Self-contained: no demo files.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from fastapi.testclient import TestClient

from sg_advance.sensor import Sensor, SensorHome, enroll, hook
from sg_advance.sensor.adapters import AdapterContext
from sg_advance.sensor.adapters.mcp_gateway import McpGatewayAdapter, body_chunks, read_head
from sg_advance.sensor.client import HttpResponse
from sg_advance.sensor.plugin_api import CLAUDE_CODE_HOOK, judge, judge_event
from sg_advance.server import Settings, create_app
from sg_advance.shorthand import build_event

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "eval" / "corpus.yaml"
POINTS = ("claude_code", "openclaw", "mcp_gateway")
POINT_NAME = {
    "claude_code": "Claude Code hook",
    "openclaw": "OpenClaw 플러그인",
    "mcp_gateway": "MCP 게이트웨이",
}
TO_OPENCLAW = {
    "Bash": "exec",
    "WebFetch": "web_fetch",
    "Read": "read",
    "Write": "write",
    "Edit": "edit",
    "Task": "sessions_spawn",
    "Grep": "grep",
    "WebSearch": "web_search",
}
CP_URL = "http://evaluation"


# ── setup: in-process control plane and an enrolled sensor ───────────────────


class _Transport:
    def __init__(self, client: TestClient) -> None:
        self.client = client

    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> HttpResponse:
        r = self.client.request(method, url.removeprefix(CP_URL), headers=headers, content=body)
        return HttpResponse(r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.content)


@contextmanager
def environment(tmp: Path):
    settings = Settings(
        db_url=f"sqlite:///{tmp / 'cp.db'}",
        rules_dir=ROOT / "rules",
        admin_token="eval-admin",
        signing_key_path=tmp / "key.pem",
        auto_verify=False,
    )
    with TestClient(create_app(settings)) as cp:
        transport = _Transport(cp)
        token = cp.post(
            "/v1/admin/enrollment-tokens", json={}, headers={"Authorization": "Bearer eval-admin"}
        )
        home = SensorHome(tmp / "sensor")
        enroll(home, CP_URL, token.json()["token"], device_id="eval-pc", transport=transport)
        sensor = Sensor(home, transport=transport)
        sensor.start()
        sensor.delegation.home = tmp / "home"  # no user-level subagent definitions
        yield sensor


# ── results ──────────────────────────────────────────────────────────────────


@dataclass
class Outcome:
    decision: str
    rules: list[str] = field(default_factory=list)
    reached: bool | None = None  # MCP: did the company server receive the judged call
    ms: list[float] = field(default_factory=list)


def _mcp(tool: str) -> tuple[str, str] | None:
    if tool.startswith("mcp__") and tool.count("__") >= 2:
        _, server, name = tool.split("__", 2)
        return server, name
    return None


def applies(case: dict[str, Any], point: str) -> bool:
    if "expect" in case:
        return point in case["expect"]
    steps = case["steps"]
    has_mcp = any("tools_list" in s or _mcp(s["call"]) for s in steps)
    all_mcp = all("tools_list" in s or _mcp(s["call"]) for s in steps)
    return {
        "claude_code": not any("tools_list" in s for s in steps),
        "openclaw": not has_mcp,
        "mcp_gateway": all_mcp,
    }[point]


def _judged_index(steps: list[dict[str, Any]]) -> int:
    for i, s in enumerate(steps):
        if s.get("judge") or s.get("judge_result"):
            return i
    return len(steps) - 1


def _rules(resp: dict[str, Any]) -> list[str]:
    return list(resp.get("rules") or [])


# ── Claude Code hook ─────────────────────────────────────────────────────────


def run_claude(sensor: Sensor, case: dict[str, Any], tmp: Path) -> Outcome:
    ctx = AdapterContext(sensor, "eval-user", "eval-pc")
    cwd = tmp / f"project-{case['id']}"
    agents = cwd / ".claude" / "agents"
    agents.mkdir(parents=True, exist_ok=True)
    for name, body in (case.get("agents") or {}).items():
        (agents / f"{name}.md").write_text(f"---\nname: {name}\ndescription: eval\n{body}\n---\n")
    session = f"eval-{case['id']}-{uuid.uuid4().hex[:6]}"
    steps = case["steps"]
    target = _judged_index(steps)
    out = Outcome("allow")
    for i, step in enumerate(steps):
        call_id = f"tu-{uuid.uuid4().hex[:10]}"
        base = {
            "session_id": session,
            "tool_name": step["call"],
            "tool_use_id": call_id,
            "permission_mode": "default",
            "cwd": str(cwd),
        }
        pre = hook.hook_event(
            base | {"hook_event_name": "PreToolUse", "tool_input": step.get("args", {})},
            user_id="eval-user",
            hostname="eval-pc",
        )
        t0 = time.perf_counter()
        resp = judge_event(ctx, pre, CLAUDE_CODE_HOOK)  # type: ignore[arg-type]
        out.ms.append((time.perf_counter() - t0) * 1000)
        decision = resp.get("decision", "allow")
        if i == target and not step.get("judge_result"):
            return Outcome(decision, _rules(resp), None, out.ms)
        if decision != "allow":
            return Outcome(f"{decision} (앞 단계)", _rules(resp), None, out.ms)
        if "returns" in step:
            post = hook.hook_event(
                base
                | {
                    "hook_event_name": "PostToolUse",
                    "tool_input": step.get("args", {}),
                    "tool_response": step["returns"],
                },
                user_id="eval-user",
                hostname="eval-pc",
            )
            t0 = time.perf_counter()
            r = judge_event(ctx, post, CLAUDE_CODE_HOOK)  # type: ignore[arg-type]
            out.ms.append((time.perf_counter() - t0) * 1000)
            if i == target:
                return Outcome(r.get("decision", "allow"), _rules(r), None, out.ms)
    return out


# ── OpenClaw plugin ──────────────────────────────────────────────────────────


def _openclaw_steps(case: dict[str, Any]) -> list[dict[str, Any]]:
    if "steps_openclaw" in case:
        return [s | {"call": TO_OPENCLAW.get(s["call"], s["call"])} for s in case["steps_openclaw"]]
    out = []
    for s in case["steps"]:
        args = dict(s.get("args", {}))
        tool = TO_OPENCLAW.get(s["call"], s["call"])
        if s["call"] == "Task":
            args = {"task": args.get("prompt", ""), "label": args.get("description", "")}
        elif s["call"] in ("Read", "Write", "Edit") and "file_path" in args:
            args["path"] = args.pop("file_path")
        out.append(s | {"call": tool, "args": args})
    return out


def run_openclaw(sensor: Sensor, case: dict[str, Any]) -> Outcome:
    ctx = AdapterContext(sensor, "eval-user", "eval-pc")
    agents = case.get("openclaw_agents") or {}
    for aid, mode in agents.items():
        sensor.process(
            build_event(
                {"kind": "inventory.snapshot", "agent_id": aid, "permission_mode": mode},
                defaults={"agent": "openclaw", "sensor": "openclaw_gateway"},
                index=0,
            )
        )
    me = "research" if "research" in agents else "main"
    key = f"agent:{me}:eval-{case['id']}-{uuid.uuid4().hex[:6]}"
    steps = _openclaw_steps(case)
    target = _judged_index(steps)
    ms: list[float] = []
    for i, step in enumerate(steps):
        call_id = f"oc-{uuid.uuid4().hex[:10]}"
        req = {
            "op": "tool_call",
            "sessionKey": key,
            "toolCallId": call_id,
            "toolName": step["call"],
            "params": step.get("args", {}),
        }
        t0 = time.perf_counter()
        resp = judge(ctx, req)
        ms.append((time.perf_counter() - t0) * 1000)
        decision = resp.get("decision", "allow")
        if i == target and not step.get("judge_result"):
            return Outcome(decision, _rules(resp), None, ms)
        if decision != "allow":
            return Outcome(f"{decision} (앞 단계)", _rules(resp), None, ms)
        if "returns" in step:  # the result arrives over the gateway WebSocket (observation only)
            ev = {
                "ts": datetime.now(UTC).isoformat(),
                "endpoint": {"device_id": "pending"},
                "principal": {"user_id": "eval-user"},
                "agent": {"type": "openclaw", "session_id": key},
                "source": {"sensor": "openclaw_gateway"},
                "labels": {},
                "payload": {
                    "kind": "tool.result",
                    "call_id": call_id,
                    "tool": step["call"],
                    "output_preview": step["returns"],
                },
            }
            from sg_advance.schema import AgentEvent

            t0 = time.perf_counter()
            result = sensor.process(AgentEvent.model_validate(ev))
            ms.append((time.perf_counter() - t0) * 1000)
            if i == target:
                rules = result.verdict.rule_ids
                return Outcome("detect" if rules else "allow", rules, None, ms)
    return Outcome("allow", [], None, ms)


# ── MCP gateway ──────────────────────────────────────────────────────────────


class Upstream:
    """A fake company MCP server: answers each tool with the corpus text; remembers what reached it."""

    def __init__(self, replies: dict[str, str], tools: list[dict[str, Any]]) -> None:
        self.replies, self.tools, self.seen, self.port = replies, tools, [], 0

    async def start(self) -> asyncio.base_events.Server:
        server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = server.sockets[0].getsockname()[1]
        return server

    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, headers = await read_head(r)
        msg = json.loads(b"".join([c async for c in body_chunks(r, headers)]))
        self.seen.append(msg)
        mid, method = msg.get("id"), msg.get("method")
        if method == "tools/call":
            text = self.replies.get(msg["params"]["name"], "ok")
            result: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
        elif method == "tools/list":
            result = {"tools": self.tools}
        else:
            result = {}
        out = json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}).encode()
        w.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(out)}\r\n\r\n".encode()
            + out
        )
        await w.drain()
        w.close()


async def _rpc(port: int, path: str, msg: dict[str, Any]) -> Any:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    body = json.dumps(msg).encode()
    w.write(
        f"POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
        "Accept: application/json, text/event-stream\r\n"
        "User-Agent: claude-code/2.1\r\nMcp-Session-Id: s-1\r\n"
        f"Content-Length: {len(body)}\r\n\r\n".encode()
        + body
    )
    await w.drain()
    _, headers = await read_head(r)
    data = b"".join([c async for c in body_chunks(r, headers)])
    w.close()
    if "text/event-stream" in headers.get("content-type", ""):
        return json.loads([ln[5:] for ln in data.decode().splitlines() if ln.startswith("data:")][0])
    return json.loads(data)


async def run_mcp(sensor: Sensor, case: dict[str, Any]) -> Outcome:
    steps = case["steps"]
    servers: dict[str, Upstream] = {}
    for s in steps:
        if "tools_list" in s:
            servers.setdefault(s["tools_list"], Upstream({}, s["tools"]))
        else:
            server, name = _mcp(s["call"])  # type: ignore[misc]
            up = servers.setdefault(server, Upstream({}, []))
            up.replies[name] = s.get("returns", "ok")
            up.tools.append({"name": name, "description": f"{name} tool", "inputSchema": {}})
    started = [await u.start() for u in servers.values()]
    gw = McpGatewayAdapter("127.0.0.1:0", {n: f"http://127.0.0.1:{u.port}/mcp" for n, u in servers.items()})
    await gw.start(AdapterContext(sensor, "eval-user", "eval-pc"))  # no security hold to wait with
    target = _judged_index(steps)
    ms: list[float] = []
    try:
        for i, step in enumerate(steps):
            if "tools_list" in step:
                listed = await _rpc(
                    gw.port, f"/mcp/{step['tools_list']}", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
                )
                names = {t["name"] for t in listed["result"]["tools"]}
                hidden = [t["name"] for t in step["tools"] if t["name"] not in names]
                return Outcome("quarantine" if hidden else "allow", [], None, ms)
            server, name = _mcp(step["call"])  # type: ignore[misc]
            mid = 100 + i
            msg = {
                "jsonrpc": "2.0",
                "id": mid,
                "method": "tools/call",
                "params": {"name": name, "arguments": step.get("args", {})},
            }
            t0 = time.perf_counter()
            out = await _rpc(gw.port, f"/mcp/{server}", msg)
            ms.append((time.perf_counter() - t0) * 1000)
            reached = any(
                m.get("id") == mid and m.get("method") == "tools/call" for m in servers[server].seen
            )
            result = out.get("result") or {}
            text = "".join(c.get("text", "") for c in result.get("content", []) if isinstance(c, dict))
            if result.get("isError") and not reached:
                decision = "block"
            elif reached and text != step.get("returns", "ok"):
                decision = "withhold"
            else:
                decision = "allow"
            if i == target:
                return Outcome(decision, [], reached, ms)
            if decision != "allow":
                return Outcome(f"{decision} (앞 단계)", [], reached, ms)
    finally:
        await gw.close()
        for s in started:
            s.close()
    return Outcome("allow", [], None, ms)


# ── report ───────────────────────────────────────────────────────────────────


def run(corpus_path: Path = CORPUS) -> dict[str, Any]:
    corpus = yaml.safe_load(corpus_path.read_text(encoding="utf-8"))
    results: dict[str, Any] = {"attacks": [], "evasions": [], "benign": []}
    with tempfile.TemporaryDirectory(prefix="sga-eval-") as d:
        tmp = Path(d)
        old_home = os.environ.get("HOME")
        os.environ["HOME"] = str(tmp / "home")
        try:
            with environment(tmp) as sensor:
                for kind in ("attacks", "evasions", "benign"):
                    for case in corpus.get(kind) or []:
                        row = {"case": case, "outcomes": {}}
                        for point in POINTS:
                            if not applies(case, point):
                                continue
                            if point == "claude_code":
                                row["outcomes"][point] = run_claude(sensor, case, tmp)
                            elif point == "openclaw":
                                row["outcomes"][point] = run_openclaw(sensor, case)
                            else:
                                row["outcomes"][point] = asyncio.run(run_mcp(sensor, case))
                        results[kind].append(row)
        finally:
            if old_home is not None:
                os.environ["HOME"] = old_home
    return results


def mismatches(results: dict[str, Any]) -> list[str]:
    out = []
    for row in [*results["attacks"], *results["evasions"]]:
        for point, o in row["outcomes"].items():
            want = row["case"]["expect"][point]
            if o.decision != want:
                out.append(f"{row['case']['id']} {point}: {o.decision} (기대 {want})")
            if point == "mcp_gateway" and want == "block" and o.reached:
                out.append(f"{row['case']['id']} {point}: 차단했다고 했지만 서버가 요청을 받음")
    for row in results["benign"]:
        for point, o in row["outcomes"].items():
            if o.decision != "allow":
                out.append(f"{row['case']['id']} {point}: 정상 작업인데 {o.decision} {o.rules}")
    return out


def markdown(results: dict[str, Any]) -> str:
    mark = {True: "✓", False: "✗"}
    lines = [
        "# 평가 결과 (scripts/evaluate.py로 생성)",
        "",
        f"생성: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}, 묶음 `eval/corpus.yaml`, 룰 `rules/`.",
        "",
        "## 공격",
        "",
        "| # | 공격 | 위협 | " + " | ".join(POINT_NAME[p] for p in POINTS) + " |",
        "|---|---|---|" + "---|" * len(POINTS),
    ]
    hit = total = 0
    for row in results["attacks"]:
        c, cells = row["case"], []
        for p in POINTS:
            o = row["outcomes"].get(p)
            if o is None:
                cells.append("–")
                continue
            ok = o.decision == c["expect"][p] and not (
                p == "mcp_gateway" and o.reached and c["expect"][p] == "block"
            )
            total += 1
            hit += ok
            extra = " · 서버 미도달" if p == "mcp_gateway" and o.reached is False else ""
            cells.append(f"{mark[ok]} {o.decision}{extra}")
        lines.append(f"| {c['id']} | {c['title']} | {c['threat']} | " + " | ".join(cells) + " |")
    lines += ["", f"설계대로 처리: **{hit}/{total}** (지점별 판정 기준)", ""]
    lines += [
        "## 우회 시도 (문서에 적은 한계 확인)",
        "",
        "| # | 우회 | 한계 | " + " | ".join(POINT_NAME[p] for p in POINTS) + " |",
        "|---|---|---|" + "---|" * len(POINTS),
    ]
    for row in results["evasions"]:
        c, cells = row["case"], []
        for p in POINTS:
            o = row["outcomes"].get(p)
            cells.append("–" if o is None else f"{mark[o.decision == c['expect'][p]]} {o.decision}")
        lines.append(f"| {c['id']} | {c['title']} | {c['limit']} | " + " | ".join(cells) + " |")
    lines += [
        "",
        "✓는 문서가 예측한 대로(allow = 알려진 미탐이 실제로 통과)라는 뜻이다.",
        "",
        "## 지점별 탐지율",
        "",
        "공격과 우회 시도 전체에서, 막거나(block·withhold·quarantine) 사람 확인(approve)으로 멈춘 비율.",
        "",
        "| 지점 | 시도 | 막음 | 사람 확인 | 통과(탐지만 포함) | 멈춘 비율 |",
        "|---|---|---|---|---|---|",
    ]
    for p in POINTS:
        os_ = [r["outcomes"][p] for r in [*results["attacks"], *results["evasions"]] if p in r["outcomes"]]
        if not os_:
            continue
        blocked = sum(o.decision in ("block", "withhold", "quarantine") for o in os_)
        asked = sum(o.decision == "approve" for o in os_)
        passed = len(os_) - blocked - asked
        lines.append(
            f"| {POINT_NAME[p]} | {len(os_)} | {blocked} | {asked} | {passed} "
            f"| {(blocked + asked) / len(os_):.0%} |"
        )
    lines += [
        "",
        "## 정상 작업 (오탐)",
        "",
        "| 지점 | 정상 작업 | 통과 | 막거나 물음 | 오탐률 |",
        "|---|---|---|---|---|",
    ]
    for p in POINTS:
        rows = [(r["case"], r["outcomes"][p]) for r in results["benign"] if p in r["outcomes"]]
        bad = [(c, o) for c, o in rows if o.decision != "allow"]
        if rows:
            lines.append(
                f"| {POINT_NAME[p]} | {len(rows)} | {len(rows) - len(bad)} | {len(bad)} "
                f"| {len(bad) / len(rows):.0%} |"
            )
    fps = [
        (r["case"], p, o)
        for r in results["benign"]
        for p, o in r["outcomes"].items()
        if o.decision != "allow"
    ]
    if fps:
        lines += ["", "오탐 목록:", ""]
        lines += [
            f"- {c['id']} {c['title']} ({POINT_NAME[p]}): {o.decision}, 룰 {', '.join(o.rules) or '-'}"
            for c, p, o in fps
        ]
    lines += [
        "",
        "## 판정 지연 (센서 안 판정, 호출 1건)",
        "",
        "| 지점 | 건수 | 중앙값 | 95% |",
        "|---|---|---|---|",
    ]
    for p in POINTS:
        ms = [
            m
            for kind in ("attacks", "evasions", "benign")
            for r in results[kind]
            if p in r["outcomes"]
            for m in r["outcomes"][p].ms
        ]
        if len(ms) >= 2:
            p95 = statistics.quantiles(ms, n=20)[-1]
            lines.append(f"| {POINT_NAME[p]} | {len(ms)} | {statistics.median(ms):.1f} ms | {p95:.1f} ms |")
    lines += [
        "",
        "MCP 게이트웨이 지연은 가짜 사내 서버 왕복을 포함한다. "
        "hook 지연은 데몬 소켓 왕복을 뺀 판정 시간이다.",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, help="write the markdown report here")
    args = ap.parse_args()
    results = run()
    report = markdown(results)
    if args.out:
        args.out.write_text(report, encoding="utf-8")
    print(report)
    bad = mismatches(results)
    for m in bad:
        print("MISMATCH", m, file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
