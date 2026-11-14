// node --test policy.test.ts   (Node >= 22.18 strips the type annotations)
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { buildRequest, cliAsk, decide, endpointAsk, hookTimeoutMs, settingsFrom, socketAsk, startHeartbeat, type Verdict } from "./policy.ts";

const s = settingsFrom({ sensorHome: "/tmp/x" }, {});
const event = { toolName: "exec", toolCallId: "c1", runId: "r1", params: { command: "rm -rf ~/x" } };
const ctx = { agentId: "main", sessionKey: "agent:main:main", requester: { channel: "webchat", senderId: "u1" } };
const ok = (v: Partial<Verdict>) => async () => ({ ok: true, ...v }) as Verdict;
const down = async (): Promise<Verdict> => {
  throw new Error("ECONNREFUSED");
};

test("request carries what the daemon needs", () => {
  const r = buildRequest(event, ctx);
  assert.equal(r.op, "tool_call");
  assert.equal(r.toolCallId, "c1");
  assert.equal(r.sessionKey, "agent:main:main");
  assert.deepEqual((r.requester as any).senderId, "u1");
});

test("daemon block -> block", async () => {
  const { result, source } = await decide(event, ctx, s, {
    askDaemon: ok({ decision: "block", reason: "SG-Advance: 파괴적 셸 명령" }),
    askCli: down,
  });
  assert.equal(source, "daemon");
  assert.deepEqual(result, { block: true, blockReason: "SG-Advance: 파괴적 셸 명령" });
});

test("daemon approve -> requireApproval, no permanent allow", async () => {
  const { result } = await decide(event, ctx, s, {
    askDaemon: ok({ decision: "approve", action: "require_approval", reason: "파괴적 SQL 실행" }),
    askCli: down,
  });
  const ra = (result as any).requireApproval;
  assert.equal(ra.description, "파괴적 SQL 실행");
  assert.deepEqual(ra.allowedDecisions, ["allow-once", "deny"]);
  assert.equal(typeof ra.onResolution, "function");
});

test("daemon allow -> no decision", async () => {
  const { result } = await decide(event, ctx, s, { askDaemon: ok({ decision: "allow" }), askCli: down });
  assert.equal(result, undefined);
});

test("daemon down -> cached-policy CLI (degraded)", async () => {
  const { result, source } = await decide(event, ctx, s, {
    askDaemon: down,
    askCli: ok({ decision: "block", reason: "blocked from cache" }),
  });
  assert.equal(source, "degraded");
  assert.deepEqual(result, { block: true, blockReason: "blocked from cache" });
});

test("everything down -> read-only passes, others are blocked (fail closed)", async () => {
  const deps = { askDaemon: down, askCli: down };
  const read = await decide({ ...event, toolName: "read" }, ctx, s, deps);
  assert.equal(read.source, "fallback");
  assert.equal(read.result, undefined);
  const exec = await decide(event, ctx, s, deps);
  assert.equal((exec.result as any).block, true);
  assert.equal((exec.result as any).requireApproval, undefined); // never handed to the person's approval
});

test("daemon answering ok:false is treated as unavailable", async () => {
  const { source } = await decide(event, ctx, s, {
    askDaemon: ok({ ok: false, error: "boom" } as any),
    askCli: ok({ ok: false, error: "no valid cached policy" } as any),
  });
  assert.equal(source, "fallback");
});

test("real unix socket round trip", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sn-"));
  const path = join(dir, "s.sock");
  const server = net.createServer((c) =>
    c.on("data", (d) => {
      const req = JSON.parse(d.toString().trim());
      c.write(`${JSON.stringify({ ok: true, decision: "allow", echo: req.toolCallId })}\n`);
    }),
  );
  await new Promise<void>((r) => server.listen(path, () => r()));
  try {
    const v: any = await socketAsk(path, 1000)(buildRequest(event, ctx));
    assert.equal(v.echo, "c1");
  } finally {
    server.close();
  }
  await assert.rejects(socketAsk(join(dir, "missing.sock"), 500)({}));
});

test("real CLI round trip and missing CLI", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sn-"));
  const fake = join(dir, "fake-sensor");
  writeFileSync(fake, `#!/bin/sh\ncat >/dev/null\necho '{"ok": true, "decision": "block", "reason": "cli"}'\n`);
  chmodSync(fake, 0o755);
  const v = await cliAsk(fake, dir, 3000)({});
  assert.equal(v.reason, "cli");
  await assert.rejects(cliAsk(join(dir, "nope"), dir, 1000)({}));
});

test("heartbeat stops and says bye when the gateway disposes the plugin", async () => {
  const sent: string[] = [];
  let dispose: (() => unknown) | undefined;
  const ask = async (req: Record<string, unknown>) => {
    sent.push(req.op as string);
    return { ok: true };
  };
  startHeartbeat(ask, { onDispose: (c) => (dispose = c) }, { plugin: "sg-advance", version: "0" }, () => {}, 10);
  await new Promise((r) => setTimeout(r, 35));
  assert.ok(sent.filter((op) => op === "hello").length >= 3); // first hello + ticks
  assert.ok(dispose, "registered an onDispose cleanup");
  await dispose!();
  const afterBye = sent.length;
  assert.equal(sent.at(-1), "bye");
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(sent.length, afterBye); // no hello after dispose
});

test("heartbeat works on hosts without managed lifecycle", async () => {
  const cleanup = startHeartbeat(async () => ({ ok: true }), undefined, { plugin: "sg-advance" });
  await cleanup(); // feature-detected: nothing to register, still stoppable
});

// ── approval answers (audit trail) ──────────────────────────────────────────

const tick = () => new Promise((r) => setTimeout(r, 10));

function recorder(okDaemon: boolean) {
  const daemon: any[] = [];
  const cli: any[] = [];
  return {
    daemon,
    cli,
    deps: {
      askDaemon: async (req: any) => {
        if (req.op === "resolution") {
          daemon.push(req);
          if (!okDaemon) throw new Error("ECONNREFUSED");
          return { ok: true } as Verdict;
        }
        return { ok: true, decision: "approve", rules: ["destructive-sql"], severity: "high" } as Verdict;
      },
      askCli: async (req: any) => {
        cli.push(req);
        return { ok: true } as Verdict;
      },
    },
  };
}

test("approval answer goes to the daemon with its own context", async () => {
  const r = recorder(true);
  const { result } = await decide(event, ctx, s, r.deps);
  (result as any).requireApproval.onResolution("allow-once");
  await tick();
  assert.equal(r.daemon.length, 1);
  const m = r.daemon[0];
  assert.equal(m.op, "resolution");
  assert.equal(m.decision, "allow-once");
  assert.equal(m.source, "daemon");
  assert.equal(m.toolCallId, "c1");
  assert.deepEqual(m.rules, ["destructive-sql"]);
  assert.equal(m.severity, "high");
  assert.equal(typeof m.requestedAt, "number");
  assert.equal(r.cli.length, 0);
});

test("approval answer falls back to the CLI when the daemon is gone", async () => {
  const r = recorder(false);
  const { result } = await decide(event, ctx, s, r.deps);
  (result as any).requireApproval.onResolution("deny");
  await tick();
  assert.equal(r.cli.length, 1);
  assert.equal(r.cli[0].decision, "deny");
});

test("risk-tier fallback never asks the person (nothing to approve)", async () => {
  const cli: any[] = [];
  const { result, source } = await decide(event, ctx, s, {
    askDaemon: down,
    askCli: async (req: any) => {
      cli.push(req);
      throw new Error("no cache");
    },
  });
  assert.equal(source, "fallback");
  assert.equal((result as any).block, true);
  await tick();
  assert.ok(cli.every((r) => r.op !== "resolution"));
});

// ── security approval (M11) ─────────────────────────────────────────────────

const held = ok({ decision: "hold", hold_id: "h1", wait_ms: 300_000, action: "security_approval", rules: ["destructive-sql"] });

test("hold -> wait for security; approved runs, denied blocks with the reason", async () => {
  const asked: object[] = [];
  const approve = async (req: object) => (asked.push(req), { ok: true, decision: "allow" }) as Verdict;
  const r1 = await decide(event, ctx, s, { askDaemon: held, askCli: down, askHold: approve });
  assert.equal(r1.result, undefined);
  assert.deepEqual(asked, [{ op: "await_hold", hold_id: "h1" }]);

  const deny = ok({ decision: "block", reason: "SG-Advance: 보안팀이 거부했습니다 (lead: no)" });
  const r2 = await decide(event, ctx, s, { askDaemon: held, askCli: down, askHold: deny });
  assert.deepEqual(r2.result, { block: true, blockReason: "SG-Advance: 보안팀이 거부했습니다 (lead: no)" });
});

test("hold -> losing the daemon while waiting blocks (nobody approved)", async () => {
  const { result } = await decide(event, ctx, s, { askDaemon: held, askCli: down, askHold: down });
  assert.equal((result as any).block, true);
  assert.match((result as any).blockReason, /연결이 끊겨/);
  const none = await decide(event, ctx, s, { askDaemon: held, askCli: down });
  assert.equal((none.result as any).block, true);
});

test("hold -> aborting the run cancels the hold", async () => {
  const sent: any[] = [];
  const controller = new AbortController();
  let release: (v: Verdict) => void = () => {};
  const askDaemon = async (req: any) => {
    sent.push(req);
    return req.op === "tool_call" ? ({ ok: true, decision: "hold", hold_id: "h9" } as Verdict) : ({ ok: true } as Verdict);
  };
  const askHold = () => new Promise<Verdict>((r) => (release = r));
  const pending = decide(event, { ...ctx, abortSignal: controller.signal }, s, { askDaemon, askCli: down, askHold });
  await new Promise((r) => setTimeout(r, 10));
  controller.abort();
  await new Promise((r) => setTimeout(r, 10));
  assert.deepEqual(sent.at(-1), { op: "cancel_hold", hold_id: "h9" });
  release({ ok: true, decision: "block", reason: "SG-Advance: 보안팀 승인 대기 중 실행이 취소됐습니다" });
  assert.equal(((await pending).result as any).block, true);
});

test("the hook may wait past the security wait (fail-closed after that)", () => {
  assert.equal(s.securityWaitMs, 300_000);
  assert.equal(hookTimeoutMs(s), 330_000);
  assert.equal(hookTimeoutMs(settingsFrom({ securityWaitMs: 1000 }, {})), 31_000);
});

// ── Windows transport (M12) ─────────────────────────────────────────────────

test("Windows defaults to loopback TCP with the endpoint file in the sensor home", () => {
  const w = settingsFrom({}, { USERPROFILE: "C:/Users/gamer" }, "win32");
  assert.equal(w.transport, "tcp");
  assert.equal(w.endpointFile, "C:/Users/gamer/.sg-advance/sga-api.json");
  assert.equal(settingsFrom({}, { HOME: "/home/a" }, "linux").transport, "unix");
  assert.equal(settingsFrom({ transport: "tcp" }, {}, "darwin").transport, "tcp");
});

test("TCP endpoint round trip sends the token; a missing endpoint file fails cleanly", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ep-"));
  const seen: any[] = [];
  const server = net.createServer((c) =>
    c.on("data", (d) => {
      const req = JSON.parse(d.toString().trim());
      seen.push(req);
      c.write(`${JSON.stringify(req.auth === "tok" ? { ok: true, decision: "allow" } : { ok: false, error: "unauthorized" })}\n`);
    }),
  );
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as net.AddressInfo).port;
  const file = join(dir, "sga-api.json");
  writeFileSync(file, JSON.stringify({ host: "127.0.0.1", port, token: "tok" }));
  try {
    const v = await endpointAsk(file, 1000)(buildRequest(event, ctx));
    assert.equal(v.decision, "allow");
    assert.equal(seen[0].auth, "tok");
    assert.equal(seen[0].toolCallId, "c1");
  } finally {
    server.close();
  }
  await assert.rejects(endpointAsk(join(dir, "missing.json"), 500)({}), /unreadable/);
});
