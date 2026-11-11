// node --test policy.test.ts   (Node >= 22.18 strips the type annotations)
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { buildRequest, cliAsk, decide, settingsFrom, socketAsk, startHeartbeat, type Verdict } from "./policy.ts";

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

test("everything down -> read-only passes, others ask the user", async () => {
  const deps = { askDaemon: down, askCli: down };
  const read = await decide({ ...event, toolName: "read" }, ctx, s, deps);
  assert.equal(read.source, "fallback");
  assert.equal(read.result, undefined);
  const exec = await decide(event, ctx, s, deps);
  assert.equal((exec.result as any).requireApproval.title, "SG-Advance unavailable");
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

test("risk-tier fallback approvals are recorded too", async () => {
  const cli: any[] = [];
  const { result, source } = await decide(event, ctx, s, {
    askDaemon: down,
    askCli: async (req: any) => {
      if (req.op === "resolution") {
        cli.push(req);
        return { ok: true } as Verdict;
      }
      throw new Error("no cache");
    },
  });
  assert.equal(source, "fallback");
  (result as any).requireApproval.onResolution("allow-once");
  await tick();
  assert.equal(cli.length, 1);
  assert.equal(cli[0].source, "fallback");
  assert.deepEqual(cli[0].rules, []);
});
