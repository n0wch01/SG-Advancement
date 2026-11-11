// node --test policy.test.ts   (Node >= 22.18 strips the type annotations)
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { buildRequest, cliAsk, decide, settingsFrom, socketAsk, type Verdict } from "./policy.ts";

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
