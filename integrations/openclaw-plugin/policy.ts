// Decision logic for the SG-Advance OpenClaw plugin. No OpenClaw imports here, so it can be
// unit-tested with plain `node --test` (Node strips the type annotations).
//
// Order of authority for one tool call (docs/sensor.md, "판정할 수 없을 때는 단계적으로"):
//   1. the local sensor daemon over its unix socket (full, stateful rules)        -> source "daemon"
//   2. `sga-sensor evaluate` (signed policy cache, stateless rules)          -> source "degraded"
//   3. risk tiers: read-only tools pass, everything else is blocked (fail closed) -> source "fallback"
// A daemon "hold" (M11 security_approval) waits for security's decision in the console: up to
// securityWaitMs, then denied. Any failure while waiting blocks: nobody approved the call.
// decide() never throws: an exception inside a before_tool_call handler would make OpenClaw block
// the call (its failure policy), which is stricter than the policy we chose.

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import net from "node:net";

export type Verdict = {
  ok: boolean;
  decision?: "allow" | "block" | "approve" | "hold";
  action?: string;
  rules?: string[];
  severity?: string;
  title?: string;
  reason?: string;
  error?: string;
  hold_id?: string; // decision "hold": ask await_hold with it
  wait_ms?: number;
  outcome?: string;
};

export type HookResult =
  | undefined
  | { block: true; blockReason: string }
  | {
      requireApproval: {
        title: string;
        description: string;
        severity: "info" | "warning" | "critical";
        timeoutMs: number;
        allowedDecisions?: Array<"allow-once" | "allow-always" | "deny">;
        onResolution?: (decision: string) => void;
      };
    };

export type PluginSettings = {
  socketPath: string;
  // Windows (M12): no unix socket there; the daemon listens on loopback TCP and writes
  // {host, port, token} to endpointFile in the user's profile. Every request carries the token.
  transport: "unix" | "tcp";
  endpointFile: string;
  sensorCli: string;
  sensorHome?: string;
  readOnlyTools: string[];
  daemonTimeoutMs: number;
  cliTimeoutMs: number;
  approvalTimeoutMs: number;
  securityWaitMs: number;
};

export type Deps = {
  askDaemon: (req: object) => Promise<Verdict>;
  askCli: (req: object) => Promise<Verdict>;
  askHold?: (req: object) => Promise<Verdict>; // the daemon socket with a timeout past securityWaitMs
  log?: (level: "info" | "warn", msg: string) => void;
};

// Conservative: tools that only read local state. web_fetch/web_search are NOT here — a URL or a
// query string can carry data out.
export const DEFAULT_READ_ONLY = ["read", "memory_search", "memory_get", "session_status"];

export function settingsFrom(
  config: Record<string, unknown> | undefined,
  env = process.env,
  platform: string = process.platform,
): PluginSettings {
  const c = config ?? {};
  const home = (c.sensorHome as string) || env.SGA_HOME || `${env.HOME ?? env.USERPROFILE ?? ""}/.sg-advance`;
  return {
    socketPath: (c.socketPath as string) || `${home}/sga.sock`,
    transport: c.transport === "tcp" || c.transport === "unix" ? c.transport : platform === "win32" ? "tcp" : "unix",
    endpointFile: (c.endpointFile as string) || `${home}/sga-api.json`,
    sensorCli: (c.sensorCli as string) || "sga-sensor",
    sensorHome: home,
    readOnlyTools: Array.isArray(c.readOnlyTools) ? (c.readOnlyTools as string[]) : DEFAULT_READ_ONLY,
    daemonTimeoutMs: Number(c.daemonTimeoutMs ?? 3000),
    cliTimeoutMs: Number(c.cliTimeoutMs ?? 8000),
    approvalTimeoutMs: Number(c.approvalTimeoutMs ?? 120_000),
    securityWaitMs: Number(c.securityWaitMs ?? 300_000), // decision 2026-11-12: 5 minutes
  };
}

/** How long OpenClaw may wait on our hook. before_tool_call is fail-closed, so running past this
 * blocks the call too; the daemon normally answers well before (its own wait ends first). */
export function hookTimeoutMs(s: PluginSettings): number {
  return Math.max(s.daemonTimeoutMs + s.cliTimeoutMs + 2000, s.securityWaitMs + 30_000);
}

/** Wait for security's decision on a held call. Aborting the run cancels the hold. */
export async function awaitSecurity(v: Verdict, ctx: any, deps: Deps): Promise<HookResult> {
  const holdId = v.hold_id;
  if (!holdId || !deps.askHold) {
    return { block: true, blockReason: "SG-Advance: 보안팀 승인을 기다릴 수 없어 차단했습니다" };
  }
  const signal: AbortSignal | undefined = ctx?.abortSignal;
  const cancel = () => {
    deps.askDaemon({ op: "cancel_hold", hold_id: holdId }).catch(() => {});
  };
  signal?.addEventListener?.("abort", cancel, { once: true });
  try {
    const r = await deps.askHold({ op: "await_hold", hold_id: holdId });
    if (r.ok && r.decision === "allow") return undefined;
    return { block: true, blockReason: r.reason || "SG-Advance: 보안팀 승인을 받지 못했습니다" };
  } catch (e) {
    const msg = String((e as Error)?.message ?? e);
    deps.log?.("warn", `security approval wait failed for ${v.rules?.join(", ")}: ${msg}`);
    return { block: true, blockReason: `SG-Advance: 보안팀 승인을 기다리는 중 센서와 연결이 끊겨 차단했습니다 (${msg})` };
  } finally {
    signal?.removeEventListener?.("abort", cancel);
  }
}

// before_tool_call event/ctx -> the daemon's request (sensor/plugin_api.py)
export function buildRequest(event: any, ctx: any): Record<string, unknown> {
  const requester = ctx?.requester ?? {};
  return {
    op: "tool_call",
    agentId: ctx?.agentId,
    sessionKey: ctx?.sessionKey,
    sessionId: ctx?.sessionId,
    runId: event?.runId ?? ctx?.runId,
    toolCallId: event?.toolCallId,
    toolName: event?.toolName,
    toolKind: event?.toolKind ?? ctx?.toolKind,
    params: event?.params ?? {},
    requester: {
      channel: requester.channel,
      accountId: requester.accountId,
      senderId: requester.senderId,
      senderIsOwner: requester.senderIsOwner,
    },
  };
}

export function toHookResult(
  v: Verdict,
  s: PluginSettings,
  source: string,
  onResolution?: (d: string) => void,
): HookResult {
  const why = v.reason || (v.rules ?? []).join(", ") || "policy";
  if (v.decision === "block") {
    return { block: true, blockReason: v.reason || `SG-Advance blocked this call (${why})` };
  }
  if (v.decision === "approve") {
    return {
      requireApproval: {
        title: v.title || "SG-Advance",
        description: `${why}${source === "daemon" ? "" : ` [${source}]`}`,
        severity: v.action === "require_approval" ? "warning" : "critical",
        timeoutMs: s.approvalTimeoutMs,
        allowedDecisions: ["allow-once", "deny"], // a policy hit must not become a permanent allow rule
        onResolution,
      },
    };
  }
  return undefined;
}

export function fallbackResult(
  toolName: string,
  s: PluginSettings,
  reason: string,
  _onResolution?: (d: string) => void,
): HookResult {
  // Fail closed (CLAUDE.md, 2026-11-13): nothing could judge this call (no daemon, no cached policy),
  // so only read-only tools pass. A failure is never handed to the person's approval.
  if (s.readOnlyTools.includes(toolName)) return undefined;
  return {
    block: true,
    blockReason: `SG-Advance: the security sensor is unavailable (${reason}), so ${toolName} is blocked; read-only tools still work.`,
  };
}

export async function decide(
  event: any,
  ctx: any,
  s: PluginSettings,
  deps: Deps,
): Promise<{ result: HookResult; source: "daemon" | "degraded" | "fallback" }> {
  const req = buildRequest(event, ctx);
  const tool = String(event?.toolName ?? "unknown");
  // The person's answer to an approval prompt is the audit trail: record it on every path. The
  // message carries its own context (rules, severity, request time) so it stands alone when the
  // daemon restarted in between or is down (then the CLI records it from the policy cache).
  const resolver = (source: "daemon" | "degraded" | "fallback", v?: Verdict) => {
    const requestedAt = Date.now();
    return (decision: string) => {
      const msg = {
        ...req,
        op: "resolution",
        decision,
        source,
        rules: v?.rules ?? [],
        severity: v?.severity,
        requestedAt,
      };
      deps
        .askDaemon(msg)
        .then((r) => (r.ok ? r : deps.askCli(msg)))
        .catch(() => deps.askCli(msg))
        .catch((e: Error) => deps.log?.("warn", `could not record approval ${decision} for ${tool}: ${e?.message}`));
    };
  };
  let firstError = "";
  try {
    const v = await deps.askDaemon(req);
    if (v.ok && v.decision === "hold") {
      deps.log?.("info", `holding ${tool} for security approval (${v.hold_id})`);
      return { result: await awaitSecurity(v, ctx, deps), source: "daemon" };
    }
    if (v.ok) return { result: toHookResult(v, s, "daemon", resolver("daemon", v)), source: "daemon" };
    firstError = v.error || "daemon error";
  } catch (e) {
    firstError = String((e as Error)?.message ?? e);
  }
  try {
    const v = await deps.askCli(req);
    if (v.ok) {
      deps.log?.("warn", `SG-Advance daemon unreachable (${firstError}); judged from cached policy`);
      return { result: toHookResult(v, s, "degraded", resolver("degraded", v)), source: "degraded" };
    }
    firstError = `${firstError}; cli: ${v.error ?? "error"}`;
  } catch (e) {
    firstError = `${firstError}; cli: ${String((e as Error)?.message ?? e)}`;
  }
  deps.log?.("warn", `SG-Advance unavailable (${firstError}); risk-tier fallback for ${tool}`);
  return {
    result: fallbackResult(tool, s, "sensor unavailable", resolver("fallback")),
    source: "fallback",
  };
}

// ── transports ─────────────────────────────────────────────────────────────

type Lifecycle = { onDispose?: (cleanup: () => unknown) => unknown } | undefined;

/** Say hello now and every ``intervalMs``; stop and say goodbye when the gateway disposes us.
 * Disabling, removing or replacing the plugin disposes the instance in place (no gateway restart)
 * and OpenClaw leaves our timers running unless we stop them: a heartbeat that outlives its hooks
 * would vouch for a plugin that no longer judges anything. Returns the cleanup for tests. */
export function startHeartbeat(
  ask: (req: Record<string, unknown>) => Promise<unknown>,
  lifecycle: Lifecycle,
  hello: Record<string, unknown>,
  onFirstError: (e: Error) => void = () => {},
  intervalMs = 60_000,
): () => Promise<void> {
  ask({ op: "hello", ...hello }).catch(onFirstError);
  const timer = setInterval(() => {
    ask({ op: "hello", ...hello }).catch(() => {});
  }, intervalMs);
  timer.unref?.();
  const cleanup = async () => {
    clearInterval(timer);
    await ask({ op: "bye", plugin: hello.plugin, reason: "disposed" }).catch(() => {});
  };
  lifecycle?.onDispose?.(cleanup);
  return cleanup;
}

/** The daemon on whichever transport this platform uses. */
export function daemonAsk(s: PluginSettings, timeoutMs: number) {
  return s.transport === "tcp" ? endpointAsk(s.endpointFile, timeoutMs) : socketAsk(s.socketPath, timeoutMs);
}

/** Loopback TCP (Windows): read the endpoint each time (the port changes when the daemon restarts). */
export function endpointAsk(file: string, timeoutMs: number) {
  return (req: object): Promise<Verdict> => {
    let ep: { host?: string; port?: number; token?: string };
    try {
      ep = JSON.parse(readFileSync(file, "utf8"));
    } catch (e) {
      return Promise.reject(new Error(`sensor endpoint ${file} unreadable: ${(e as Error).message}`));
    }
    if (typeof ep.port !== "number" || typeof ep.token !== "string") {
      return Promise.reject(new Error(`sensor endpoint ${file} is incomplete`));
    }
    const connect = () => net.createConnection({ host: ep.host || "127.0.0.1", port: ep.port as number });
    return lineAsk(connect, timeoutMs)({ ...req, auth: ep.token });
  };
}

export function socketAsk(path: string, timeoutMs: number) {
  return lineAsk(() => net.createConnection(path), timeoutMs);
}

function lineAsk(connect: () => net.Socket, timeoutMs: number) {
  return (req: object): Promise<Verdict> =>
    new Promise((resolve, reject) => {
      const sock = connect();
      let buf = "";
      const timer = setTimeout(() => {
        sock.destroy();
        reject(new Error(`daemon timeout after ${timeoutMs}ms`));
      }, timeoutMs);
      sock.on("connect", () => sock.write(`${JSON.stringify(req)}\n`));
      sock.on("data", (d) => {
        buf += d.toString("utf8");
        const nl = buf.indexOf("\n");
        if (nl >= 0) {
          clearTimeout(timer);
          sock.end();
          try {
            resolve(JSON.parse(buf.slice(0, nl)));
          } catch (e) {
            reject(e);
          }
        }
      });
      sock.on("error", (e) => {
        clearTimeout(timer);
        reject(e);
      });
    });
}

export function cliAsk(cli: string, home: string | undefined, timeoutMs: number) {
  return (req: object): Promise<Verdict> =>
    new Promise((resolve, reject) => {
      const args = [...(home ? ["--home", home] : []), "evaluate"];
      const child = spawn(cli, args, { stdio: ["pipe", "pipe", "ignore"] });
      let out = "";
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        reject(new Error(`cli timeout after ${timeoutMs}ms`));
      }, timeoutMs);
      child.stdout.on("data", (d) => (out += d.toString("utf8")));
      child.on("error", (e) => {
        clearTimeout(timer);
        reject(e);
      });
      child.on("close", () => {
        clearTimeout(timer);
        try {
          resolve(JSON.parse(out.trim().split("\n").pop() || "{}"));
        } catch (e) {
          reject(e);
        }
      });
      child.stdin.end(JSON.stringify(req));
    });
}
