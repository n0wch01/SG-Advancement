// Decision logic for the SG-Advance OpenClaw plugin. No OpenClaw imports here, so it can be
// unit-tested with plain `node --test` (Node strips the type annotations).
//
// Order of authority for one tool call (docs/sensor.md, "판정할 수 없을 때는 단계적으로"):
//   1. the local sensor daemon over its unix socket (full, stateful rules)        -> source "daemon"
//   2. `sga-sensor evaluate` (signed policy cache, stateless rules)          -> source "degraded"
//   3. risk tiers: read-only tools pass, everything else asks the user            -> source "fallback"
// decide() never throws: an exception inside a before_tool_call handler would make OpenClaw block
// the call (its failure policy), which is stricter than the policy we chose.

import { spawn } from "node:child_process";
import net from "node:net";

export type Verdict = {
  ok: boolean;
  decision?: "allow" | "block" | "approve";
  action?: string;
  rules?: string[];
  severity?: string;
  title?: string;
  reason?: string;
  error?: string;
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
  sensorCli: string;
  sensorHome?: string;
  readOnlyTools: string[];
  daemonTimeoutMs: number;
  cliTimeoutMs: number;
  approvalTimeoutMs: number;
};

export type Deps = {
  askDaemon: (req: object) => Promise<Verdict>;
  askCli: (req: object) => Promise<Verdict>;
  log?: (level: "info" | "warn", msg: string) => void;
};

// Conservative: tools that only read local state. web_fetch/web_search are NOT here — a URL or a
// query string can carry data out.
export const DEFAULT_READ_ONLY = ["read", "memory_search", "memory_get", "session_status"];

export function settingsFrom(config: Record<string, unknown> | undefined, env = process.env): PluginSettings {
  const c = config ?? {};
  const home = (c.sensorHome as string) || env.SGA_HOME || `${env.HOME ?? ""}/.sg-advance`;
  return {
    socketPath: (c.socketPath as string) || `${home}/sga.sock`,
    sensorCli: (c.sensorCli as string) || "sga-sensor",
    sensorHome: home,
    readOnlyTools: Array.isArray(c.readOnlyTools) ? (c.readOnlyTools as string[]) : DEFAULT_READ_ONLY,
    daemonTimeoutMs: Number(c.daemonTimeoutMs ?? 3000),
    cliTimeoutMs: Number(c.cliTimeoutMs ?? 8000),
    approvalTimeoutMs: Number(c.approvalTimeoutMs ?? 120_000),
  };
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
  onResolution?: (d: string) => void,
): HookResult {
  if (s.readOnlyTools.includes(toolName)) return undefined;
  return {
    requireApproval: {
      title: "SG-Advance unavailable",
      description: `Security sensor could not judge this ${toolName} call (${reason}). Approve only if you expected it.`,
      severity: "warning",
      timeoutMs: s.approvalTimeoutMs,
      allowedDecisions: ["allow-once", "deny"],
      onResolution,
    },
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

export function socketAsk(path: string, timeoutMs: number) {
  return (req: object): Promise<Verdict> =>
    new Promise((resolve, reject) => {
      const sock = net.createConnection(path);
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
