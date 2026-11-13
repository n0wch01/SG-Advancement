// SG-Advance — OpenClaw gateway plugin (milestone M5c).
//
// Judges every tool call *before* it runs by asking the local SG-Advance sensor daemon
// (`sga-sensor run`) over its unix socket, then blocks it, asks the user, or lets it pass.
// Decision logic and fallbacks live in policy.ts. Install: docs/sensor.md ("OpenClaw 플러그인").

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

import { cliAsk, decide, hookTimeoutMs, settingsFrom, socketAsk, startHeartbeat } from "./policy.ts";

const VERSION = "0.1.0";

export default definePluginEntry({
  id: "sg-advance",
  name: "SG-Advance",
  description: "Pre-execution policy check for every tool call via the local SG-Advance sensor.",
  register(api: any) {
    const s = settingsFrom(api.pluginConfig);
    const askDaemon = socketAsk(s.socketPath, s.daemonTimeoutMs);
    const askCli = cliAsk(s.sensorCli, s.sensorHome, s.cliTimeoutMs);
    // Security approval (M11): the daemon answers once security decided or its wait ended.
    const askHold = socketAsk(s.socketPath, s.securityWaitMs + 15_000);
    const log = (level: "info" | "warn", msg: string) => api.logger?.[level]?.(msg);

    // Announce ourselves: the daemon only treats unjudged tool calls as a bypass while we're around.
    // On dispose (plugin disabled/removed/replaced) the heartbeat stops and the daemon hears "bye".
    startHeartbeat(askDaemon, api.lifecycle, { plugin: "sg-advance", version: VERSION }, (e: Error) =>
      log("warn", `SG-Advance daemon not reachable at ${s.socketPath}: ${e.message}`),
    );

    api.on(
      "before_tool_call",
      async (event: any, ctx: any) => {
        const { result, source } = await decide(event, ctx, s, { askDaemon, askCli, askHold, log });
        if (result && "block" in result) log("info", `blocked ${event?.toolName} (${source})`);
        return result;
      },
      // Run before other policy plugins; a block from us is terminal. Long enough for a security
      // approval wait (before_tool_call is fail-closed: a timeout blocks the call).
      { priority: 1000, timeoutMs: hookTimeoutMs(s) },
    );
  },
});
