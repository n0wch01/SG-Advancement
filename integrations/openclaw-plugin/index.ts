// SG-Advance — OpenClaw gateway plugin (milestone M5c).
//
// Judges every tool call *before* it runs by asking the local SG-Advance sensor daemon
// (`sga-sensor run`) over its unix socket, then blocks it, asks the user, or lets it pass.
// Decision logic and fallbacks live in policy.ts. Install: docs/sensor.md ("OpenClaw 플러그인").

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

import { cliAsk, decide, settingsFrom, socketAsk } from "./policy.ts";

const VERSION = "0.1.0";

export default definePluginEntry({
  id: "sg-advance",
  name: "SG-Advance",
  description: "Pre-execution policy check for every tool call via the local SG-Advance sensor.",
  register(api: any) {
    const s = settingsFrom(api.pluginConfig);
    const askDaemon = socketAsk(s.socketPath, s.daemonTimeoutMs);
    const askCli = cliAsk(s.sensorCli, s.sensorHome, s.cliTimeoutMs);
    const log = (level: "info" | "warn", msg: string) => api.logger?.[level]?.(msg);

    // Announce ourselves: the daemon only treats unjudged tool calls as a bypass while we're around.
    askDaemon({ op: "hello", plugin: "sg-advance", version: VERSION }).catch((e: Error) =>
      log("warn", `SG-Advance daemon not reachable at ${s.socketPath}: ${e.message}`),
    );
    const heartbeat = setInterval(() => {
      askDaemon({ op: "hello", plugin: "sg-advance", version: VERSION }).catch(() => {});
    }, 60_000);
    heartbeat.unref?.();

    api.on(
      "before_tool_call",
      async (event: any, ctx: any) => {
        const { result, source } = await decide(event, ctx, s, { askDaemon, askCli, log });
        if (result && "block" in result) log("info", `blocked ${event?.toolName} (${source})`);
        return result;
      },
      // Run before other policy plugins; a block from us is terminal.
      { priority: 1000, timeoutMs: s.daemonTimeoutMs + s.cliTimeoutMs + 2000 },
    );
  },
});
