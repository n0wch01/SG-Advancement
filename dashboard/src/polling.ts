export type PollReason = "initial" | "auto" | "manual";

interface PollOptions<T> {
  load: (reason: PollReason) => Promise<T>;
  intervalMs?: number;
  canPoll: () => boolean;
  onStart: (reason: PollReason) => void;
  onSuccess: (data: T, reason: PollReason) => void;
  onError: (error: Error, reason: PollReason) => void;
  onSettled: () => void;
}

/** One request at a time; a stopped task can never publish a late response. */
export function createPoller<T>(options: PollOptions<T>) {
  let stopped = false;
  let busy = false;
  const run = async (reason: PollReason = "manual") => {
    if (stopped || busy || (reason === "auto" && !options.canPoll())) return;
    busy = true;
    options.onStart(reason);
    try {
      const data = await options.load(reason);
      if (!stopped && (reason !== "auto" || options.canPoll())) options.onSuccess(data, reason);
    } catch (cause) {
      if (!stopped && (reason !== "auto" || options.canPoll())) {
        options.onError(cause instanceof Error ? cause : new Error(String(cause)), reason);
      }
    } finally {
      busy = false;
      if (!stopped) options.onSettled();
    }
  };
  const timer = options.intervalMs ? setInterval(() => void run("auto"), options.intervalMs) : undefined;
  return {
    run,
    isBusy: () => busy,
    stop() {
      stopped = true;
      if (timer !== undefined) clearInterval(timer);
    },
  };
}
