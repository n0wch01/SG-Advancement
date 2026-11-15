import { useCallback, useEffect, useRef, useState } from "react";

import { createPoller } from "./polling";

export interface AsyncState<T> {
  data: T | null;
  error: Error | null;
  loading: boolean;
  refreshing: boolean;
  updatedAt: string | null;
}

/** How often live pages reload (2026-11-15: a laptop's tool calls show up without pressing reload). */
export const REFRESH_MS = 3000;

/** Runs ``load`` whenever ``deps`` change; ignores results of superseded runs. With ``refreshMs`` it
 * also reloads on that interval while the tab is visible, keeping what is on screen until the new
 * data arrives (no loading flash). A failed reload keeps the last data and shows the error. */
export function useAsync<T>(load: () => Promise<T>, deps: unknown[], refreshMs?: number, paused = false) {
  const [state, setState] = useState<AsyncState<T>>({ data: null, error: null, loading: true, refreshing: false, updatedAt: null });
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  const taskRef = useRef<ReturnType<typeof createPoller<T>> | null>(null);
  useEffect(() => {
    const task = createPoller({
      load,
      intervalMs: refreshMs,
      canPoll: () => !pausedRef.current && document.visibilityState === "visible",
      onStart: (reason) => setState((current) => reason === "initial"
        ? { data: null, error: null, loading: true, refreshing: true, updatedAt: null }
        : { ...current, refreshing: true }),
      onSuccess: (data) => setState({ data, error: null, loading: false, refreshing: false, updatedAt: new Date().toISOString() }),
      onError: (error) => setState((current) => ({ ...current, error, loading: false, refreshing: false })),
      onSettled: () => setState((current) => current.refreshing ? { ...current, refreshing: false } : current),
    });
    taskRef.current = task;
    void task.run("initial");
    const resume = () => { if (refreshMs) void task.run("auto"); };
    document.addEventListener("visibilitychange", resume);
    window.addEventListener("online", resume);
    return () => {
      task.stop();
      taskRef.current = null;
      document.removeEventListener("visibilitychange", resume);
      window.removeEventListener("online", resume);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, refreshMs]);
  useEffect(() => {
    if (!paused && refreshMs) void taskRef.current?.run("auto");
  }, [paused, refreshMs]);
  const refresh = useCallback(() => taskRef.current?.run("manual"), []);
  return { ...state, refresh };
}
