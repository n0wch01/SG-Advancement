import { useEffect, useState } from "react";

export interface AsyncState<T> {
  data: T | null;
  error: Error | null;
  loading: boolean;
}

/** How often live pages reload (2026-11-15: a laptop's tool calls show up without pressing reload). */
export const REFRESH_MS = 3000;

/** Runs ``load`` whenever ``deps`` change; ignores results of superseded runs. With ``refreshMs`` it
 * also reloads on that interval while the tab is visible, keeping what is on screen until the new
 * data arrives (no loading flash). A failed reload keeps the last data and shows the error. */
export function useAsync<T>(load: () => Promise<T>, deps: unknown[], refreshMs?: number): AsyncState<T> {
  const [state, setState] = useState<AsyncState<T>>({ data: null, error: null, loading: true });
  useEffect(() => {
    let live = true;
    let busy = false;
    const run = (quiet: boolean) => {
      if (busy) return;
      busy = true;
      if (!quiet) setState((s) => ({ ...s, loading: true, error: null }));
      load().then(
        (data) => live && setState({ data, error: null, loading: false }),
        (error: Error) => live && setState((s) => ({ data: quiet ? s.data : null, error, loading: false })),
      ).finally(() => {
        busy = false;
      });
    };
    run(false);
    const timer = refreshMs
      ? setInterval(() => {
          if (typeof document === "undefined" || document.visibilityState === "visible") run(true);
        }, refreshMs)
      : undefined;
    return () => {
      live = false;
      if (timer) clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, refreshMs]);
  return state;
}
