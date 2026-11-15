import { useEffect, useLayoutEffect, useMemo, useSyncExternalStore } from "react";

import type { Api } from "./api";
import { FindingFeed, type FindingFeedCache } from "./findingFeed";
import { findingFilters } from "./format";
import { REFRESH_MS } from "./useAsync";

export function useFindingFeed(api: Api, query: Record<string, string>, cache: FindingFeedCache) {
  const key = JSON.stringify(findingFilters(query));
  const feed = useMemo(() => {
    const model = cache.get(key) ?? new FindingFeed((request) => api.findings(request), JSON.parse(key), () => document.visibilityState === "visible");
    cache.delete(key);
    cache.set(key, model);
    if (cache.size > 8) {
      const oldest = cache.keys().next().value;
      if (oldest !== undefined) {
        cache.get(oldest)?.stop();
        cache.delete(oldest);
      }
    }
    return model;
  }, [api, key, cache]);
  const state = useSyncExternalStore(feed.subscribe, feed.getSnapshot);

  useEffect(() => {
    feed.start(REFRESH_MS);
    const resume = () => { void feed.poll(); };
    document.addEventListener("visibilitychange", resume);
    window.addEventListener("online", resume);
    return () => {
      feed.stop();
      document.removeEventListener("visibilitychange", resume);
      window.removeEventListener("online", resume);
    };
  }, [feed]);

  useLayoutEffect(() => {
    window.scrollTo(0, feed.scrollY);
    const remember = () => { feed.scrollY = window.scrollY; };
    window.addEventListener("scroll", remember, { passive: true });
    return () => window.removeEventListener("scroll", remember);
  }, [feed]);

  return { feed, ...state };
}
