import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createPoller } from "./polling";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

describe("polling lifecycle", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); });

  function setup(load = vi.fn(async () => 1)) {
    let allowed = true;
    const onSuccess = vi.fn();
    const onError = vi.fn();
    const task = createPoller({ load, intervalMs: 3000, canPoll: () => allowed, onStart: vi.fn(), onSuccess, onError, onSettled: vi.fn() });
    return { task, load, onSuccess, onError, pause: () => { allowed = false; }, resume: () => { allowed = true; } };
  }

  it("skips automatic requests while paused or hidden, but allows an explicit refresh", async () => {
    const { task, load, pause, resume } = setup();
    await task.run("initial");
    pause();
    await vi.advanceTimersByTimeAsync(9000);
    expect(load).toHaveBeenCalledTimes(1);
    await task.run("manual");
    expect(load).toHaveBeenCalledTimes(2);
    resume();
    await task.run("auto");
    expect(load).toHaveBeenCalledTimes(3);
    task.stop();
  });

  it("does not overlap requests or publish an automatic result after pause", async () => {
    const wait = deferred<number>();
    const { task, load, onSuccess, pause } = setup(vi.fn(() => wait.promise));
    const request = task.run("auto");
    await task.run("manual");
    await vi.advanceTimersByTimeAsync(6000);
    expect(load).toHaveBeenCalledTimes(1);
    pause();
    wait.resolve(2);
    await request;
    expect(onSuccess).not.toHaveBeenCalled();
    expect(task.isBusy()).toBe(false);
    task.stop();
  });

  it("ignores late responses and clears the timer after the route changes", async () => {
    const wait = deferred<number>();
    const { task, load, onSuccess, onError } = setup(vi.fn(() => wait.promise));
    const request = task.run("initial");
    task.stop();
    wait.resolve(2);
    await request;
    await vi.advanceTimersByTimeAsync(9000);
    expect(load).toHaveBeenCalledTimes(1);
    expect(onSuccess).not.toHaveBeenCalled();
    expect(onError).not.toHaveBeenCalled();
  });

  it("reports a failure and can recover on the next request", async () => {
    const load = vi.fn(async () => 1).mockRejectedValueOnce(new Error("offline"));
    const { task, onError, onSuccess } = setup(load);
    await task.run("initial");
    expect(onError.mock.calls[0][0].message).toBe("offline");
    await task.run("manual");
    expect(onSuccess).toHaveBeenCalledWith(1, "manual");
    task.stop();
  });
});
