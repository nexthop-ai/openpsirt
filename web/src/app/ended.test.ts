import { beforeEach, describe, expect, it, vi } from "vitest";
import { sessionEnded, sessionResumed, snapshot, subscribe } from "./ended";

beforeEach(() => {
  sessionResumed();
});

describe("a session that ended under somebody", () => {
  it("starts as not ended, because that is what a working session looks like", () => {
    expect(snapshot()).toBe(false);
  });

  it("tells whoever is watching, once", () => {
    // Once, because the offer to sign in again is either up or it is not.
    // Every refused write after the first would otherwise redraw it.
    const told = vi.fn();
    const stop = subscribe(told);
    sessionEnded();
    sessionEnded();
    expect(snapshot()).toBe(true);
    expect(told).toHaveBeenCalledTimes(1);
    stop();
  });

  it("stops telling somebody who stopped watching", () => {
    const told = vi.fn();
    subscribe(told)();
    sessionEnded();
    expect(told).not.toHaveBeenCalled();
  });

  it("can be cleared, so it is not a one-way door", () => {
    const told = vi.fn();
    const stop = subscribe(told);
    sessionEnded();
    sessionResumed();
    expect(snapshot()).toBe(false);
    expect(told).toHaveBeenCalledTimes(2);
    stop();
  });
});
