// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from "vitest";

// Each test reads its own copy of the module, so a session one test ended is
// not ended in the next.
let ended: typeof import("./ended");

beforeEach(async () => {
  vi.resetModules();
  ended = await import("./ended");
});

describe("a session that ended under somebody", () => {
  it("starts as not ended, because that is what a working session looks like", () => {
    expect(ended.snapshot()).toBe(false);
  });

  it("tells whoever is watching, once", () => {
    // Once, because the offer to sign in again is either up or it is not.
    // Every refused write after the first would otherwise redraw it.
    const told = vi.fn();
    const stop = ended.subscribe(told);
    ended.sessionEnded();
    ended.sessionEnded();
    expect(ended.snapshot()).toBe(true);
    expect(told).toHaveBeenCalledTimes(1);
    stop();
  });

  it("stops telling somebody who stopped watching", () => {
    const told = vi.fn();
    ended.subscribe(told)();
    ended.sessionEnded();
    expect(told).not.toHaveBeenCalled();
  });
});
