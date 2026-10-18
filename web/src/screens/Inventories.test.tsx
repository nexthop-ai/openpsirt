// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Inventories } from "./Inventories";
import { mounted, screen, serve } from "../test/mount";

// The page of receipts is asked for again only while an upload on it has not
// settled. A settled page asked for on a timer is load on the server for an
// answer that cannot have moved.
const mount = mounted();

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

const SCANS = "/v1/products/{product}/streams/{stream}/variants/{variant}/scans";

function receipt(state: string) {
  return { scan_id: 1, received_at: "2026-10-01T00:00:00Z", state };
}

// How many times the page was asked for over a minute on the screen.
async function askedOverAMinute(state: string): Promise<number> {
  const get = serve((path) => {
    if (path === SCANS) return { data: { items: [receipt(state)], total: 1 } };
    return { data: { items: [], total: 0, quiet: 0 } };
  });
  vi.useFakeTimers();
  mount.render(
    screen(
      <Inventories />,
      "/products/sonic/streams/master/variants/x/inventories",
      "/products/:product/streams/:stream/variants/:variant/inventories",
    ),
  );
  for (let second = 0; second < 60; second++) {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });
  }
  const calls = get.mock.calls as unknown as [path: string, init: unknown][];
  return calls.filter(([path]) => path === SCANS).length;
}

describe("the page of receipts", () => {
  it("is not asked for again once every upload on it has settled", async () => {
    expect(await askedOverAMinute("scanned")).toBe(1);
  });

  it("is asked for again while an upload on it is still being read", async () => {
    expect(await askedOverAMinute("reading")).toBeGreaterThan(2);
  });

  it("is asked for again while an upload on it is waiting to be scanned", async () => {
    expect(await askedOverAMinute("scanning")).toBeGreaterThan(2);
  });
});
