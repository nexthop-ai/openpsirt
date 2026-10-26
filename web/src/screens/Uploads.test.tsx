// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Uploads } from "./Uploads";
import { mounted, screen, serve, settle } from "../test/mount";

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
      <Uploads />,
      "/products/sonic/streams/master/variants/x/uploads",
      "/products/:product/streams/:stream/variants/:variant/uploads",
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

const UPLOADS = "/v1/products/{product}/streams/{stream}/variants/{variant}/uploads";
const PATTERN = "/products/:product/streams/:stream/variants/:variant/uploads/:type?";

// The screen at an address, with the kinds of upload the server lists.
async function opened(at: string, kinds: unknown[]) {
  const get = serve((path) => {
    if (path === UPLOADS) return { data: { items: kinds } };
    return { data: { items: [], total: 0, quiet: 0, refused: [] } };
  });
  mount.render(
    screen(<Uploads />, `/products/sonic/streams/master/variants/x/uploads${at}`, PATTERN),
  );
  await settle();
  const tabs = Array.from(mount.host().querySelectorAll("nav .tab2"));
  const asked = (get.mock.calls as unknown as [path: string][]).map(([path]) => path);
  return { tabs, asked };
}

describe("the tabs", () => {
  it("are the kinds the server lists, so a kind the reader may not read has none", async () => {
    const { tabs } = await opened("", [
      { type: "sbom", total: 3 },
      { type: "vex", total: 1 },
      { type: "supplier-advisory", total: 0 },
    ]);
    expect(tabs.map((tab) => tab.textContent)).toEqual([
      "SBOMs3",
      "VEX documents1",
      "Supplier advisories0",
    ]);
  });

  it("mark a kind whose newest upload was turned away", async () => {
    const { tabs } = await opened("", [
      {
        type: "sbom",
        total: 3,
        latest: { received_at: "2026-10-01T00:00:00Z", status: "refused" },
      },
      {
        type: "sarif",
        total: 1,
        latest: { received_at: "2026-10-01T00:00:00Z", status: "completed" },
      },
    ]);
    expect(tabs.map((tab) => tab.classList.contains("urgent"))).toEqual([true, false]);
  });

  it("open on the kind the address names, and read that kind's own list", async () => {
    const { tabs, asked } = await opened("/vex", [
      { type: "sbom", total: 0 },
      { type: "vex", total: 0 },
    ]);
    expect(tabs.find((tab) => tab.getAttribute("aria-selected") === "true")?.textContent).toBe(
      "VEX documents0",
    );
    expect(asked).toContain("/v1/products/{product}/vex-statements");
    expect(asked).not.toContain(SCANS);
  });

  it("each open on the first page of their own list", async () => {
    const doc = {
      received_at: "2026-10-01T00:00:00Z",
      status: "completed",
      publisher: "debian",
      document: "debian.json",
      recorded: 1,
      set_aside: 0,
      current: true,
    };
    const get = serve((path) => {
      if (path === UPLOADS) {
        return {
          data: {
            items: [
              { type: "sbom", total: 0 },
              { type: "vex", total: 60 },
              { type: "supplier-advisory", total: 3 },
            ],
          },
        };
      }
      return { data: { items: [doc], total: 60 } };
    });
    mount.render(
      screen(<Uploads />, "/products/sonic/streams/master/variants/x/uploads/vex", PATTERN),
    );
    await settle();
    const next = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Next",
    );
    act(() => next?.click());
    await settle();
    const advisories = Array.from(mount.host().querySelectorAll<HTMLAnchorElement>("nav .tab2"))[2];
    act(() => advisories?.click());
    await settle();
    const calls = get.mock.calls as unknown as [
      path: string,
      init: { params?: { query?: { offset?: number } } },
    ][];
    const offsets = (path: string) =>
      calls.filter(([at]) => at === path).map(([, init]) => init?.params?.query?.offset);
    expect(offsets("/v1/products/{product}/vex-statements")).toEqual([0, 50]);
    expect(offsets("/v1/products/{product}/supplier-advisories")).toEqual([0]);
  });

  it("open on SBOMs where the address names a kind the reader may not read", async () => {
    const { asked } = await opened("/sarif", [{ type: "sbom", total: 0 }]);
    expect(asked).toContain(SCANS);
    expect(asked).not.toContain(
      "/v1/products/{product}/streams/{stream}/variants/{variant}/analyses",
    );
  });
});
