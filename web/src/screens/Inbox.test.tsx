// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Inbox } from "./Inbox";
import { location, mounted, screen, serve, settle } from "../test/mount";
import { press } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const REPORTS = [
  { reference: "sonic-R-1", reported_by: "eve@example.com", received: "2026-01-01" },
  { reference: "sonic-R-2", found_here: true, reported_by: "ana", disposition: "accepted" },
  { reference: "sonic-R-3", acknowledged: "2026-01-02T00:00:00Z", ruling: 7 },
  { reference: "sonic-R-4" },
];

async function drawn(may_hide: boolean, total = REPORTS.length, at = "/products/sonic/inbox") {
  serve((path) => {
    if (path === "/v1/session/me")
      return {
        data: {
          identity: "ana",
          name: "Ana",
          admin: false,
          kind: "person",
          reach: [{ product: "sonic", may_hide }],
          outcomes: [],
        },
      };
    if (path === "/v1/products/{product}/reports") return { data: { items: REPORTS, total } };
    if (path === "/v1/products/{product}/report-rulings") return { data: { items: [], total: 0 } };
    return undefined;
  });
  mount.render(screen(<Inbox />, at, "/products/:product/inbox"));
  await settle();
}

const box = (label: string) =>
  mount.host().querySelector<HTMLInputElement>(`input[aria-label="${label}"]`);
const text = () => mount.host().textContent ?? "";

describe("the inbox for somebody who works it", () => {
  it("selects on the page only the reports nothing answers", async () => {
    await drawn(true);
    await act(async () => box("Select every open vulnerability report on this page")?.click());
    expect(text()).toContain("2 selected");
    expect(box("Select sonic-R-1")?.checked).toBe(true);
    expect(box("Select sonic-R-4")?.checked).toBe(true);
    expect(box("Select sonic-R-2")).toBeNull();
    expect(box("Select sonic-R-3")).toBeNull();
  });

  it("lets go of the selection on another page, which holds other reports", async () => {
    await drawn(true, 120);
    await act(async () => box("Select sonic-R-1")?.click());
    expect(text()).toContain("1 selected");
    await press(mount.host(), "Next");
    await settle();
    expect(text()).not.toContain("selected");
  });

  it("offers the way to report a flaw", async () => {
    await drawn(true);
    expect(text()).toContain("Report a flaw");
  });

  it("says a report found here was never sent, and one sent in is not answered yet", async () => {
    await drawn(true);
    expect(text()).toContain("found here · ana");
    expect(text()).toContain("not yet");
  });
});

describe("the inbox for somebody who only reads it", () => {
  it("offers no selection and no report form", async () => {
    await drawn(false);
    expect(box("Select sonic-R-1")?.closest("td")?.hidden).toBe(true);
    expect(text()).not.toContain("Report a flaw");
  });
});

describe("the rulings waiting", () => {
  it("is a tab the address carries", async () => {
    await drawn(true);
    await press(mount.host(), "Waiting for approval 0");
    await settle();
    expect(location()).toBe("/products/sonic/inbox?waiting=1");
    expect(text()).toContain("Nothing waiting.");
  });
});
