// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Queue, stillPicked } from "./Queue";
import { Product } from "./Product";
import { accept, screen, serve, settle, mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const exports = () =>
  Array.from(mount.host().querySelectorAll<HTMLAnchorElement>("a")).filter((each) =>
    each.getAttribute("href")?.startsWith("/v1/review-queue."),
  );

describe("the review queue", () => {
  it("says the disclosure requests could not be read when their read fails", async () => {
    serve((path) =>
      path === "/v1/disclosure-movements" ? { status: 503 } : { data: { items: [], total: 0 } },
    );
    mount.render(screen(<Queue />, "/review-queue"));
    await settle();
    expect(mount.host().textContent).toContain(
      "Requests to move a disclosure date could not be read.",
    );
  });

  it("exports the queue with the filters it applies", async () => {
    serve(() => ({ data: { items: [], total: 0 } }));
    mount.render(screen(<Queue />, "/review-queue?severity=high"));
    await settle();
    expect(exports().map((each) => each.getAttribute("href"))).toEqual([
      "/v1/review-queue.csv?severity=high",
      "/v1/review-queue.json?severity=high",
    ]);
  });

  it("offers no export on the tab it has no file for", async () => {
    serve(() => ({ data: { items: [], total: 0 } }));
    mount.render(screen(<Queue />, "/review-queue?reaffirm=1&severity=high"));
    await settle();
    expect(exports()).toEqual([]);
  });
});

// A claim waiting in the queue, as the server lists one.
function waiting(id: number) {
  return {
    age_days: 3,
    builds: ["master · broadcom"],
    claim: { id, kind: "finding", proposed_at: "2026-09-01T00:00:00Z", proposed_by: "bo" },
    decision: { id: id * 10, outcome: "not-applicable", reasoning: "not built" },
    decisions: 1,
    issues: 1,
    places: 1,
    place: { place: `p${id}`, product: "sonic", vulnerability: `CVE-2026-${id}` },
    proposed_by: "bo",
    reasoning: "not built",
  };
}

describe("approving a selection", () => {
  // Verified by dropping the batch name from the request each claim is
  // approved with, by counting landed approvals as refused, and by clearing the
  // whole selection after the loop: each fails one assertion below.
  it("approves every claim under the batch name, and keeps only the refused one ticked", async () => {
    serve((path) => {
      if (path === "/v1/review-queue")
        return { data: { items: [waiting(1), waiting(2)], total: 2 } };
      if (path === "/v1/session/me") {
        return { data: { identity: "ana", name: "Ana", admin: false, kind: "person", reach: [] } };
      }
      return { data: { items: [], total: 0 } };
    });
    const sent = accept((_path, init) => {
      const id = (init as { params: { path: { id: number } } }).params.path.id;
      return id === 2 ? { status: 409 } : { data: {} };
    });
    mount.render(screen(<Queue />, "/review-queue"));
    await settle();
    const host = mount.host();

    const all = host.querySelector<HTMLInputElement>(
      'input[aria-label="Select every claim shown"]',
    );
    expect(all, "no select-all control").not.toBeNull();
    act(() => all?.click());
    const batch = host.querySelector<HTMLInputElement>('input[aria-label="Batch name"]');
    act(() => {
      if (!batch) return;
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(
        batch,
        "tuesday",
      );
      batch.dispatchEvent(new Event("input", { bubbles: true }));
    });
    const approve = Array.from(host.querySelectorAll<HTMLButtonElement>("button")).find(
      (each) => each.textContent === "Approve 2 selected",
    );
    expect(approve, "no approve control for the two ticked").toBeDefined();
    await act(async () => approve?.click());
    await settle();

    expect(
      sent().map(([path, init]) => [
        path,
        (init as { params: { path: { id: number } }; body: unknown }).params.path.id,
        (init as { body: unknown }).body,
      ]),
    ).toEqual([
      ["/v1/claims/{id}/approval", 1, { batch: "tuesday" }],
      ["/v1/claims/{id}/approval", 2, { batch: "tuesday" }],
    ]);
    expect(host.textContent).toContain("One claim could not be agreed to and is still selected.");
    expect(host.textContent).toContain("1 selected");
    expect(host.textContent).toContain("Agreed to under “tuesday”");
  });
});

// The list a request to the queue asked for.
const reasonOf = (init: unknown) =>
  (init as { params?: { query?: { reason?: string } } })?.params?.query?.reason;

describe("the review queue by reason", () => {
  it("counts each tab from its own list", async () => {
    const totals: Record<string, number> = {
      approval: 2,
      "expired-deferral": 3,
      "missed-fix-date": 4,
    };
    serve((path, init) =>
      path === "/v1/review-queue"
        ? { data: { items: [], total: totals[reasonOf(init) ?? ""] ?? 0 } }
        : { data: { items: [], total: 0 } },
    );
    mount.render(screen(<Queue />, "/review-queue"));
    await settle();
    const tabs = Array.from(mount.host().querySelectorAll("button.tab2")).map((each) =>
      each.textContent?.replace(/\s+/g, " ").trim(),
    );
    expect(tabs.slice(0, 3)).toEqual(["To approve 2", "Expired deferrals 3", "Missed fix dates 4"]);
  });

  it("names a missed promise and offers changing it or deciding again, never approving", async () => {
    const promise = {
      ...waiting(7),
      decision: {
        id: 70,
        outcome: "upgrade-needed",
        upgrade_to: "3.0.15",
        committed_to: "2026-09-01",
        reasoning: "moving",
      },
    };
    serve((path, init) =>
      path === "/v1/review-queue" && reasonOf(init) === "missed-fix-date"
        ? { data: { items: [promise], total: 1 } }
        : { data: { items: [], total: 0 } },
    );
    mount.render(screen(<Queue />, "/review-queue?reason=missed-fix-date"));
    await settle();
    const host = mount.host();
    expect(host.textContent).toContain("Upgrade to 3.0.15 by 2026-09-01");
    expect(host.textContent).toContain("Fix date missed");
    const buttons = Array.from(host.querySelectorAll("button")).map((each) => each.textContent);
    expect(buttons).toContain("Change the version or date");
    expect(buttons.some((text) => text?.startsWith("Approve"))).toBe(false);
    expect(Array.from(host.querySelectorAll("a")).map((each) => each.textContent)).toContain(
      "Decide again →",
    );
    expect(exports().map((each) => each.getAttribute("href"))).toEqual([
      "/v1/review-queue.csv?reason=missed-fix-date",
      "/v1/review-queue.json?reason=missed-fix-date",
    ]);
  });
});

describe("the selection an approval loop leaves", () => {
  it("keeps what was ticked while it ran, and what was refused", () => {
    const now = new Map([
      ["a", 1],
      ["b", 2],
      ["late", 3],
    ]);
    expect([...stillPicked(now, new Set(["a", "b"]), ["b"]).keys()]).toEqual(["b", "late"]);
  });

  it("does not put back a refused claim that was unticked while it ran", () => {
    const now = new Map([["a", 1]]);
    expect([...stillPicked(now, new Set(["a", "b"]), ["b"]).keys()]).toEqual([]);
  });
});

describe("a product's page", () => {
  it("opens the review queue for the product it counted", async () => {
    serve((path) => {
      if (path === "/v1/products/{product}/overview")
        return { data: { name: "sonic", waiting: 3 } };
      if (path === "/v1/session/me") {
        return { data: { identity: "ana", name: "Ana", admin: false, kind: "person", reach: [] } };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Product />, "/products/sonic", "/products/:product"));
    await settle();
    const waiting = Array.from(mount.host().querySelectorAll<HTMLAnchorElement>("a.kpi")).find(
      (each) => each.textContent?.includes("Waiting on a second person"),
    );
    expect(waiting?.getAttribute("href")).toBe("/review-queue?product=sonic");
  });
});
