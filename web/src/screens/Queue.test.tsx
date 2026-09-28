// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Queue, stillPicked } from "./Queue";
import { Product } from "./Product";
import { screen, serve, settle, mounted } from "../test/mount";

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
