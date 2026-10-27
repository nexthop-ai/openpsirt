// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildsWords, DisclosureDeadlines, embargoKey } from "./DisclosureDeadlines";
import { remember } from "../app/scope";
import { screen, serve, settle, mounted } from "../test/mount";

const mount = mounted();

afterEach(() => {
  vi.restoreAllMocks();
  window.sessionStorage.clear();
});

const may = (product: string) => ({ product, may_hide: true });
const me = {
  identity: "ana",
  name: "Ana",
  admin: false,
  kind: "person",
  reach: [may("sonic"), may("openpsirt")],
};

// One issue embargoed in two products: two embargoes, one row each.
const row = (product: string) => ({
  vulnerability: "OPENPSIRT-2026-1",
  summary: "Accepts a document nobody authenticated.",
  product,
  components: ["openpsirt-image"],
  builds: [
    { branch_or_tag: "main", variant: "container" },
    { branch_or_tag: "v1.0", variant: "container" },
  ],
  severity: "high",
  disclose_at: "2027-01-01T00:00:00Z",
  passed: false,
  occurrences: 2,
});

describe("the disclosure deadlines screen", () => {
  it("opens the form on the one embargo whose row was pressed", async () => {
    serve((path) => {
      if (path === "/v1/session/me") return { data: me };
      if (path === "/v1/disclosure-deadlines") {
        return { data: { items: [row("sonic"), row("openpsirt")], total: 2 } };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<DisclosureDeadlines />, "/disclosure-deadlines"));
    await settle();
    const moves = Array.from(mount.host().querySelectorAll("button")).filter(
      (each) => each.textContent === "Move or disclose",
    );
    expect(moves).toHaveLength(2);
    act(() => moves[0]?.click());
    await settle();
    expect(mount.host().querySelectorAll('input[type="date"]')).toHaveLength(1);
    expect(mount.host().textContent).toContain("main, v1.0 · container");
  });

  it("asks for the scope picked and says which it is", async () => {
    remember({ product: "sonic", branch_or_tag: "main" });
    const asked: Record<string, unknown>[] = [];
    serve((path, init) => {
      if (path === "/v1/session/me") return { data: me };
      if (path === "/v1/disclosure-deadlines") {
        asked.push((init as { params: { query: Record<string, unknown> } }).params.query);
        return { data: { items: [], total: 0 } };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<DisclosureDeadlines />, "/disclosure-deadlines"));
    await settle();
    expect(asked.at(-1)).toMatchObject({ product: "sonic", branch_or_tag: "main" });
    expect(mount.host().querySelector(".screen-head p")?.textContent).toContain("sonic · main");
    const shortcut = Array.from(mount.host().querySelectorAll("a")).find(
      (each) => each.textContent === "Record a reported flaw",
    );
    expect(shortcut?.getAttribute("href")).toBe("/record-a-flaw?product=sonic&source=outside");
  });
});

describe("an embargo's key", () => {
  it("is one issue in one product, and two products are two keys", () => {
    expect(embargoKey(row("sonic"))).not.toBe(embargoKey(row("openpsirt")));
    expect(embargoKey({ product: "a b", vulnerability: "c" })).not.toBe(
      embargoKey({ product: "a", vulnerability: "b c" }),
    );
  });
});

describe("the builds a row names", () => {
  it("names each build's variant where they differ", () => {
    expect(
      buildsWords([
        { branch_or_tag: "main", variant: "broadcom" },
        { branch_or_tag: "202411", variant: "mellanox" },
      ]),
    ).toBe("main · broadcom, 202411 · mellanox");
  });
});
