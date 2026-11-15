// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it } from "vitest";
import { buildsWords, DisclosureDeadlines, embargoKey } from "./DisclosureDeadlines";
import { remember } from "../app/scope";
import { accept, answer, screen, serve, settle, mounted } from "../test/mount";
import { change, only, press } from "../test/controls";

const mount = mounted();

afterEach(() => {
  window.sessionStorage.clear();
});

const may = (product: string) => ({ product, may_hide: true, reads_private: true });
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

  it("opens another row's form without the refusal the last row was given", async () => {
    serve((path) => {
      if (path === "/v1/session/me") return { data: me };
      if (path === "/v1/disclosure-deadlines") {
        return { data: { items: [row("sonic"), row("openpsirt")], total: 2 } };
      }
      return { data: { items: [], total: 0 } };
    });
    answer("POST", () => ({ status: 409 }));
    mount.render(screen(<DisclosureDeadlines />, "/disclosure-deadlines"));
    await settle();
    const moves = () =>
      Array.from(mount.host().querySelectorAll("button")).filter(
        (each) => each.textContent === "Move or disclose",
      );
    act(() => moves()[0]?.click());
    await settle();
    change(mount.host().querySelector<HTMLInputElement>('input[type="date"]'), "2027-02-01");
    change(
      mount.host().querySelector<HTMLTextAreaElement>("textarea"),
      "The vendor needs a month.",
    );
    await press(mount.host(), "Ask");
    await settle();
    expect(mount.host().textContent).toContain("That date was not moved.");
    act(() => moves()[1]?.click());
    await settle();
    expect(mount.host().querySelectorAll('input[type="date"]')).toHaveLength(1);
    expect(mount.host().textContent).not.toContain("That date was not moved.");
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

describe("moving or disclosing an embargo", () => {
  const ISSUE = "/v1/products/{product}/issues/{issue}";

  // The row leaves the list once an act in force lands.
  async function asked(act: string, inForce: boolean) {
    let landed = false;
    serve((path) => {
      if (path === "/v1/session/me") return { data: me };
      if (path === "/v1/disclosure-deadlines") {
        const items = landed && inForce ? [] : [row("openpsirt")];
        return { data: { items, total: items.length } };
      }
      return { data: { items: [], total: 0 } };
    });
    const sent = accept(() => {
      landed = true;
      return { data: { in_force: inForce } };
    });
    mount.render(screen(<DisclosureDeadlines />, "/disclosure-deadlines"));
    await settle();
    await press(mount.host(), "Move or disclose");
    const choice = Array.from(mount.host().querySelectorAll("label")).find(
      (each) => each.querySelector("span")?.textContent === "Act",
    );
    change(choice?.querySelector("select") ?? null, act);
    if (act !== "disclosure") {
      change(mount.host().querySelector<HTMLInputElement>('input[type="date"]'), "2027-02-01");
    }
    change(mount.host().querySelector("textarea"), "The vendor asked.");
    await press(mount.host(), "Ask");
    await settle();
    return sent;
  }

  it.each([
    [
      "extension",
      `${ISSUE}/disclosure/extension`,
      { until: "2027-02-01", reason: "The vendor asked." },
    ],
    [
      "shortening",
      `${ISSUE}/disclosure/shortening`,
      { until: "2027-02-01", reason: "The vendor asked." },
    ],
    ["disclosure", `${ISSUE}/disclosure`, { reason: "The vendor asked." }],
  ])("sends the %s to its own route with what it takes", async (act, route, body) => {
    const sent = await asked(act, true);
    const [path, init] = only(sent);
    expect(path).toBe(route);
    expect(init.params?.path).toEqual({ product: "openpsirt", issue: "OPENPSIRT-2026-1" });
    expect(init.body).toEqual(body);
  });

  it("says a movement past the threshold waits in the review queue", async () => {
    await asked("extension", false);
    expect(mount.host().textContent).toContain(
      "Recorded. Nothing changes until a second person agrees.",
    );
    const waiting = Array.from(mount.host().querySelectorAll("a")).find(
      (each) => each.textContent === "Waiting in the review queue →",
    );
    expect(waiting?.getAttribute("href")).toBe("/review-queue#embargoes");
  });

  it("says a disclosure in force is public once its row has left the list", async () => {
    await asked("disclosure", true);
    expect(mount.host().textContent).toContain("Nothing is approaching a disclosure date.");
    expect(mount.host().textContent).toContain(
      "Disclosed. The findings and everything on them are public.",
    );
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
