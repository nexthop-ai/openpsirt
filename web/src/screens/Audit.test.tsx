// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Audit, CHANGES_MOST, changeKind, outcomesSaid, periodSent } from "./Audit";
import { classesOf } from "../ui/outcomes";
import { PUBLISHED } from "../test/outcomes";
import { screen, serve, settle, mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

describe("the change history on the record", () => {
  it("never asks for more rows than the route answers", async () => {
    const asked: number[] = [];
    serve((path, init) => {
      if (path === "/v1/session/me") {
        return { data: { identity: "ana", name: "Ana", admin: true, kind: "person", reach: [] } };
      }
      if (path === "/v1/administration/changes") {
        const limit = (init as { params: { query: { limit: number } } }).params.query.limit;
        asked.push(limit);
        if (limit > CHANGES_MOST) return { status: 422 };
        const items = Array.from({ length: limit }, (_, i) => ({
          id: i + 1,
          at: "2026-09-01T00:00:00Z",
          actor: "ana",
          kind: "setting",
          subject: `s${i}`,
        }));
        return { data: { items, total: 400 } };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Audit />, "/audit"));
    await settle();
    const more = () =>
      Array.from(mount.host().querySelectorAll("button")).find(
        (each) => each.textContent === "Show more",
      );
    for (let press = 0; press < 3 && more(); press++) {
      act(() => more()?.click());
      await settle();
    }
    expect(Math.max(...asked)).toBe(CHANGES_MOST);
    expect(more()).toBeUndefined();
    expect(mount.host().textContent).not.toContain("could not be read");
  });
});

describe("the change history's kind", () => {
  it("asks the list and the file for the kind the address names", async () => {
    const kinds: unknown[] = [];
    serve((path, init) => {
      if (path === "/v1/session/me") {
        return { data: { identity: "ana", name: "Ana", admin: true, kind: "person", reach: [] } };
      }
      if (path === "/v1/administration/changes") {
        kinds.push((init as { params: { query: { kind?: string } } }).params.query.kind);
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Audit />, "/audit?change=role"));
    await settle();
    expect(kinds).toContain("role");
    const file = Array.from(mount.host().querySelectorAll("a"))
      .map((each) => each.getAttribute("href") ?? "")
      .find((href) => href.startsWith("/v1/administration/changes.csv"));
    expect(file).toContain("kind=role");
    expect(mount.host().textContent).toContain("No changes of that kind");
  });

  it("leaves out a kind the server does not take", () => {
    expect(changeKind(new URLSearchParams("change=everything"))).toBe("");
    expect(changeKind(new URLSearchParams("change=credential"))).toBe("credential");
  });
});

describe("the period on the record", () => {
  it("includes the day named as its end in everything it asks for", async () => {
    const ends: Record<string, unknown> = {};
    serve((path, init) => {
      if (path === "/v1/session/me") {
        return { data: { identity: "ana", name: "Ana", admin: true, kind: "person", reach: [] } };
      }
      const query = (init as { params?: { query?: Record<string, unknown> } }).params?.query;
      if (query && "to" in query) ends[path] = query.to;
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Audit />, "/audit?from=2026-01-01&to=2026-03-31"));
    await settle();
    expect(ends["/v1/audit/claims"]).toBe("2026-04-01");
    expect(ends["/v1/administration/changes"]).toBe("2026-04-01");
    const files = Array.from(mount.host().querySelectorAll("a"))
      .map((each) => each.getAttribute("href") ?? "")
      .filter((href) => href.startsWith("/v1/"));
    expect(files.length).toBeGreaterThan(0);
    for (const href of files) expect(href).toContain("to=2026-04-01");
  });

  it("asks nothing of a day that is not on the calendar", () => {
    expect(periodSent(new URLSearchParams("from=2026-02-30&to=2026-02-30"))).toEqual({
      from: "",
      to: "",
    });
  });
});

describe("the outcomes the record is filtered by", () => {
  it("name a dismissal as one where the server says it is", () => {
    const said = new Map(outcomesSaid(classesOf(PUBLISHED).dismisses));
    expect(said.get("wont-fix")).toBe("dismissed — will not fix");
    expect(said.get("deferred")).toBe("deferred");
    const moved = PUBLISHED.map((each) =>
      each.outcome === "wont-fix" ? { ...each, dismisses: false } : each,
    );
    expect(new Map(outcomesSaid(classesOf(moved).dismisses)).get("wont-fix")).toBe("will not fix");
  });
});

describe("the record's list", () => {
  it("draws one card per claim and links to where its decisions sit", async () => {
    serve((path) => {
      if (path === "/v1/session/me") {
        return { data: { identity: "ana", name: "Ana", admin: true, kind: "person", reach: [] } };
      }
      if (path === "/v1/audit/claims") {
        return {
          data: {
            total: 1,
            items: [
              {
                claim: 7,
                issue: "CVE-2026-1",
                issues: 1,
                product: "mine",
                products: 1,
                component: "openssl",
                version: "3.0.2",
                components: 1,
                decisions: 40,
                places: 40,
                outcome: "upgrade-needed",
                reasoning: "Moving to 3.0.15.",
                state: "mixed",
                states: { proposed: 0, approved: 39, withdrawn: 0, lapsed: 1 },
                standing: 39,
                proposed_by: "ana",
                proposed_at: "2026-09-01T00:00:00Z",
                approvals: [],
                two_people: false,
              },
            ],
          },
        };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Audit />, "/audit?state=approved&state=lapsed"));
    await settle();
    const cards = mount.host().querySelectorAll(".judgment");
    expect(cards.length).toBe(1);
    const card = cards.item(0);
    const text = card.textContent ?? "";
    expect(text).toContain("40 places");
    expect(text).toContain("39 agreed · 1 lapsed");
    const hrefs = Array.from(card.querySelectorAll("a")).map(
      (each) => each.getAttribute("href") ?? "",
    );
    expect(hrefs).toContain("/claims/7");
    const there = hrefs.find((href) => href.startsWith("/findings?"));
    expect(there).toBeDefined();
    const asked = new URLSearchParams(there?.split("?")[1]);
    expect(asked.get("claim")).toBe("7");
    expect(asked.getAll("claim_state")).toEqual(["approved", "lapsed"]);
  });
});
