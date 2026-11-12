// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuditLog, CHANGES_MOST, changeKind, outcomesSaid, periodSent } from "./AuditLog";
import { classesOf } from "../ui/outcomes";
import { PUBLISHED } from "../test/outcomes";
import { screen, serve, settle, mounted } from "../test/mount";
import { api } from "../api/client";
import { readingDependencies } from "../test/reach";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

describe("the change history on the audit log", () => {
  it("is neither asked for nor drawn for a reader who neither administers nor audits", async () => {
    const asked: string[] = [];
    serve((path) => {
      asked.push(path);
      if (path === "/v1/session/me") {
        return {
          data: {
            identity: "tia",
            name: "Tia",
            admin: false,
            kind: "person",
            reach: [readingDependencies("sonic")],
          },
        };
      }
      if (path === "/v1/administration/changes") return { status: 403 };
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<AuditLog />, "/audit-log"));
    await settle();
    expect(asked).not.toContain("/v1/administration/changes");
    expect(mount.host().textContent).not.toContain("Change history");
  });

  it("stays drawn for an auditor over a period with no changes, saying so", async () => {
    serve((path) => {
      if (path === "/v1/session/me") {
        return {
          data: {
            identity: "ana",
            name: "Ana",
            admin: false,
            audits: true,
            kind: "person",
            reach: [readingDependencies("sonic")],
          },
        };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<AuditLog />, "/audit-log"));
    await settle();
    expect(mount.host().textContent).toContain("Change history");
    expect(mount.host().textContent).toContain("No changes over this period");
  });

  it("never asks for more rows than the route answers", async () => {
    const asked: number[] = [];
    serve((path, init) => {
      if (path === "/v1/session/me") {
        return {
          data: {
            identity: "ana",
            name: "Ana",
            admin: true,
            kind: "person",
            reach: [readingDependencies("sonic")],
          },
        };
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
    mount.render(screen(<AuditLog />, "/audit-log"));
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

describe("the change history while it is read", () => {
  it("says nothing about an empty kind until the answer arrives", async () => {
    const pending = new Promise<never>(() => {});
    serve((path) => {
      if (path === "/v1/session/me") {
        return {
          data: {
            identity: "ana",
            name: "Ana",
            admin: true,
            kind: "person",
            reach: [readingDependencies("sonic")],
          },
        };
      }
      return { data: { items: [], total: 0 } };
    });
    const answered = vi.mocked(api.GET).getMockImplementation() as unknown as (
      path: string,
      init: unknown,
    ) => unknown;
    vi.mocked(api.GET).mockImplementation(((path: string, init: unknown) =>
      path === "/v1/administration/changes" ? pending : answered(path, init)) as never);
    mount.render(screen(<AuditLog />, "/audit-log?change=role"));
    await settle();
    expect(mount.host().textContent).toContain("Change history");
    expect(mount.host().textContent).not.toContain("No changes of that kind");
  });
});

describe("the change history shown longer", () => {
  it("keeps the rows in hand while the longer page is read", async () => {
    const page = Array.from({ length: 50 }, (_, i) => ({
      at: "2026-10-01T00:00:00Z",
      kind: "role",
      about: `grant ${i}`,
      by: "ana",
    }));
    let asked = 0;
    serve((path) => {
      if (path === "/v1/session/me") {
        return {
          data: {
            identity: "ana",
            name: "Ana",
            admin: true,
            kind: "person",
            reach: [readingDependencies("sonic")],
          },
        };
      }
      return { data: { items: [], total: 0 } };
    });
    const answered = vi.mocked(api.GET).getMockImplementation() as unknown as (
      path: string,
      init: unknown,
    ) => unknown;
    vi.mocked(api.GET).mockImplementation(((path: string, init: unknown) => {
      if (path !== "/v1/administration/changes") return answered(path, init);
      asked++;
      return asked === 1
        ? Promise.resolve({
            data: { items: page, total: 120 },
            response: new Response(null, { status: 200 }),
          })
        : new Promise(() => {});
    }) as never);
    mount.render(screen(<AuditLog />, "/audit-log"));
    await settle();
    const more = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Show more",
    );
    await act(async () => more?.click());
    await settle();
    expect(asked).toBe(2);
    expect(mount.host().textContent).toContain("grant 49");
  });
});

describe("the change history's kind", () => {
  it("asks the list and the file for the kind the address names", async () => {
    const kinds: unknown[] = [];
    serve((path, init) => {
      if (path === "/v1/session/me") {
        return {
          data: {
            identity: "ana",
            name: "Ana",
            admin: true,
            kind: "person",
            reach: [readingDependencies("sonic")],
          },
        };
      }
      if (path === "/v1/administration/changes") {
        kinds.push((init as { params: { query: { kind?: string } } }).params.query.kind);
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<AuditLog />, "/audit-log?change=role"));
    await settle();
    expect(kinds).toContain("role");
    const file = Array.from(mount.host().querySelectorAll("a"))
      .map((each) => each.getAttribute("href") ?? "")
      .find((href) => href.startsWith("/v1/administration/changes.csv"));
    expect(file).toContain("kind=role");
    // The audit log's own file takes no kind of change, and refuses one.
    const record = Array.from(mount.host().querySelectorAll("a"))
      .map((each) => each.getAttribute("href") ?? "")
      .filter((href) => href.startsWith("/v1/audit."));
    expect(record.length).toBeGreaterThan(0);
    for (const href of record) expect(href).not.toContain("change=");
    expect(mount.host().textContent).toContain("No changes of that kind");
  });

  it("leaves out a kind the server does not take", () => {
    expect(changeKind(new URLSearchParams("change=everything"))).toBe("");
    expect(changeKind(new URLSearchParams("change=credential"))).toBe("credential");
  });
});

describe("the period on the audit log", () => {
  it("includes the day named as its end in everything it asks for", async () => {
    const ends: Record<string, unknown> = {};
    serve((path, init) => {
      if (path === "/v1/session/me") {
        return {
          data: {
            identity: "ana",
            name: "Ana",
            admin: true,
            kind: "person",
            reach: [readingDependencies("sonic")],
          },
        };
      }
      const query = (init as { params?: { query?: Record<string, unknown> } }).params?.query;
      if (query && "to" in query) ends[path] = query.to;
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<AuditLog />, "/audit-log?from=2026-01-01&to=2026-03-31"));
    await settle();
    expect(ends["/v1/audit/decisions"]).toBe("2026-04-01");
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

describe("the outcomes the audit log is filtered by", () => {
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

describe("the audit log's list", () => {
  it("draws one card per decision and links to where its decisions sit", async () => {
    serve((path) => {
      if (path === "/v1/session/me") {
        return {
          data: {
            identity: "ana",
            name: "Ana",
            admin: true,
            kind: "person",
            reach: [readingDependencies("sonic")],
          },
        };
      }
      if (path === "/v1/audit/decisions") {
        return {
          data: {
            total: 1,
            items: [
              {
                decision: 7,
                issue: "CVE-2026-1",
                issues: 1,
                product: "mine",
                products: 1,
                component: "openssl",
                version: "3.0.2",
                components: 1,
                rows: 40,
                occurrences: 40,
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
    mount.render(screen(<AuditLog />, "/audit-log?state=approved&state=lapsed"));
    await settle();
    const cards = mount.host().querySelectorAll(".audited");
    expect(cards.length).toBe(1);
    const card = cards.item(0);
    const text = card.textContent ?? "";
    expect(text).toContain("40 occurrences");
    expect(text).toContain("39 agreed · 1 lapsed");
    const hrefs = Array.from(card.querySelectorAll("a")).map(
      (each) => each.getAttribute("href") ?? "",
    );
    expect(hrefs).toContain("/decisions/7");
    const there = hrefs.find((href) => href.startsWith("/findings?"));
    expect(there).toBeDefined();
    const asked = new URLSearchParams(there?.split("?")[1]);
    expect(asked.get("decision")).toBe("7");
    expect(asked.getAll("decision_state")).toEqual(["approved", "lapsed"]);
  });
});

describe("the exception report", () => {
  it("reads as one that should be empty when asked for a code finding's dismissals", async () => {
    serve((path) => {
      if (path === "/v1/session/me") {
        return {
          data: {
            identity: "ana",
            name: "Ana",
            admin: true,
            kind: "person",
            reach: [readingDependencies("sonic")],
            outcomes: PUBLISHED,
          },
        };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(
      screen(<AuditLog />, "/audit-log?outcome=dismissed&outcome=not-security&alone=true"),
    );
    await settle();
    expect(mount.host().textContent).toContain("No dismissal stands on one person's say-so.");
  });
});
