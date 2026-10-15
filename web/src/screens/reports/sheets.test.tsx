// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Backlog } from "./Backlog";
import { Compliance } from "./Compliance";
import { Register } from "./Register";
import { Support } from "./Support";
import { location, mounted, screen, serve, settle, type Answer } from "../../test/mount";
import { BANDS } from "../../ui/severities";

const mount = mounted();

beforeEach(() => window.sessionStorage.clear());
afterEach(() => vi.restoreAllMocks());

// The scope the tab remembers, which is what a report reads when its own
// address names none.
function scoped(at: Record<string, string>) {
  window.sessionStorage.setItem("openpsirt.scope", JSON.stringify(at));
}

type Asked = { params?: { query?: Record<string, unknown> } };

// What the screen asked of one route, in order.
function askedOf(spy: ReturnType<typeof serve>, route: string): Record<string, unknown>[] {
  return (spy.mock.calls as unknown as [string, Asked][])
    .filter(([path]) => path === route)
    .map(([, init]) => init.params?.query ?? {});
}

const text = () => mount.host().textContent ?? "";

function press(label: string) {
  const button = Array.from(mount.host().querySelectorAll("button")).find(
    (each) => each.textContent === label,
  );
  if (!button) throw new Error(`no button ${label}`);
  return act(async () => button.click());
}

function links(name: string): string[] {
  return Array.from(mount.host().querySelectorAll("a"))
    .filter((each) => each.textContent === name)
    .map((each) => each.getAttribute("href") ?? "");
}

const REGISTER = "/v1/products/{product}/streams/{stream}/variants/{variant}/register";

describe("the disposition register", () => {
  const row = {
    vulnerability: "CVE-2026-1",
    place: "p1",
    severity: "high",
    component: "zlib",
    version: "1.2",
    state: "agreed",
    outcome: "not-applicable",
    proposed_by: "ana",
    proposed_at: "2026-01-01T00:00:00Z",
    approved_by: "bo",
    approved_at: "2026-01-02T00:00:00Z",
    agreement_carried: true,
    closed: "2026-01-03T00:00:00Z",
    closed_because: "disclaimed",
    stated: { publisher: "acme", product: "box", justification: "component_not_present" },
    met: true,
  };

  async function drawn(answer: (query: Record<string, unknown>) => Answer) {
    scoped({ product: "sonic", stream: "master", variant: "arm" });
    const spy = serve((path, init) =>
      path === REGISTER ? answer((init as Asked).params?.query ?? {}) : undefined,
    );
    mount.render(screen(<Register />, "/reports/register"));
    await settle();
    return spy;
  }

  it("asks for nothing until a whole build is picked", async () => {
    scoped({ product: "sonic" });
    const spy = serve(() => undefined);
    mount.render(screen(<Register />, "/reports/register"));
    await settle();
    expect(askedOf(spy, REGISTER)).toHaveLength(0);
    expect(text()).toContain("Pick a product, a branch or tag, and a variant.");
  });

  it("goes back to the first page when the narrowing changes", async () => {
    const spy = await drawn(() => ({ data: { items: [row], total: 450 } }));
    await press("Next");
    await settle();
    expect(askedOf(spy, REGISTER).at(-1)?.offset).toBe(200);
    const open = Array.from(mount.host().querySelectorAll("label")).find((each) =>
      each.textContent?.includes("Still open"),
    );
    await act(async () => open?.querySelector("input")?.click());
    await settle();
    expect(askedOf(spy, REGISTER).at(-1)).toMatchObject({ offset: 0, standing: "open" });
    expect(location()).toContain("standing=open");
  });

  it("links a file narrowed the same way as the list on screen", async () => {
    await drawn(() => ({ data: { items: [row], total: 1 } }));
    await press("nobody has said");
    await settle();
    const [csv] = links("CSV");
    expect(csv).toContain("register.csv");
    expect(csv).toContain("state=undecided");
  });

  it("says who stated a closure and that an agreement was carried", async () => {
    await drawn(() => ({ data: { items: [row], total: 1 } }));
    expect(text()).toContain("acme says box is not affected (component not present)");
    expect(text()).toContain("carried");
    expect(text()).toContain("met");
  });

  it("says a page past the end holds nothing and keeps the way back", async () => {
    await drawn(() => ({ data: { items: [], total: 3 } }));
    expect(text()).toContain("Nothing on this page.");
    expect(text()).toContain("Previous");
  });
});

describe("the releases out of support", () => {
  it("asks for the warning window picked and links the file the same way", async () => {
    scoped({ product: "sonic" });
    const spy = serve((path) =>
      path === "/v1/releases/out-of-support"
        ? {
            data: {
              items: [
                {
                  product: "sonic",
                  stream: "202305",
                  kind: "branch",
                  ended_on: "2026-01-01",
                  ended_days: 1,
                  open: 4,
                  inherited: true,
                },
              ],
              ending: [
                {
                  product: "sonic",
                  stream: "202411",
                  kind: "tag",
                  ended_on: "2026-12-01",
                  ended_days: -30,
                  open: 2,
                },
              ],
              total: 1,
              open: 4,
              ending_open: 2,
            },
          }
        : undefined,
    );
    mount.render(screen(<Support />, "/reports/releases-out-of-support"));
    await settle();
    expect(askedOf(spy, "/v1/releases/out-of-support")[0]).toEqual({ product: "sonic" });
    await press("and the next 30 days");
    await settle();
    expect(askedOf(spy, "/v1/releases/out-of-support").at(-1)).toEqual({
      product: "sonic",
      within: 30,
    });
    expect(links("CSV")[0]).toContain("within=30");
    // The count past end of life opens the list with the two filters that
    // keep it from defaulting to branches in support.
    const past = Array.from(mount.host().querySelectorAll("a")).find(
      (each) => each.textContent === "4",
    );
    expect(past?.getAttribute("href")).toContain("support=past-eol");
    const ending = Array.from(mount.host().querySelectorAll("a")).find(
      (each) => each.textContent === "2",
    );
    expect(ending?.getAttribute("href")).toContain("on=tag");
    expect(ending?.getAttribute("href")).not.toContain("support=");
    expect(text()).toContain("30 days");
  });
});

describe("deadline compliance", () => {
  it("asks for nothing without a product", async () => {
    const spy = serve(() => undefined);
    mount.render(screen(<Compliance />, "/reports/compliance"));
    await settle();
    expect(askedOf(spy, "/v1/compliance")).toHaveLength(0);
    expect(text()).toContain("Pick a product.");
  });

  it("adds the bands into one rate and prints a dash where nothing closed", async () => {
    scoped({ product: "sonic" });
    serve((path) =>
      path === "/v1/compliance"
        ? {
            data: {
              items: [
                { severity: BANDS[0], closed: 3, met: 2, late: 1, deferred: 1, overdue: 2 },
                { severity: BANDS[1], closed: 1, met: 1, late: 0, deferred: 0, overdue: 0 },
                { severity: BANDS[3], closed: 0, met: 0, late: 0, deferred: 0, overdue: 0 },
              ],
            },
          }
        : undefined,
    );
    mount.render(screen(<Compliance />, "/reports/compliance"));
    await settle();
    expect(text()).toContain("75%");
    expect(text()).toContain("3 of 4 closed");
    expect(text()).toContain("—");
  });
});

describe("the backlog over time", () => {
  const point = (at: string, open: number) => ({
    at,
    open,
    opened: 2,
    resolved: 1,
    by_severity: { critical: open },
    opened_by_severity: { critical: 2 },
    resolved_by_severity: { low: 1 },
  });

  it("asks for the window picked and leaves the first step out of the flows", async () => {
    scoped({ product: "sonic" });
    const spy = serve((path) =>
      path === "/v1/trend"
        ? { data: { items: [point("2026-01-04", 5), point("2026-01-11", 6)] } }
        : undefined,
    );
    mount.render(screen(<Backlog />, "/reports/backlog"));
    await settle();
    expect(askedOf(spy, "/v1/trend")[0]).toEqual({ product: "sonic", weeks: 13 });
    expect(mount.host().querySelectorAll("tbody tr")).toHaveLength(1);
    expect(text()).toContain("2026-01-11");
    await press("a year");
    await settle();
    expect(askedOf(spy, "/v1/trend").at(-1)).toEqual({ product: "sonic", weeks: 52 });
    expect(links("CSV")[0]).toContain("weeks=52");
  });

  it("says one step is not a trend", async () => {
    serve((path) =>
      path === "/v1/trend" ? { data: { items: [point("2026-01-04", 5)] } } : undefined,
    );
    mount.render(screen(<Backlog />, "/reports/backlog"));
    await settle();
    expect(text()).toContain("One step is not a trend.");
  });
});
