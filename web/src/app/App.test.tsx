// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { SignIn } from "../screens/SignIn";
import { api } from "../api/client";
import { location, mounted, screen, serve, settle, type Answer } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const WHO = {
  identity: "ana",
  name: "Ana",
  admin: false,
  kind: "person" as const,
  reach: [],
  outcomes: [],
};

// The reads a forward lands on that answer one object rather than a list,
// each in the shape the server gives.
const ONE: Record<string, unknown> = {
  "/v1/decisions/{id}": {
    decision: { id: 12, proposed_by: "bo" },
    occurrence: { product: "sonic", vulnerability: "CVE-2026-1" },
    argument: { outcome: "not-applicable" },
    happened: "waiting",
    undisclosed: false,
    security_testing: false,
    issues: 1,
    occurrences: 1,
    age_days: 1,
  },
  "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/unmatched-components":
    { unmatched: 0, components: 0, total: 0, reasons: [], items: [] },
};

// Draws the application at an address, with the identity read answered as
// given and every other read answered empty.
async function drawn(
  who: () => Answer,
  at = "/nowhere/at/all",
  ways: Answer = { data: { items: [] } },
) {
  const asked = serve((path) => {
    if (path === "/v1/session/me") return who();
    if (path === "/v1/sign-in") return ways;
    if (path in ONE) return { data: ONE[path] };
    return { data: { items: [], total: 0 } };
  });
  mount.render(screen(<App />, at));
  await settle();
  return () =>
    (asked.mock.calls as unknown as [string][]).filter(([path]) => path === "/v1/session/me")
      .length;
}

const text = () => mount.host().textContent ?? "";

describe("the application before anybody is known", () => {
  it("says the identity could not be read rather than offering a sign-in", async () => {
    await drawn(() => ({ status: 503 }));
    expect(text()).toContain("The signed-in person could not be read.");
    expect(text()).toContain("Try again");
    expect(mount.host().querySelector(".topsearch")).toBeNull();
  });

  it("asks again when Try again is pressed, and draws the screen it gets", async () => {
    let answer: Answer = { status: 503 };
    const asks = await drawn(() => answer);
    expect(asks()).toBe(1);
    answer = { data: WHO };
    const again = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Try again",
    );
    await act(async () => again?.click());
    await settle();
    expect(asks()).toBe(2);
    expect(text()).not.toContain("The signed-in person could not be read.");
    expect(mount.host().querySelector(".topsearch")).not.toBeNull();
  });

  it("offers a way in to a browser nobody is signed in on", async () => {
    await drawn(() => ({ status: 401 }));
    expect(text()).toContain("Sign in to continue");
    expect(text()).not.toContain("The signed-in person could not be read.");
    expect(mount.host().querySelector(".topsearch")).toBeNull();
  });
});

describe("the application after a refused sign-in", () => {
  afterEach(() => window.history.replaceState({}, "", "/"));

  it("says this account has no access here, and offers the way in without forwarding", async () => {
    // One provider forwards straight to it anywhere else. Here that would
    // refuse the same account again, in a loop.
    window.history.replaceState({}, "", "/?no-access");
    await drawn(() => ({ status: 401 }), "/", {
      data: { items: [{ name: "oidc", path: "/v1/sign-in/oidc" }] },
    });
    expect(text()).toContain("No access here");
    expect(text()).toContain("Ask an administrator for access.");
    expect(text()).not.toContain("Sign in to continue");
    const way = mount.host().querySelector<HTMLAnchorElement>('a[href^="/v1/sign-in/oidc"]');
    expect(way?.getAttribute("href")).toBe("/v1/sign-in/oidc");
  });
});

describe("the application after a refused sign-in with no way in", () => {
  afterEach(() => window.history.replaceState({}, "", "/"));

  it("says no way in is configured, and not to ask for access", async () => {
    window.history.replaceState({}, "", "/?no-access");
    await drawn(() => ({ status: 401 }), "/");
    expect(text()).toContain("No way in is configured.");
    expect(text()).not.toContain("Ask an administrator for access.");
    expect(text()).not.toContain("Sign in to continue");
  });

  it("says the ways in could not be read, and not to ask for access", async () => {
    window.history.replaceState({}, "", "/?no-access");
    await drawn(() => ({ status: 401 }), "/", { status: 503 });
    expect(text()).toContain("The ways in could not be read.");
    expect(text()).not.toContain("Ask an administrator for access.");
    expect(text()).not.toContain("Sign in to continue");
  });
});

describe("the application for a browser the proxy named and this deployment refused", () => {
  it("says there is no access here, and offers no way in the proxy would override", async () => {
    await drawn(() => ({ status: 401 }), "/", {
      data: { items: [{ name: "oidc", path: "/v1/sign-in/oidc" }], named_by_proxy: true },
    });
    expect(text()).toContain("No access here");
    expect(text()).toContain("Ask an administrator for access.");
    expect(text()).not.toContain("Sign in to continue");
    expect(text()).not.toContain("Continue with");
  });

  it("says there is no access here when a session ends under it", async () => {
    serve((path) =>
      path === "/v1/sign-in"
        ? { data: { items: [{ name: "oidc", path: "/v1/sign-in/oidc" }], named_by_proxy: true } }
        : { data: { items: [] } },
    );
    mount.render(screen(<SignIn resuming />, "/"));
    await settle();
    expect(text()).toContain("No access here");
    // What the overlay is named by, so a screen reader hears what is drawn.
    expect(mount.host().querySelector("#sign-in-state")?.textContent).toBe("No access here");
    expect(text()).not.toContain("Your session ended");
    expect(text()).not.toContain("Anything you typed is kept.");
    expect(text()).not.toContain("Continue with");
  });

  it("says nothing of a session ending while the ways in load", async () => {
    vi.spyOn(api, "GET").mockImplementation(() => new Promise(() => {}));
    mount.render(screen(<SignIn resuming />, "/"));
    await settle();
    expect(text()).not.toContain("Your session ended");
    expect(text()).not.toContain("Anything you typed is kept.");
  });

  it("says there is no access here where no provider is configured", async () => {
    await drawn(() => ({ status: 401 }), "/", { data: { items: [], named_by_proxy: true } });
    expect(text()).toContain("No access here");
    expect(text()).not.toContain("No way in is configured.");
  });
});

describe("the application after a sign-in that failed on this side", () => {
  afterEach(() => window.history.replaceState({}, "", "/"));

  it("says to try again, and offers the way in without forwarding", async () => {
    window.history.replaceState({}, "", "/?sign-in-failed");
    await drawn(() => ({ status: 401 }), "/", {
      data: { items: [{ name: "oidc", path: "/v1/sign-in/oidc" }] },
    });
    expect(text()).toContain("Sign-in didn\u2019t finish");
    expect(text()).toContain("Try again shortly.");
    expect(text()).not.toContain("No access here");
    expect(text()).not.toContain("Sign in to continue");
    const way = mount.host().querySelector<HTMLAnchorElement>('a[href^="/v1/sign-in/oidc"]');
    expect(way?.getAttribute("href")).toBe("/v1/sign-in/oidc");
  });
});

describe("the application for somebody signed in", () => {
  it("keeps an address it does not answer in the bar and says so", async () => {
    await drawn(() => ({ data: WHO }));
    expect(mount.host().querySelector(".topsearch")).not.toBeNull();
    expect(text()).toContain("A link from outside the application can also point at a screen");
  });
});

// Each address a screen had before it was renamed, and where it lands. The
// destinations are written out rather than built with the route helpers, so a
// forward pointed at the wrong screen fails here.
describe("a former address drawn by the application", () => {
  const build = "/products/sonic/branches-and-tags/main/variants/broadcom";
  it.each([
    ["/people", "/access"],
    ["/people/ana", "/access/ana"],
    ["/work?tab=people", "/assignments?tab=people"],
    ["/exploited-here", "/incidents"],
    ["/obligations", "/incidents"],
    ["/audit", "/audit-log"],
    ["/record?product=sonic", "/audit-log?product=sonic"],
    ["/disclosing", "/disclosure-deadlines"],
    ["/report-a-flaw", "/record-a-flaw"],
    ["/reports", "/analytics"],
    ["/reports/deadline-compliance", "/analytics/deadline-compliance"],
    ["/products/sonic/inbox", "/products/sonic/vulnerability-reports"],
    ["/products/sonic/inbox/R-7", "/products/sonic/vulnerability-reports/R-7"],
    [`${build}/components`, `${build}/dependencies`],
    [`${build}/scans`, `${build}/uploads`],
    [`${build}/inventories`, `${build}/uploads`],
    [`${build}/scans/7/changes`, `${build}/uploads/7/changes`],
    [`${build}/inventories/7/changes`, `${build}/uploads/7/changes`],
    ["/claims/12", "/decisions/12"],
    [`${build}/components/libnl/decide`, `${build}/components/libnl/bulk-decision`],
    [`${build}/match-coverage`, `${build}/unmatched-components`],
    [`${build}/pending-upgrades`, `${build}/planned-upgrades`],
    ["/products/sonic/streams/main/variants/broadcom/findings", `${build}/findings`],
    [
      "/products/sonic/streams/main/variants/broadcom/components/libnl/decide",
      `${build}/components/libnl/bulk-decision`,
    ],
  ])("forwards %s to %s", async (from, to) => {
    vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
    await drawn(() => ({ data: WHO }), from);
    // Long enough for the screen landed on to load and read, so a screen that
    // forwards again on its own is seen doing so.
    for (let i = 0; i < 5; i++) await settle();
    expect(location()).toBe(to);
  });
});
