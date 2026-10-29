// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import type { Who } from "../app/session";
import { mounted, screen, serve, settle } from "../test/mount";
import { reaching, readingDependencies } from "../test/reach";
import { AuditLog } from "./AuditLog";
import { Component } from "./Component";
import { Dependencies } from "./Dependencies";
import { Findings } from "./Findings";
import { Home } from "./Home";
import { Product } from "./Product";

// Each screen counting dependency findings, drawn for a reader who does not
// read them where the screen is: none of its zeros may stand for "nothing
// open".

const mount = mounted();

afterEach(() => {
  vi.restoreAllMocks();
  window.sessionStorage.clear();
});

function who(reach: Who["reach"], more: Partial<Who> = {}): Who {
  return {
    identity: "ana",
    name: "Ana",
    admin: false,
    kind: "person",
    reach,
    outcomes: [],
    ...more,
  };
}

// A developer: security testing read in sonic, nothing else.
const DEVELOPER = who([reaching("sonic", { may_see: true, reads_security_testing: true })]);
// The same developer, reading dependency findings in another product.
const ELSEWHERE = who([
  readingDependencies("edge"),
  reaching("sonic", { may_see: true, reads_security_testing: true }),
]);
// A release manager reading disclosed findings in sonic alone.
const DISCLOSED = who([reaching("sonic", { may_see: true, reads_public: true })]);
// An auditor: the audit permission and no product read.
const AUDITOR = who([reaching("sonic")], { audits: true });

const text = () => mount.host().textContent ?? "";

// Every read answered as the server answers a reader holding none of what is
// asked: zeros and empty lists.
function serving(as: Who, more: Record<string, unknown> = {}) {
  return serve((path) => {
    if (path === "/v1/session/me") return { data: as };
    if (path in more) return { data: more[path] };
    return { data: { items: [], total: 0 } };
  });
}

const asked = (spy: ReturnType<typeof serving>) =>
  (spy.mock.calls as unknown as [string][]).map(([path]) => path);

// One build shipping libnl, with nothing open that the reader can see.
const COMPONENT = {
  items: [
    {
      branch_or_tag: "master",
      variant: "arm",
      version: "3.7",
      source: "libnl",
      ecosystem: "deb",
      issues: 0,
      packages: [{ name: "libnl", version: "3.7", issues: 0 }],
    },
  ],
};

async function component(as: Who) {
  serving(as, { "/v1/products/{product}/components/{component}": COMPONENT });
  mount.render(
    screen(
      <Component />,
      "/products/sonic/components/libnl",
      "/products/:product/components/:component",
    ),
  );
  await settle();
}

describe("the component screen", () => {
  it("shows a reader without dependency read no zero and nothing called clean", async () => {
    await component(DEVELOPER);
    expect(text()).not.toContain("nothing open");
    expect(text()).not.toContain("no dependency findings open");
    expect(text()).not.toContain("0 open");
    expect(text()).not.toContain("Open on it");
    expect(text()).not.toContain("You don't read");
  });

  it("says in one line that dependency findings are read in another product", async () => {
    await component(ELSEWHERE);
    expect(text()).toContain("You don't read dependency findings in sonic.");
    expect(text()).not.toContain("0 open");
  });

  it("names what its zero counts for a reader of dependency findings here", async () => {
    await component(who([readingDependencies("sonic")]));
    expect(text()).toContain("no dependency findings open");
    expect(text()).toContain("Open on it");
  });

  it("says a disclosed-only reader's counts are of disclosed findings", async () => {
    await component(DISCLOSED);
    expect(text()).toContain("Counting disclosed findings, the ones you read here.");
    expect(text()).toContain("no dependency findings open");
  });
});

describe("the product page", () => {
  const OVERVIEW = {
    "/v1/products/{product}/overview": {
      name: "sonic",
      open: 0,
      builds: [{ branch_or_tag: "master", variant: "arm", open: 0 }],
    },
  };

  it("draws no dependency figure for a reader holding them elsewhere, and says so", async () => {
    serving(ELSEWHERE, OVERVIEW);
    mount.render(screen(<Product />, "/products/sonic", "/products/:product"));
    await settle();
    expect(mount.host().querySelector(".kpis")).toBeNull();
    expect(text()).not.toContain("Overdue");
    expect(text()).toContain("You don't read dependency findings in sonic.");
    expect(text()).toContain("master");
  });

  it("says a disclosed-only reader's figures are of disclosed findings", async () => {
    serving(DISCLOSED, OVERVIEW);
    mount.render(screen(<Product />, "/products/sonic", "/products/:product"));
    await settle();
    expect(mount.host().querySelector(".kpis")).not.toBeNull();
    expect(text()).toContain("Counting disclosed findings, the ones you read here.");
  });
});

describe("the dependency tree", () => {
  const BUILD = "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}";
  const node = (component: string) => ({
    component,
    version: "1.0",
    findings: 0,
    beneath: 0,
    children: 0,
  });

  async function tree(as: Who) {
    serving(as, {
      [`${BUILD}/components`]: {
        components: 2,
        edges: 1,
        root: { ...node("sonic"), children: 1 },
        items: [node("libnl")],
      },
    });
    mount.render(
      screen(
        <Dependencies />,
        "/products/sonic/branches-and-tags/master/variants/arm/dependencies",
        "/products/:product/branches-and-tags/:branch_or_tag/variants/:variant/dependencies",
      ),
    );
    await settle();
  }

  it("draws no count on a node for a reader without dependency read here", async () => {
    await tree(ELSEWHERE);
    expect(text()).toContain("libnl");
    expect(mount.host().querySelector(".tree .count")).toBeNull();
    expect(text()).toContain("You don't read dependency findings in sonic.");
  });

  it("draws each node's count for a reader of dependency findings here", async () => {
    await tree(who([readingDependencies("sonic")]));
    expect(mount.host().querySelector(".tree .count")).not.toBeNull();
  });
});

describe("the findings list", () => {
  it("says an empty list is one the reader does not read, never that nothing is open", async () => {
    serving(ELSEWHERE);
    mount.render(screen(<Findings />, "/products/sonic/findings", "/products/:product/findings"));
    await settle();
    expect(text()).not.toContain("Nothing is open here at all.");
    expect(text()).toContain("You don't read dependency findings in sonic.");
  });
});

describe("the findings list's total", () => {
  it("says a disclosed-only reader's list is of disclosed findings", async () => {
    serving(DISCLOSED);
    mount.render(screen(<Findings />, "/products/sonic/findings", "/products/:product/findings"));
    await settle();
    expect(text()).toContain("Counting disclosed findings, the ones you read here.");
  });
});

describe("the home page", () => {
  async function home(as: Who, at = "/products/sonic") {
    const spy = serving(as);
    mount.render(screen(<Home who={as} />, at, at === "/" ? "*" : "/products/:product"));
    await settle();
    return spy;
  }

  const tiles = () =>
    Array.from(mount.host().querySelectorAll(".kpi .l")).map((each) => each.textContent ?? "");

  it("draws no dependency tile or trend for a reader holding them nowhere", async () => {
    const spy = await home(DEVELOPER);
    expect(tiles().some((each) => each.startsWith("Open issues"))).toBe(false);
    expect(tiles().some((each) => each.includes("Overdue"))).toBe(false);
    expect(text()).not.toContain("Severity over time");
    expect(text()).not.toContain("You don't read");
    expect(asked(spy)).not.toContain("/v1/trend");
    expect(tiles().some((each) => each.startsWith("Assigned to you"))).toBe(true);
  });

  it("says in one line that dependency findings are read in another product", async () => {
    await home(ELSEWHERE);
    expect(tiles().some((each) => each.startsWith("Open issues"))).toBe(false);
    expect(text()).toContain("You don't read dependency findings in sonic.");
  });

  it("says a disclosed-only reader's figures are of disclosed findings", async () => {
    await home(DISCLOSED);
    expect(tiles().some((each) => each.startsWith("Open issues"))).toBe(true);
    expect(text()).toContain("Counting disclosed findings, the ones you read here.");
  });

  it("opens an auditor on the deployment's records rather than a page of zeros", async () => {
    const spy = await home(AUDITOR, "/");
    expect(mount.host().querySelector(".kpis")).toBeNull();
    expect(text()).toContain("You audit this deployment");
    expect(text()).toContain("You don’t read findings in any product.");
    const links = Array.from(mount.host().querySelectorAll("a")).map((a) => a.getAttribute("href"));
    expect(links).toContain("/audit-log");
    expect(asked(spy)).not.toContain("/v1/trend");
  });
});

describe("the audit log", () => {
  it("shows an auditor the change history, never a record of zero decisions", async () => {
    const spy = serving(AUDITOR);
    mount.render(screen(<AuditLog />, "/audit-log"));
    await settle();
    expect(text()).toContain("You don’t read findings in any product.");
    expect(asked(spy)).toContain("/v1/administration/changes");
    expect(asked(spy)).not.toContain("/v1/audit/decisions");
  });
});
