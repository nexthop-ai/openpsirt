// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import type { Who } from "../app/session";
import { client, mounted, screen, serve, settle } from "../test/mount";
import { reaching, readingDependencies } from "../test/reach";
import { AuditLog } from "./AuditLog";
import { Component } from "./Component";
import { Dependencies } from "./Dependencies";
import { Findings } from "./Findings";
import { Home } from "./Home";
import { Product } from "./Product";
import { Products } from "./Products";
import { Branches } from "./Branches";
import { Variants } from "./Variants";
import { Release } from "./Release";
import { Compare } from "./Compare";
import { DisclosureDeadlines } from "./DisclosureDeadlines";
import { Overview } from "./analytics/Overview";
import { Backlog } from "./analytics/Backlog";
import { Compliance } from "./analytics/Compliance";
import { Register } from "./analytics/Register";
import { Support } from "./analytics/Support";
import { remember } from "../app/scope";

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

// A query client holding the session already, as the app's does by the time a
// screen draws: a screen asks nothing it would not draw for this reader.
function signedIn(as: Who) {
  const queries = client();
  queries.setQueryData(["whoami"], as);
  return queries;
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

  it("draws no total or view count, and asks for none, where the reader does not read the list", async () => {
    const spy = serving(ELSEWHERE);
    mount.render(
      screen(
        <Findings />,
        "/products/sonic/findings",
        "/products/:product/findings",
        signedIn(ELSEWHERE),
      ),
    );
    await settle();
    expect(mount.host().querySelector(".screen-head .n")).toBeNull();
    expect(mount.host().querySelector(".viewtabs")).toBeNull();
    expect(asked(spy)).not.toContain("/v1/products/{product}/findings");
    expect(asked(spy)).not.toContain("/v1/products/{product}/findings/components");
    expect(asked(spy)).not.toContain("/v1/products/{product}/planned-upgrades");
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
    expect(asked(spy)).not.toContain("/v1/trend/releases");
    expect(asked(spy)).not.toContain("/v1/running-out");
    expect(asked(spy)).not.toContain("/v1/products/{product}/findings");
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
    expect(tiles().some((each) => each.startsWith("Open issues"))).toBe(false);
    expect(text()).toContain("You audit this deployment");
    expect(text()).toContain("You don’t read findings in any product.");
    const links = Array.from(mount.host().querySelectorAll("a")).map((a) => a.getAttribute("href"));
    expect(links).toContain("/audit-log");
    expect(asked(spy)).not.toContain("/v1/trend");
  });
});

describe("the home page of a capability without a read role", () => {
  it("keeps the work panels beside the records", async () => {
    const approver = who([reaching("sonic", { may_agree: true, agrees_private: true })]);
    serving(approver);
    mount.render(screen(<Home who={approver} />, "/", "*"));
    await settle();
    expect(text()).toContain("You don’t read findings in any product.");
    const panels = Array.from(mount.host().querySelectorAll(".panel h3")).map(
      (each) => each.textContent,
    );
    expect(panels).toContain("Pending your approval");
    const labels = Array.from(mount.host().querySelectorAll(".kpi .l")).map(
      (each) => each.textContent ?? "",
    );
    expect(labels.some((each) => each.startsWith("Assigned to you"))).toBe(true);
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

// What a screen asked of one path, by its query parameters.
function queriesAt(spy: ReturnType<typeof serving>, path: string) {
  return (spy.mock.calls as unknown as [string, { params?: { query?: unknown } }][])
    .filter(([each]) => each === path)
    .map(([, init]) => init?.params?.query as Record<string, unknown> | undefined);
}

const headers = () =>
  Array.from(mount.host().querySelectorAll("th")).map((each) => each.textContent?.trim());

describe("the products list", () => {
  const PRODUCTS = {
    "/v1/products": {
      items: [
        { name: "edge", open: 3 },
        { name: "sonic", open: 0 },
      ],
    },
  };

  it("draws a dash for a product the reader does not read dependency findings in", async () => {
    serving(ELSEWHERE, PRODUCTS);
    mount.render(screen(<Products who={ELSEWHERE} />, "/products"));
    await settle();
    expect(headers()).toContain("Open findings");
    const sonic = Array.from(mount.host().querySelectorAll("tr")).find((row) =>
      row.textContent?.includes("sonic"),
    );
    const dash = sonic?.querySelector("td.hint");
    expect(dash?.textContent).toBe("—");
    expect(dash?.getAttribute("title")).toBe("You don't read dependency findings in sonic.");
  });

  it("draws no open column, and asks for no count, for a reader of them nowhere", async () => {
    const spy = serving(DEVELOPER, PRODUCTS);
    mount.render(screen(<Products who={DEVELOPER} />, "/products"));
    await settle();
    expect(headers()).not.toContain("Open findings");
    expect(queriesAt(spy, "/v1/products").every((query) => !query?.counts)).toBe(true);
  });
});

describe("the branches and tags list", () => {
  it("draws no open column, asks for no count, and says why", async () => {
    const spy = serving(ELSEWHERE, {
      "/v1/products/{product}/branches-and-tags": { items: [{ name: "master", kind: "branch" }] },
    });
    mount.render(
      screen(
        <Branches />,
        "/products/sonic/branches-and-tags",
        "/products/:product/branches-and-tags",
        signedIn(ELSEWHERE),
      ),
    );
    await settle();
    expect(text()).toContain("master");
    expect(headers()).not.toContain("Open");
    expect(text()).toContain("You don't read dependency findings in sonic.");
    const asked = queriesAt(spy, "/v1/products/{product}/branches-and-tags");
    expect(asked.length).toBeGreaterThan(0);
    expect(asked.every((query) => !query?.counts)).toBe(true);
  });
});

describe("the variants list", () => {
  it("draws no open column, asks for no count, and says why", async () => {
    const spy = serving(ELSEWHERE, {
      "/v1/products/{product}/variants": { items: [{ name: "arm" }] },
    });
    mount.render(
      screen(
        <Variants />,
        "/products/sonic/variants",
        "/products/:product/variants",
        signedIn(ELSEWHERE),
      ),
    );
    await settle();
    expect(text()).toContain("arm");
    expect(headers()).not.toContain("Open");
    expect(text()).toContain("You don't read dependency findings in sonic.");
    const asked = queriesAt(spy, "/v1/products/{product}/variants");
    expect(asked.length).toBeGreaterThan(0);
    expect(asked.every((query) => !query?.counts)).toBe(true);
  });
});

describe("a release", () => {
  it("draws no open count per variant or in all, and asks for none", async () => {
    const spy = serving(ELSEWHERE, {
      "/v1/products/{product}/branches-and-tags": { items: [{ name: "v1", kind: "tag" }] },
      "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants": {
        items: [{ name: "arm" }],
      },
    });
    mount.render(
      screen(<Release product="sonic" branch_or_tag="v1" />, "/", "*", signedIn(ELSEWHERE)),
    );
    await settle();
    expect(text()).toContain("arm");
    expect(headers()).not.toContain("Open");
    expect(text()).not.toContain("Open now");
    expect(text()).not.toContain("open in all");
    expect(text()).toContain("You don't read dependency findings in sonic.");
    expect(asked(spy)).not.toContain(
      "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/readiness",
    );
  });
});

describe("release comparison", () => {
  it("draws no chart or column and asks for neither, saying why", async () => {
    const spy = serving(ELSEWHERE);
    mount.render(
      screen(
        <Compare />,
        "/products/sonic/compare?from=v1&from_variant=arm&to=v2&to_variant=arm",
        "/products/:product/compare",
        signedIn(ELSEWHERE),
      ),
    );
    await settle();
    expect(text()).toContain("You don't read dependency findings in sonic.");
    expect(mount.host().querySelector(".col")).toBeNull();
    expect(asked(spy)).not.toContain("/v1/products/{product}/comparison");
    expect(asked(spy)).not.toContain("/v1/products/{product}/releases");
  });
});

describe("disclosure deadlines", () => {
  it("says the reader reads no undisclosed work, never that nothing is approaching", async () => {
    const spy = serving(DEVELOPER);
    mount.render(
      screen(<DisclosureDeadlines />, "/disclosure-deadlines", "*", signedIn(DEVELOPER)),
    );
    await settle();
    expect(text()).not.toContain("Nothing is approaching");
    expect(text()).toContain("You don't read undisclosed findings in any product.");
    expect(asked(spy)).not.toContain("/v1/disclosure-deadlines");
  });
});

describe("analytics", () => {
  async function report(node: React.ReactElement, as: Who) {
    remember({ product: "sonic" });
    const spy = serving(as);
    mount.render(screen(node, "/analytics/report", "*", signedIn(as)));
    await settle();
    return spy;
  }

  it("draws no keeping pace or repeated deferrals in the program overview, and asks for neither", async () => {
    const spy = await report(<Overview />, ELSEWHERE);
    expect(text()).not.toContain("Keeping pace");
    expect(text()).not.toContain("Repeated deferrals");
    expect(text()).toContain("Triage times");
    expect(text()).toContain("You don't read dependency findings in sonic.");
    expect(asked(spy)).not.toContain("/v1/remediation");
    expect(asked(spy)).not.toContain("/v1/deferrals/repeated");
  });

  it("draws no decision figure in the program overview for a reader of no finding", async () => {
    const spy = await report(<Overview />, AUDITOR);
    expect(text()).not.toContain("Triage times");
    expect(asked(spy)).not.toContain("/v1/measures");
    expect(asked(spy)).not.toContain("/v1/audit");
  });

  it("draws no backlog and asks for no trend", async () => {
    const spy = await report(<Backlog />, ELSEWHERE);
    expect(text()).toContain("You don't read dependency findings in sonic.");
    expect(text()).not.toContain("Nothing has been scanned yet.");
    expect(asked(spy)).not.toContain("/v1/trend");
  });

  it("draws no compliance rate and asks for none", async () => {
    const spy = await report(<Compliance />, ELSEWHERE);
    expect(text()).toContain("You don't read dependency findings in sonic.");
    expect(asked(spy)).not.toContain("/v1/compliance");
  });

  it("draws no disposition register and asks for none", async () => {
    remember({ product: "sonic", branch_or_tag: "master", variant: "arm" });
    const spy = serving(ELSEWHERE);
    mount.render(screen(<Register />, "/analytics/report", "*", signedIn(ELSEWHERE)));
    await settle();
    expect(text()).toContain("You don't read dependency findings in sonic.");
    expect(asked(spy)).not.toContain(
      "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/register",
    );
  });

  it("draws no open count on releases out of support where the reader does not read them", async () => {
    remember({});
    const spy = serving(ELSEWHERE, {
      "/v1/releases/out-of-support": {
        items: [
          {
            product: "sonic",
            branch_or_tag: "v1",
            kind: "tag",
            ended_on: "2026-01-01",
            ended_days: 10,
            open: 0,
          },
        ],
        total: 1,
        open: 0,
      },
    });
    mount.render(screen(<Support />, "/analytics/report", "*", signedIn(ELSEWHERE)));
    await settle();
    expect(asked(spy)).toContain("/v1/releases/out-of-support");
    const sonic = Array.from(mount.host().querySelectorAll("tr")).find((row) =>
      row.textContent?.includes("sonic"),
    );
    expect(sonic?.querySelector("td.hint")?.getAttribute("title")).toBe(
      "You don't read dependency findings in sonic.",
    );
  });
});
