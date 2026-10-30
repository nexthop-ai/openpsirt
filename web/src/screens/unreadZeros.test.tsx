// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import type { Who } from "../app/session";
import { client, mounted, screen, serve, settle } from "../test/mount";
import { reaching, readingDependencies } from "../test/reach";
import { PUBLISHED } from "../test/outcomes";
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
import { Scrutiny } from "./analytics/Scrutiny";
import { Effort } from "./analytics/Effort";
import { remember } from "../app/scope";
import { Incidents } from "./Incidents";
import { Uploads } from "./Uploads";
import { Run } from "./Run";
import { Assignments } from "./Assignments";
import { CodeFindings } from "./CodeFindings";
import { CodeFindingSeries } from "./analytics/CodeFindingSeries";

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
// A reader of dependency findings in edge alone, with a role in sonic too.
const OTHER_PRODUCT = who([readingDependencies("edge"), reaching("sonic")]);
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
  const labels = () =>
    Array.from(mount.host().querySelectorAll(".kpi .l")).map((each) => each.textContent ?? "");

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
    expect(labels()).not.toContain("Past a deadline");
    expect(labels()).not.toContain("Open · sonic");
    expect(text()).not.toContain("Overdue");
    expect(text()).toContain("You don't read dependency findings in sonic.");
    expect(text()).toContain("master");
  });

  it("counts what waits on a second person for an approver reading code findings alone", async () => {
    const approver = who([
      reaching("sonic", { may_see: true, reads_security_testing: true, may_agree: true }),
    ]);
    serving(approver, {
      "/v1/products/{product}/overview": {
        ...OVERVIEW["/v1/products/{product}/overview"],
        waiting: 2,
      },
    });
    mount.render(screen(<Product />, "/products/sonic", "/products/:product"));
    await settle();
    expect(labels()).not.toContain("Past a deadline");
    expect(labels()).toContain("Waiting on a second person");
  });

  it("says a disclosed-only reader's figures are of disclosed findings", async () => {
    serving(DISCLOSED, OVERVIEW);
    mount.render(screen(<Product />, "/products/sonic", "/products/:product"));
    await settle();
    expect(labels()).toContain("Past a deadline");
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

  it.each([
    ["components", "/v1/products/{product}/findings/components"],
    ["bumps", "/v1/products/{product}/planned-upgrades"],
  ])(
    "says why a kept link to the %s view is empty, and asks for none of it",
    async (view, path) => {
      const spy = serving(ELSEWHERE);
      mount.render(
        screen(
          <Findings />,
          `/products/sonic/findings?view=${view}`,
          "/products/:product/findings",
          signedIn(ELSEWHERE),
        ),
      );
      await settle();
      expect(text()).toContain("You don't read dependency findings in sonic.");
      expect(text()).not.toContain("Nothing matches what you are looking at.");
      expect(asked(spy)).not.toContain(path);
    },
  );
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
    expect(tiles().some((each) => each.startsWith("Code findings assigned to you"))).toBe(true);
    expect(tiles().some((each) => each.startsWith("Dependency findings assigned to you"))).toBe(
      false,
    );
  });

  const panels = () =>
    Array.from(mount.host().querySelectorAll(".panel h3")).map((each) => each.textContent ?? "");

  it("draws lapsed decisions for a reader of code findings alone, asking no dependency count", async () => {
    const spy = await home(DEVELOPER);
    expect(panels()).toContain("Lapsed decisions");
    expect(asked(spy)).not.toContain("/v1/products/{product}/findings");
  });

  it("draws no lapsed decisions where the reader reads neither family", async () => {
    await home(OTHER_PRODUCT);
    expect(panels()).not.toContain("Lapsed decisions");
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
    // Holding nothing of a family read nowhere draws no figure of it, so no
    // zero stands for work they cannot be handed.
    const labels = Array.from(mount.host().querySelectorAll(".kpi .l")).map(
      (each) => each.textContent ?? "",
    );
    expect(labels.some((each) => each.includes("assigned to you"))).toBe(false);
  });

  it("counts the work handed to them, though they read neither family", async () => {
    const approver = who([reaching("sonic", { may_agree: true, agrees_private: true })]);
    serving(approver, { "/v1/people/{identity}/assignments": { items: [], total: 2 } });
    mount.render(screen(<Home who={approver} />, "/", "*"));
    await settle();
    const labels = Array.from(mount.host().querySelectorAll(".kpi")).map(
      (each) =>
        `${each.querySelector(".l")?.textContent?.split(" · ")[0]} ${each.querySelector(".n")?.textContent}`,
    );
    expect(labels).toContain("Dependency findings assigned to you 2");
  });
});

describe("the audit log", () => {
  it("shows an auditor the change history, never a record of zero decisions", async () => {
    const spy = serving(AUDITOR);
    mount.render(screen(<AuditLog />, "/audit-log"));
    await settle();
    expect(text()).toContain("You don’t read findings in any product.");
    expect(asked(spy)).toContain("/v1/administration/changes");
    expect(mount.host().querySelector(".audited")).toBeNull();
  });

  it("lists a case collaborator's own decisions though they read no finding", async () => {
    const collaborator = who([]);
    serving(collaborator, {
      "/v1/audit/decisions": {
        total: 1,
        items: [
          {
            decision: 7,
            issue: "CVE-2026-1",
            issues: 1,
            product: "sonic",
            products: 1,
            component: "libnl",
            version: "3.7",
            components: 1,
            rows: 1,
            occurrences: 1,
            outcome: "not-affected",
            reasoning: "Never reached.",
            state: "approved",
            states: { proposed: 0, approved: 1, withdrawn: 0, lapsed: 0 },
            standing: 1,
            proposed_by: "bob",
            proposed_at: "2026-09-01T00:00:00Z",
            approvals: [],
            two_people: false,
          },
        ],
      },
    });
    mount.render(screen(<AuditLog />, "/audit-log", "*", signedIn(collaborator)));
    await settle();
    expect(mount.host().querySelectorAll(".audited").length).toBe(1);
    expect(text()).toContain("CVE-2026-1");
    expect(text()).not.toContain("You don’t read findings in any product.");
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
    expect(text()).toContain("Nothing to list.");
    expect(text()).toContain("You don't read dependency findings in sonic.");
    expect(mount.host().querySelector(".col")).toBeNull();
    expect(asked(spy)).not.toContain("/v1/products/{product}/comparison");
    expect(asked(spy)).not.toContain("/v1/products/{product}/releases");
  });

  it("asks an undisclosed-only reader's comparison of undisclosed findings, offering no chip", async () => {
    const reader = who([reaching("sonic", { may_see: true, reads_private: true })]);
    const spy = serving(reader);
    mount.render(
      screen(
        <Compare />,
        "/products/sonic/compare?from=v1&from_variant=arm&to=v2&to_variant=arm",
        "/products/:product/compare",
        signedIn(reader),
      ),
    );
    await settle();
    expect(text()).toContain("Counting undisclosed findings, the ones you read here.");
    expect(text()).not.toContain("Include undisclosed");
    const comparisons = queriesAt(spy, "/v1/products/{product}/comparison");
    expect(comparisons.length).toBeGreaterThan(0);
    expect(comparisons.every((query) => query?.include_undisclosed === true)).toBe(true);
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
    // Outcomes the server publishes, so the dismissals would be asked and
    // drawn were the reader not turned away.
    const spy = await report(<Overview />, { ...AUDITOR, outcomes: PUBLISHED });
    expect(text()).not.toContain("Triage times");
    expect(text()).not.toContain("Dismissals");
    expect(text()).toContain("Nothing to list.");
    expect(text()).toContain("You don't read findings in any product.");
    expect(asked(spy)).not.toContain("/v1/measures");
    expect(asked(spy)).not.toContain("/v1/audit");
  });

  it("draws no decision figure in the program overview for a reader of findings in another product", async () => {
    const spy = await report(<Overview />, { ...OTHER_PRODUCT, outcomes: PUBLISHED });
    expect(text()).not.toContain("Triage times");
    expect(text()).not.toContain("Dismissals");
    expect(text()).toContain("Nothing to list.");
    expect(text()).toContain("You don't read findings in sonic.");
    expect(asked(spy)).not.toContain("/v1/measures");
    expect(asked(spy)).not.toContain("/v1/audit");
  });

  it.each([
    [
      "approval quality",
      <Scrutiny key="scrutiny" />,
      "/v1/approvals/scrutiny",
      "No dismissal stands",
    ],
    ["effort", <Effort key="effort" />, "/v1/effort", "Nothing was argued"],
  ])(
    "draws no %s, and asks for none, for a reader of findings in another product",
    async (_, node, path, clean) => {
      const spy = await report(node, OTHER_PRODUCT);
      expect(text()).not.toContain(clean);
      expect(text()).toContain("Nothing to list.");
      expect(text()).toContain("You don't read findings in sonic.");
      expect(asked(spy)).not.toContain(path);
    },
  );

  it.each([
    ["approval quality", <Scrutiny key="scrutiny" />, "/v1/approvals/scrutiny"],
    ["effort", <Effort key="effort" />, "/v1/effort"],
  ])("asks for %s for a reader of code findings alone", async (_, node, path) => {
    const spy = await report(node, DEVELOPER);
    expect(text()).not.toContain("Nothing to list.");
    expect(asked(spy)).toContain(path);
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

describe("the home page's incidents", () => {
  const SHELF = {
    "/v1/incidents": { items: [{ id: 1, product: "sonic", standing: true, issue: "CVE-2026-1" }] },
  };
  const tiles = () =>
    Array.from(mount.host().querySelectorAll(".kpi .l")).map((each) => each.textContent ?? "");

  it("counts a case collaborator's incident though they read no dependency finding", async () => {
    const collaborator = who([]);
    serving(collaborator, SHELF);
    mount.render(screen(<Home who={collaborator} />, "/products/sonic", "/products/:product"));
    await settle();
    expect(tiles().some((each) => each.includes("Incidents"))).toBe(true);
  });

  it("draws no incidents tile over an empty shelf", async () => {
    serving(ELSEWHERE);
    mount.render(screen(<Home who={ELSEWHERE} />, "/products/sonic", "/products/:product"));
    await settle();
    expect(tiles().some((each) => each.includes("Incidents"))).toBe(false);
  });

  it("counts the incidents of a reader of dependency findings here", async () => {
    const reader = who([readingDependencies("sonic")]);
    serving(reader, SHELF);
    mount.render(screen(<Home who={reader} />, "/products/sonic", "/products/:product"));
    await settle();
    expect(tiles().some((each) => each.includes("Incidents"))).toBe(true);
  });
});

describe("the incidents screen", () => {
  async function shelf(as: Who, at: string) {
    const spy = serving(as);
    mount.render(screen(<Incidents />, at, "/incidents", signedIn(as)));
    await settle();
    return spy;
  }

  it("says the reader reads no dependency findings, never that none are recorded", async () => {
    await shelf(DEVELOPER, "/incidents");
    expect(text()).not.toContain("No incidents are recorded.");
    expect(text()).toContain("You don't read dependency findings in any product.");
    expect(mount.host().querySelector(".screen-head .n")).toBeNull();
  });

  it("says in one line that dependency findings are read in another product", async () => {
    await shelf(ELSEWHERE, "/incidents?product=sonic");
    expect(text()).not.toContain("has no incidents");
    expect(text()).toContain("You don't read dependency findings in sonic.");
    expect(mount.host().querySelector(".screen-head .n")).toBeNull();
  });

  it("lists a collaborator's own case for a reader of no dependency findings", async () => {
    const spy = serving(DEVELOPER, {
      "/v1/incidents": {
        items: [
          {
            id: 7,
            product: "sonic",
            product_name: "SONIC",
            vulnerability: "CVE-2026-9",
            standing: true,
            known_at: "2026-09-01T00:00:00Z",
            grounds: "Seen in the field.",
            windows: [],
            told: [],
            fixes: [],
          },
        ],
      },
    });
    mount.render(screen(<Incidents />, "/incidents", "/incidents", signedIn(DEVELOPER)));
    await settle();
    expect(asked(spy)).toContain("/v1/incidents");
    expect(text()).toContain("CVE-2026-9");
    expect(text()).not.toContain("Nothing to list.");
    expect(mount.host().querySelector(".screen-head .n")).toBeNull();
  });

  it("names what its zero counts for a reader of dependency findings here", async () => {
    const spy = await shelf(who([readingDependencies("sonic")]), "/incidents?product=sonic");
    expect(text()).toContain("sonic has no incidents.");
    expect(mount.host().querySelector(".screen-head .n")?.textContent).toBe("0");
    expect(asked(spy)).toContain("/v1/incidents");
  });

  it("says a disclosed-only reader's shelf is of disclosed findings", async () => {
    await shelf(DISCLOSED, "/incidents?product=sonic");
    expect(text()).toContain("Counting disclosed findings, the ones you read here.");
  });
});

describe("a build's uploads", () => {
  const BUILD = "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}";
  const UPLOADS = {
    [`${BUILD}/uploads`]: { items: [{ type: "sbom", total: 1 }] },
    [`${BUILD}/sboms`]: {
      items: [
        { scan_id: 1, received_at: "2026-10-01T00:00:00Z", state: "scanned", opened: 0, closed: 0 },
      ],
      total: 1,
    },
  };

  async function uploads(as: Who) {
    serving(as, UPLOADS);
    mount.render(
      screen(
        <Uploads />,
        "/products/sonic/branches-and-tags/master/variants/arm/uploads",
        "/products/:product/branches-and-tags/:branch_or_tag/variants/:variant/uploads",
        signedIn(as),
      ),
    );
    await settle();
  }

  it("draws no opened or closed count where dependency findings are not read", async () => {
    await uploads(ELSEWHERE);
    expect(text()).toContain("Received");
    expect(headers()).not.toContain("Opened");
    expect(headers()).not.toContain("Closed");
    expect(text()).toContain("You don't read dependency findings in sonic.");
  });

  it("draws them for a reader of dependency findings here", async () => {
    await uploads(who([readingDependencies("sonic")]));
    expect(headers()).toContain("Opened");
    expect(headers()).toContain("Closed");
  });
});

describe("a scan run's page", () => {
  const RUN = {
    "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/runs/{run}": {
      run_id: 7,
      scanner: "grype",
      finished_at: "2026-10-01T00:00:00Z",
      opened: { total: 0 },
      closed: { total: 0 },
    },
  };

  async function run(as: Who) {
    serving(as, RUN);
    mount.render(
      screen(
        <Run />,
        "/products/sonic/branches-and-tags/master/variants/arm/runs/7",
        "/products/:product/branches-and-tags/:branch_or_tag/variants/:variant/runs/:run",
        signedIn(as),
      ),
    );
    await settle();
  }

  it("draws no opened or closed count, and nothing called unchanged, where the reader does not read them", async () => {
    await run(ELSEWHERE);
    expect(text()).toContain("grype");
    expect(text()).not.toContain("The findings it opened");
    expect(text()).not.toContain("Nothing changed.");
    expect(text()).toContain("You don't read dependency findings in sonic.");
  });

  it("draws them for a reader of dependency findings here", async () => {
    await run(who([readingDependencies("sonic")]));
    expect(text()).toContain("The findings it opened");
    expect(text()).toContain("Nothing changed.");
  });
});

describe("assignments", () => {
  async function assignments(as: Who, at = "/assignments?tab=people") {
    const spy = serving(as);
    mount.render(screen(<Assignments />, at, "/assignments", signedIn(as)));
    await settle();
    return spy;
  }

  it("draws no one else's holdings, and asks for none, for a reader of no finding", async () => {
    const spy = await assignments(AUDITOR);
    expect(text()).not.toContain("Assigned to others");
    expect(text()).not.toContain("Nobody else is holding anything.");
    expect(text()).toContain("Assigned to me");
    expect(asked(spy)).not.toContain("/v1/assignments");
  });

  it("says in one line which families are read in another product", async () => {
    remember({ product: "sonic" });
    const spy = await assignments(
      who([readingDependencies("edge"), reaching("sonic", { may_see: true })]),
    );
    expect(text()).not.toContain("Assigned to others");
    expect(text()).toContain("You don't read dependency findings in sonic.");
    expect(asked(spy)).not.toContain("/v1/assignments");
  });

  it("counts who else holds what for a reader of either family", async () => {
    const spy = await assignments(DEVELOPER);
    expect(text()).toContain("Assigned to others");
    expect(text()).toContain("Nobody else is holding anything.");
    expect(asked(spy)).toContain("/v1/assignments");
  });

  it("asks for no one's list from a kept link the reader is not shown", async () => {
    const spy = await assignments(AUDITOR, "/assignments?tab=people&person=bob");
    const holders = (spy.mock.calls as unknown as [string, { params?: { path?: unknown } }][])
      .filter(([path]) => path === "/v1/people/{identity}/assignments")
      .map(([, init]) => (init?.params?.path as { identity?: string } | undefined)?.identity);
    expect(holders).not.toContain("bob");
    expect(holders).toContain("me");
  });

  it("asks for no team's list from a kept link the reader is not shown", async () => {
    const spy = await assignments(AUDITOR, "/assignments?tab=people&team=intake");
    expect(asked(spy)).toContain("/v1/people/{identity}/assignments");
    expect(asked(spy)).not.toContain("/v1/teams/{team}/assignments");
  });

  it("links a retired product's unassigned code findings, as the session holds its counts", async () => {
    remember({ product: "old" });
    await assignments(DEVELOPER);
    expect(text()).toContain("Unassigned code findings in old");
  });
});

describe("security testing", () => {
  // A reader of code findings in edge alone, with a role in sonic too.
  const CODE_ELSEWHERE = who([
    reaching("edge", { may_see: true, reads_security_testing: true }),
    reaching("sonic", { may_see: true }),
  ]);

  it("says the list is one the reader does not read in the product, and asks for none", async () => {
    const spy = serving(CODE_ELSEWHERE);
    mount.render(
      screen(
        <CodeFindings />,
        "/products/sonic/code-findings",
        "/products/:product/code-findings",
        signedIn(CODE_ELSEWHERE),
      ),
    );
    await settle();
    expect(text()).toContain("Nothing to list.");
    expect(text()).toContain("You don't read code findings in sonic.");
    expect(text()).not.toContain("Nothing in the queue.");
    expect(asked(spy)).not.toContain("/v1/products/{product}/code-findings");
  });

  it("lists a retired product's code findings, as the session holds its counts", async () => {
    const spy = serving(CODE_ELSEWHERE);
    mount.render(
      screen(
        <CodeFindings />,
        "/products/old/code-findings",
        "/products/:product/code-findings",
        signedIn(CODE_ELSEWHERE),
      ),
    );
    await settle();
    expect(asked(spy)).toContain("/v1/products/{product}/code-findings");
  });

  it("names the product code findings are not read in on the analyzer report", async () => {
    remember({ product: "sonic" });
    const spy = serving(CODE_ELSEWHERE);
    mount.render(screen(<CodeFindingSeries />, "/analytics/report", "*", signedIn(CODE_ELSEWHERE)));
    await settle();
    expect(text()).toContain("You don't read code findings in sonic.");
    expect(asked(spy)).not.toContain("/v1/products/{product}/code-finding-series");
  });

  it("counts a retired product's analyzers, as the session holds its counts", async () => {
    remember({ product: "old" });
    const spy = serving(CODE_ELSEWHERE);
    mount.render(screen(<CodeFindingSeries />, "/analytics/report", "*", signedIn(CODE_ELSEWHERE)));
    await settle();
    expect(asked(spy)).toContain("/v1/products/{product}/code-finding-series");
  });
});
