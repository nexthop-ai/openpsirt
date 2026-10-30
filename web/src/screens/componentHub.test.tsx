// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import type { Who } from "../app/session";
import { mounted, screen, serve, settle } from "../test/mount";
import { reaching, readingDependencies } from "../test/reach";
import { CodeFindings } from "./CodeFindings";
import { Component } from "./Component";
import { Components } from "./Components";
import { Dependencies } from "./Dependencies";

// The component as the hub both families link into: the component screen's
// security testing card, build column and second panel, the tree's code
// findings column, the queue narrowed to a component, and the chooser a search
// lands on. Each is drawn and asked for only where the reader reads code
// findings, and said in one line where they read them elsewhere.

const mount = mounted();

afterEach(() => {
  vi.restoreAllMocks();
  window.sessionStorage.clear();
});

function who(reach: Who["reach"]): Who {
  return { identity: "ana", name: "Ana", admin: false, kind: "person", reach, outcomes: [] };
}

// Both families read in sonic.
const BOTH = who([
  reaching("sonic", {
    may_see: true,
    reads_public: true,
    reads_private: true,
    reads_security_testing: true,
  }),
]);
// Dependency findings in sonic; code findings in edge alone.
const CODE_ELSEWHERE = who([
  readingDependencies("sonic"),
  reaching("edge", { may_see: true, reads_security_testing: true }),
]);
// Dependency findings in sonic, and code findings nowhere.
const DEPENDENCIES = who([readingDependencies("sonic")]);
// Both families in edge, and sonic unlisted, as a retired product is: the
// session cannot say what is read there until the server is asked.
const UNLISTED = who([
  reaching("edge", {
    may_see: true,
    reads_public: true,
    reads_private: true,
    reads_security_testing: true,
  }),
]);

const text = () => mount.host().textContent ?? "";
const links = () => Array.from(mount.host().querySelectorAll("a"));
const hrefOf = (label: string) =>
  links()
    .find((each) => each.textContent === label)
    ?.getAttribute("href");

// Every read answered from the table given, the rest as empty lists, and each
// request kept with what it was asked.
function serving(as: Who, answers: Record<string, unknown>) {
  const asked: [string, unknown][] = [];
  serve((path, init) => {
    asked.push([path, init]);
    if (path === "/v1/session/me") return { data: as };
    if (path in answers) return { data: answers[path] };
    return { data: { items: [], total: 0 } };
  });
  return asked;
}

const COUNTS = "/v1/products/{product}/components/{component}/code-finding-counts";
const TREND = "/v1/products/{product}/code-finding-trend";
const STATES = {
  open: 0,
  "no-longer-detected": 0,
  fixed: 0,
  dismissed: 0,
  "not-security": 0,
  confirmed: 0,
  "recorded-as-flaw": 0,
};

const SPLIT = { by_tier: {}, by_series: {}, by_method: {} };

const SHIPPED = {
  items: [
    {
      branch_or_tag: "master",
      variant: "arm",
      version: "3.7",
      source: "libnl",
      ecosystem: "deb",
      issues: 2,
      packages: [{ name: "libnl3", version: "3.7", issues: 2 }],
    },
  ],
};

// Every read answered from the table given, a status in place of an answer
// where one is named, and each request kept.
function servingWith(as: Who, answers: Record<string, unknown>, statuses: Record<string, number>) {
  const asked: [string, unknown][] = [];
  serve((path, init) => {
    asked.push([path, init]);
    if (path in statuses) return { status: statuses[path] };
    if (path === "/v1/session/me") return { data: as };
    if (path in answers) return { data: answers[path] };
    return { data: { items: [], total: 0 } };
  });
  return asked;
}

async function component(
  as: Who,
  more: Record<string, unknown> = {},
  at = "/products/sonic/components/libnl",
  statuses: Record<string, number> = {},
) {
  const asked = servingWith(
    as,
    {
      "/v1/products/{product}/components/{component}": SHIPPED,
      [COUNTS]: {
        series: [
          {
            series: "clang-tidy/default",
            states: { ...STATES, open: 3, fixed: 1 },
            waiting: 0,
            ruled: 0,
            unplaced: 0,
          },
          { series: "semgrep/default", states: STATES, waiting: 0, ruled: 0, unplaced: 0 },
        ],
        builds: [{ branch_or_tag: "master", variant: "arm", version: "3.7", open: 3 }],
      },
      [TREND]: {
        points: [
          { at: "2026-10-15", not_fixed: 4, opened: 0, fixed: 0, ...SPLIT },
          { at: "2026-10-22", not_fixed: 3, opened: 0, fixed: 1, ...SPLIT },
        ],
        markers: [
          {
            at: "2026-10-21",
            series: "clang-tidy/default",
            change: "tool-version",
            from: "18.1",
            to: "19.1",
            builds: 1,
          },
        ],
        no_longer_detected: 0,
      },
      ...more,
    },
    statuses,
  );
  mount.render(screen(<Component />, at, "/products/:product/components/:component"));
  await settle();
  return asked.map(([path]) => path);
}

describe("the component screen's security testing", () => {
  it("counts each series by state, each count opening the queue narrowed to the source package", async () => {
    await component(BOTH);
    expect(text()).toContain("Security testing");
    expect(text()).toContain("3 code findings open");
    expect(hrefOf("3")).toBe(
      "/products/sonic/code-findings?component=libnl&series=clang-tidy%2Fdefault&state=open",
    );
    expect(hrefOf("1")).toBe(
      "/products/sonic/code-findings?component=libnl&series=clang-tidy%2Fdefault&state=fixed",
    );
    expect(text()).toContain("semgrep/default");
  });

  it("gives each build row its open code findings, opening the queue at that build and version", async () => {
    await component(BOTH);
    const cell = links().find((each) =>
      each.getAttribute("href")?.includes("component_version=3.7"),
    );
    expect(cell?.textContent).toBe("3");
    expect(cell?.getAttribute("href")).toBe(
      "/products/sonic/code-findings?component=libnl&component_version=3.7&branch_or_tag=master&variant=arm&state=open",
    );
  });

  it("draws twelve weeks of code findings as a panel of their own beside the issues", async () => {
    await component(BOTH);
    expect(text()).toContain("Code findings · 12 weeks");
    expect(
      mount.host().querySelector('svg[aria-label^="Code findings not fixed from 4 to 3"]'),
    ).not.toBeNull();
    expect(mount.host().querySelector('svg[aria-label^="Open findings"]')).toBeNull();
    expect(mount.host().querySelector(".chart .mark title")?.textContent).toBe(
      "clang-tidy/default: new version from 18.1 to 19.1",
    );
    expect(hrefOf("Code findings over time →")).toBe(
      "/analytics/code-findings-over-time?branch_or_tag=master&variant=arm&beneath=libnl3&beneath_version=3.7&beneath_ecosystem=deb",
    );
  });

  it("names the code findings on the build itself as unplaced, with the way to the repositories", async () => {
    await component(BOTH, {
      [COUNTS]: {
        series: [
          {
            series: "semgrep/default",
            states: { ...STATES, open: 2 },
            waiting: 0,
            ruled: 0,
            unplaced: 2,
          },
        ],
        builds: [],
      },
    });
    expect(text()).toContain("2 of those open are unplaced");
    expect(hrefOf("Repositories →")).toBe("/products/sonic/repositories");
  });

  it("says in one line that code findings are read in another product, asking for none", async () => {
    const asked = await component(CODE_ELSEWHERE);
    expect(text()).toContain("You don't read code findings in sonic.");
    expect(text()).not.toContain("code findings open");
    // A count never asked for is never waited on.
    expect(mount.host().querySelector(".loading")).toBeNull();
    expect(text()).not.toContain("Code findings · 12 weeks");
    expect(asked).not.toContain(COUNTS);
    expect(asked).not.toContain(TREND);
  });

  it("counts and links by the name in the address, which may be a binary's", async () => {
    await component(BOTH, {}, "/products/sonic/components/libnl3");
    expect(hrefOf("3 code findings open")).toBe(
      "/products/sonic/code-findings?component=libnl3&state=open",
    );
    expect(hrefOf("1")).toBe(
      "/products/sonic/code-findings?component=libnl3&series=clang-tidy%2Fdefault&state=fixed",
    );
    const cell = links().find((each) =>
      each.getAttribute("href")?.includes("component_version=3.7"),
    );
    expect(cell?.getAttribute("href")).toBe(
      "/products/sonic/code-findings?component=libnl3&component_version=3.7&branch_or_tag=master&variant=arm&state=open",
    );
  });

  it("draws no build column while the counts have not answered, and the trend from its own read", async () => {
    await component(BOTH, {}, undefined, { [COUNTS]: 500 });
    expect(mount.host().querySelector("th[title^='Open code findings']")).toBeNull();
    expect(text()).toContain("The code findings could not be counted.");
    expect(text()).toContain("Code findings · 12 weeks");
  });

  it("says in one line that the trend is refused where the session lists the product as read", async () => {
    await component(BOTH, {}, undefined, { [TREND]: 403 });
    expect(text()).toContain("3 code findings open");
    expect(text()).toContain("You don't read code findings in sonic.");
    expect(mount.host().querySelector('svg[aria-label^="Code findings not fixed"]')).toBeNull();
  });

  it("reads a refused count in a product the session does not list as held elsewhere", async () => {
    const asked = await component(UNLISTED, {}, undefined, { [COUNTS]: 403 });
    expect(text()).toContain("You don't read code findings in sonic.");
    expect(text()).not.toContain("could not be counted");
    expect(mount.host().querySelector("th[title^='Open code findings']")).toBeNull();
    expect(text()).not.toContain("Code findings · 12 weeks");
    expect(asked).not.toContain(TREND);
  });

  it("draws the header unlinked where nothing is open", async () => {
    await component(BOTH, {
      [COUNTS]: {
        series: [{ series: "semgrep/default", states: STATES, waiting: 0, ruled: 0, unplaced: 0 }],
        builds: [],
      },
    });
    expect(text()).toContain("0 code findings open");
    expect(links().find((each) => each.textContent === "0 code findings open")).toBeUndefined();
  });

  it("draws the card on the build's root, which no build row ships, with its unplaced line", async () => {
    await component(
      BOTH,
      {
        "/v1/products/{product}/components/{component}": { items: [] },
        [COUNTS]: {
          series: [
            {
              series: "semgrep/default",
              states: { ...STATES, open: 2 },
              waiting: 0,
              ruled: 0,
              unplaced: 2,
            },
          ],
          builds: [],
        },
      },
      "/products/sonic/components/sonic-image",
    );
    expect(text()).toContain("Security testing");
    expect(text()).toContain("2 of those open are unplaced");
    expect(hrefOf("2 code findings open")).toBe(
      "/products/sonic/code-findings?component=sonic-image&state=open",
    );
    expect(text()).not.toContain("No build of this product ships it.");
  });

  it("says no build ships a name whose counts hold nothing", async () => {
    await component(BOTH, {
      "/v1/products/{product}/components/{component}": { items: [] },
      [COUNTS]: {
        series: [{ series: "semgrep/default", states: STATES, waiting: 0, ruled: 0, unplaced: 0 }],
        builds: [],
      },
    });
    expect(text()).toContain("No build of this product ships it.");
    expect(text()).not.toContain("Security testing");
  });

  it("draws nothing of security testing for a reader holding it nowhere, asking for none", async () => {
    const asked = await component(DEPENDENCIES);
    expect(text()).not.toContain("Security testing");
    expect(text()).not.toContain("code findings");
    expect(mount.host().querySelector("th[title^='Open code findings']")).toBeNull();
    expect(asked).not.toContain(COUNTS);
    expect(asked).not.toContain(TREND);
  });
});

describe("the dependency tree's code findings", () => {
  const BUILD = "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}";
  const node = (component: string, code?: { on: number; beneath: number }) => ({
    component,
    version: "1.0",
    findings: 0,
    beneath: 0,
    children: 0,
    ...(code ? { code_findings: code.on, code_findings_beneath: code.beneath } : {}),
  });

  async function tree(as: Who) {
    const asked: [string, unknown][] = [];
    serve((path, init) => {
      asked.push([path, init]);
      if (path === "/v1/session/me") return { data: as };
      if (path !== `${BUILD}/components`) return { data: { items: [], total: 0 } };
      const query = (init as { params: { query: Record<string, unknown> } }).params.query;
      return {
        data: {
          components: 2,
          edges: 1,
          root: {
            ...node("sonic", query.code_findings ? { on: 2, beneath: 5 } : undefined),
            children: 1,
          },
          items: [node("libnl", query.code_findings ? { on: 3, beneath: 3 } : undefined)],
        },
      };
    });
    mount.render(
      screen(
        <Dependencies />,
        "/products/sonic/branches-and-tags/master/variants/arm/dependencies",
        "/products/:product/branches-and-tags/:branch_or_tag/variants/:variant/dependencies",
      ),
    );
    await settle();
    return asked
      .filter(([path]) => path === `${BUILD}/components`)
      .map(([, init]) => (init as { params: { query: Record<string, unknown> } }).params.query);
  }

  it("counts what is open at and under each node, opening the queue beneath it", async () => {
    const asked = await tree(BOTH);
    expect(asked[0]).toEqual({ code_findings: true });
    const badges = Array.from(mount.host().querySelectorAll(".tree a.code"));
    expect(badges.map((each) => each.textContent)).toEqual(["5 code", "3 code"]);
    expect(badges[1]?.getAttribute("href")).toBe(
      "/products/sonic/code-findings?branch_or_tag=master&variant=arm&beneath=libnl&beneath_version=1.0&state=open",
    );
  });

  it("says on the root how many code findings are unplaced, with the way to the repositories", async () => {
    await tree(BOTH);
    expect(text()).toContain("2 open code findings are unplaced, on the build itself");
    expect(hrefOf("Repositories")).toBe("/products/sonic/repositories");
  });

  it("draws and asks for no code finding count for a reader holding them nowhere", async () => {
    const asked = await tree(DEPENDENCIES);
    expect(asked[0]).toEqual({});
    expect(mount.host().querySelector(".tree .code")).toBeNull();
    expect(text()).not.toContain("unplaced");
  });

  it("says in one line that code findings are read in another product, asking for none", async () => {
    const asked = await tree(CODE_ELSEWHERE);
    expect(asked[0]).toEqual({});
    expect(mount.host().querySelector(".tree .code")).toBeNull();
    expect(text()).toContain("You don't read code findings in sonic.");
  });
});

describe("the queue narrowed to a component", () => {
  async function queue(at: string) {
    const asked = serving(BOTH, {
      "/v1/products/{product}/code-findings": {
        items: [],
        total: 0,
        states: {},
        waiting: 0,
        ruled: 0,
        past_end_of_life: 0,
      },
    });
    mount.render(screen(<CodeFindings />, at, "/products/:product/code-findings"));
    await settle();
    return asked
      .filter(([path]) => path === "/v1/products/{product}/code-findings")
      .map(([, init]) => (init as { params: { query: Record<string, unknown> } }).params.query);
  }

  it("asks for a source package at a version and says so in its heading", async () => {
    const asked = await queue(
      "/products/sonic/code-findings?component=libnl&component_version=3.7",
    );
    expect(asked[0]).toMatchObject({ component: "libnl", component_version: "3.7" });
    expect(text()).toContain("on libnl 3.7");
  });

  it("asks for everything beneath a component of one build and says so in its heading", async () => {
    const asked = await queue(
      "/products/sonic/code-findings?branch_or_tag=master&variant=arm&beneath=libnl&beneath_version=1.0&beneath_ecosystem=deb",
    );
    expect(asked[0]).toMatchObject({
      branch_or_tag: "master",
      variant: "arm",
      beneath: "libnl",
      beneath_version: "1.0",
      beneath_ecosystem: "deb",
    });
    expect(text()).toContain("at or under libnl 1.0");
  });
});

describe("the component chooser", () => {
  const MATCHES = {
    items: [
      { product: "sonic", component: "libnl", issues: 4, code_findings: 2 },
      { product: "edge", component: "libnl", code_findings: 1 },
    ],
  };

  async function chooser(as: Who) {
    const asked = serving(as, { "/v1/components": MATCHES });
    mount.render(screen(<Components />, "/search/libnl", "/search/:term"));
    await settle();
    return asked
      .filter(([path]) => path === "/v1/components")
      .map(([, init]) => (init as { params: { query: Record<string, unknown> } }).params.query);
  }

  it("lists each match with both families' counts, each leading to the component screen", async () => {
    const asked = await chooser(BOTH);
    expect(asked[0]).toEqual({ q: "libnl" });
    const sonic = mount.host().querySelectorAll("tbody tr")[0];
    expect(Array.from(sonic?.querySelectorAll("td") ?? []).map((each) => each.textContent)).toEqual(
      ["libnl", "sonic", "4", "2"],
    );
    expect(sonic?.querySelector("a")?.getAttribute("href")).toBe(
      "/products/sonic/components/libnl",
    );
  });

  it("draws a dash, never a zero, for a family the reader does not read in that product", async () => {
    await chooser(CODE_ELSEWHERE);
    const [sonic, edge] = Array.from(mount.host().querySelectorAll("tbody tr"));
    const cells = (row?: Element) => Array.from(row?.querySelectorAll("td") ?? []);
    expect(cells(sonic)[3]?.textContent).toBe("—");
    expect(cells(sonic)[3]?.getAttribute("title")).toBe("You don't read code findings in sonic.");
    expect(cells(edge)[2]?.textContent).toBe("—");
    expect(cells(edge)[3]?.textContent).toBe("1");
  });

  it("draws a dash for a count the server left out in a product the session does not list", async () => {
    serving(UNLISTED, {
      "/v1/components": { items: [{ product: "sonic", component: "libnl", issues: 4 }] },
    });
    mount.render(screen(<Components />, "/search/libnl", "/search/:term"));
    await settle();
    const cells = Array.from(mount.host().querySelectorAll("tbody tr td"));
    expect(cells[2]?.textContent).toBe("4");
    expect(cells[3]?.textContent).toBe("—");
    expect(cells[3]?.getAttribute("title")).toBe("You don't read code findings in sonic.");
  });

  it("offers the findings list's search for the same term", async () => {
    await chooser(BOTH);
    expect(hrefOf("Search the findings list instead")).toBe("/findings?q=libnl");
  });
});
