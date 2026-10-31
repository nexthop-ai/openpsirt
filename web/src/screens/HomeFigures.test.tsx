// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { Home, figuresShown } from "./Home";
import { merged } from "./HomeSecurityTesting";
import type { CodeFindingTrend } from "../api/codeFindings";
import type { Who } from "../app/session";
import { mounted, screen, serve, settle } from "../test/mount";
import { reaching, readingDependencies } from "../test/reach";

const mount = mounted();

const person = (reach: Who["reach"]) =>
  ({
    identity: "ana",
    name: "Ana",
    admin: false,
    kind: "person",
    reach,
    outcomes: [],
  }) as unknown as Who;

const both = (product: string) =>
  reaching(product, {
    may_see: true,
    reads_public: true,
    reads_private: true,
    reads_security_testing: true,
  });
const codeOnly = (product: string) =>
  reaching(product, { may_see: true, reads_security_testing: true });

// A twelve-week trend whose last week opened three and fixed one.
function trendOf(notFixed: number, marker?: string): CodeFindingTrend {
  return {
    points: Array.from({ length: 12 }, (_, i) => ({
      at: `2026-08-${String(i + 10).padStart(2, "0")}`,
      not_fixed: notFixed,
      opened: i === 11 ? 3 : 0,
      fixed: i === 11 ? 1 : 0,
      by_tier: { "memory-safety": notFixed, input: 0, resource: 0, other: 0 },
      by_series: {},
      by_method: { sast: notFixed },
    })),
    markers: marker
      ? [{ at: "2026-08-20", series: marker, change: "tool-version", builds: 1 }]
      : [],
    no_longer_detected: 0,
  };
}

// The home page drawn for a reader at an address, the server answering the
// security testing reads with figures and everything else with nothing.
async function home(who: Who, at = "/", quiet = true) {
  const asked: string[] = [];
  serve((path) => {
    asked.push(path);
    if (path === "/v1/code-findings" || path === "/v1/products/{product}/code-findings") {
      return {
        data: { items: [], total: 4, states: { open: 6, "no-longer-detected": 2 }, waiting: 2 },
      };
    }
    if (path === "/v1/products/{product}/code-finding-trend") return { data: trendOf(5) };
    if (path === "/v1/products/{product}/code-finding-time-to-judge") {
      return { data: { waiting: [], no_longer_detected: 2, oldest: "2026-10-01" } };
    }
    if (path === "/v1/products/{product}/analysis-coverage") {
      return {
        data: {
          quiet: quiet ? 1 : 0,
          items: [
            {
              series: "clang-tidy",
              branch_or_tag: "main",
              variant: "arm",
              quiet,
              last_arrived: "2026-10-20T00:00:00Z",
            },
          ],
        },
      };
    }
    return { data: { items: [], total: 0 } };
  });
  mount.render(screen(<Home who={who} />, at));
  await settle();
  return asked;
}

const tabs = () =>
  [...mount.host().querySelectorAll('[role="tab"]')].map((each) => [
    each.textContent,
    each.getAttribute("aria-selected"),
    each.getAttribute("href"),
  ]);
const tile = (label: string) =>
  [...mount.host().querySelectorAll("button.kpi")].find((each) =>
    each.querySelector(".l")?.textContent?.trim().startsWith(label),
  );

describe("which figures home draws", () => {
  it("offers both families as tabs to a reader of both, Dependencies first", () => {
    expect(figuresShown(person([both("sonic")]), null)).toEqual({
      figures: "dependencies",
      strip: true,
    });
  });

  it("opens the tab the address names", () => {
    expect(figuresShown(person([both("sonic")]), "security-testing")).toEqual({
      figures: "security-testing",
      strip: true,
    });
  });

  it("offers the tabs to a reader of each family in a different product", () => {
    expect(figuresShown(person([readingDependencies("edge"), codeOnly("sonic")]), null)).toEqual({
      figures: "dependencies",
      strip: true,
    });
  });

  it("draws a reader of dependency findings alone their figures with no strip, whatever the address", () => {
    expect(figuresShown(person([readingDependencies("sonic")]), "security-testing")).toEqual({
      figures: "dependencies",
      strip: false,
    });
  });

  it("draws a reader of code findings alone theirs with no strip", () => {
    expect(figuresShown(person([codeOnly("sonic")]), null)).toEqual({
      figures: "security-testing",
      strip: false,
    });
  });

  it("draws no figures for a reader of neither", () => {
    expect(figuresShown(person([reaching("sonic")]), null)).toEqual({
      figures: undefined,
      strip: false,
    });
  });
});

describe("the home tab strip", () => {
  it("is drawn for a reader of both, with the tab in the address", async () => {
    await home(person([both("sonic")]));
    expect(tabs()).toEqual([
      ["Dependencies", "true", "/"],
      ["Security testing", "false", "/?figures=security-testing"],
    ]);
    expect(tile("Open issues")).toBeDefined();
    expect(tile("Waiting for a judgment")).toBeUndefined();
  });

  it("opens Security testing where the address names it", async () => {
    await home(person([both("sonic")]), "/?figures=security-testing");
    expect(tabs().map(([label, selected]) => [label, selected])).toEqual([
      ["Dependencies", "false"],
      ["Security testing", "true"],
    ]);
    expect(tile("Waiting for a judgment")).toBeDefined();
    expect(tile("Open issues")).toBeUndefined();
  });

  it("is not drawn for a reader of code findings alone, who sees their figures", async () => {
    await home(person([codeOnly("sonic")]));
    expect(tabs()).toEqual([]);
    expect(tile("Waiting for a judgment")).toBeDefined();
  });

  it("is not drawn for a reader of dependency findings alone, who sees theirs", async () => {
    const asked = await home(person([readingDependencies("sonic")]), "/?figures=security-testing");
    expect(tabs()).toEqual([]);
    expect(tile("Open issues")).toBeDefined();
    expect(asked).not.toContain("/v1/products/{product}/code-finding-trend");
  });

  it("keeps the work above the strip for every reader", async () => {
    await home(person([both("sonic")]));
    const host = mount.host();
    const strip = host.querySelector('[role="tablist"]');
    const pending = [...host.querySelectorAll("button.kpi")].find((each) =>
      each.textContent?.includes("Pending your approval"),
    );
    expect(strip && pending).toBeTruthy();
    expect(
      pending && strip && pending.compareDocumentPosition(strip) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });
});

describe("the Security testing figures", () => {
  it("count the queue, this week and the quiet series at every product read", async () => {
    const asked = await home(person([codeOnly("sonic"), codeOnly("edge")]));
    expect(mount.host().textContent).toContain("Open · 2 products");
    expect(tile("Open")?.querySelector(".n")?.textContent).toBe("6");
    expect(tile("Waiting for a judgment")?.querySelector(".n")?.textContent).toBe("4");
    expect(tile("This week")?.querySelector(".n")?.textContent).toBe("+6 −2");
    expect(tile("No longer detected")?.querySelector(".n")?.textContent).toBe("2");
    expect(tile("Analyzers gone quiet")?.textContent).toContain("sonic clang-tidy on main · arm");
    expect(
      asked.filter((path) => path === "/v1/products/{product}/code-finding-trend"),
    ).toHaveLength(2);
  });

  it("open the queue they count, narrowed to the product picked", async () => {
    await home(person([codeOnly("sonic")]), "/products/sonic");
    expect(tile("Open")?.textContent).toContain("Open · sonic");
    expect(tile("Analyzers gone quiet")?.textContent).toContain("clang-tidy on main · arm");
    expect(tile("Analyzers gone quiet")?.textContent).not.toContain("sonic clang-tidy");
  });

  it("say so in one line where the reader reads code findings in another product", async () => {
    const asked = await home(
      person([both("edge"), readingDependencies("sonic")]),
      "/products/sonic?figures=security-testing",
    );
    expect(mount.host().textContent).toContain("You don't read code findings in sonic.");
    expect(tile("Waiting for a judgment")).toBeUndefined();
    expect(asked).not.toContain("/v1/products/{product}/code-finding-trend");
  });

  it("say no analyzer has run where no series has, rather than drawing zeros", async () => {
    serve((path) =>
      path === "/v1/products/{product}/analysis-coverage"
        ? { data: { quiet: 0, items: [] } }
        : { data: { items: [], total: 0, states: {}, points: [], markers: [] } },
    );
    mount.render(screen(<Home who={person([codeOnly("sonic")])} />, "/"));
    await settle();
    expect(mount.host().textContent).toContain("No analyzer has run here.");
    expect(tile("Open")).toBeUndefined();
  });

  it("name the last analyzer run in the status panel", async () => {
    await home(person([codeOnly("sonic")]), "/", false);
    expect(mount.host().textContent).toContain("Last analyzer run received");
    expect(tile("Analyzers gone quiet")?.querySelector(".n")?.textContent).toBe("0");
  });
});

describe("a trend over several products", () => {
  it("adds each week's counts and names each marker's product", () => {
    const one = merged(["sonic", "edge"], [trendOf(5, "clang"), trendOf(2)], true);
    expect(one?.points[11]).toMatchObject({ not_fixed: 7, opened: 6, fixed: 2 });
    expect(one?.points[11]?.by_tier["memory-safety"]).toBe(7);
    expect(one?.markers.map((m) => m.series)).toEqual(["sonic clang"]);
  });

  it("is unread until every product's trend is", () => {
    expect(merged(["sonic", "edge"], [trendOf(5), undefined], true)).toBeUndefined();
  });
});
