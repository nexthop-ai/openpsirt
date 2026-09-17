import { describe, expect, it } from "vitest";
import { CATALOG, leadsTo, reportAt, scopeWords } from "./catalog";
import { PAGES } from "./Report";
import { matchPath } from "react-router-dom";
import { ROUTES as NAMED } from "../../app/App";

// The router's patterns as a list, because what is asked here is whether an
// address matches any of them rather than which.
const ROUTES = Object.values(NAMED);

describe("the catalog and the addresses that answer it", () => {
  // A name in the list with nothing behind it is a link that goes nowhere,
  // and a page nothing names is a report nobody finds. Both are silent.
  it("names a page for every report it owns, and owns every page", () => {
    const owned = CATALOG.filter((report) => report.slug).map((report) => report.slug);
    expect([...owned].sort()).toEqual(Object.keys(PAGES).sort());
  });

  it("gives every entry somewhere to lead", () => {
    for (const report of CATALOG) {
      expect(Boolean(report.slug) || Boolean(report.to)).toBe(true);
    }
  });
});

describe("where a catalog row leads", () => {
  it("addresses a report the catalog owns by its name", () => {
    const overview = reportAt("program-overview");
    expect(overview).toBeDefined();
    expect(leadsTo(overview!, {})).toEqual({ to: "/reports/program-overview", why: null });
  });

  it("says what to pick rather than leading nowhere", () => {
    const compare = CATALOG.find((report) => report.name === "Release comparison")!;
    expect(leadsTo(compare, {}).to).toBeNull();
    expect(leadsTo(compare, {}).why).toContain("product");
    expect(leadsTo(compare, { product: "sonic" }).to).toBe("/products/sonic/comparison");
  });

  it("asks for a whole build where the screen it points at needs one", () => {
    const upgrades = CATALOG.find((report) => report.name === "Upgrade plan status")!;
    // A product alone is not enough: the screen exists for one build and no
    // other, so an entry into it on a partial scope would open on a selection
    // that means nothing.
    expect(leadsTo(upgrades, { product: "sonic" }).to).toBeNull();
    expect(leadsTo(upgrades, { product: "sonic", stream: "master" }).to).toBeNull();
    const whole = { product: "sonic", stream: "master", variant: "broadcom" };
    expect(leadsTo(upgrades, whole).to).toBe(
      "/products/sonic/streams/master/variants/broadcom/pending-upgrades",
    );
  });

  it("leads somewhere that needs nothing picked", () => {
    const disclosing = CATALOG.find((report) => report.name === "Embargo and disclosure")!;
    expect(leadsTo(disclosing, {}).to).toBe("/disclosing");
  });

  it("holds no name the catalog does not", () => {
    expect(reportAt("nothing-of-the-sort")).toBeUndefined();
  });
});

describe("what a sheet says it was asked of", () => {
  // A printed figure narrowed to one variant and one spanning a program read
  // the same on paper without it.
  it("names every level, and says so where one is not picked", () => {
    expect(scopeWords({})).toBe("Every product · every branch · every variant");
    expect(scopeWords({ product: "sonic", stream: "master" })).toBe(
      "sonic · master · every variant",
    );
  });
});

describe("every address a report leads to", () => {
  // Eight entries build an address from a scope by hand, and nothing pinned
  // one of them against the router. An address that matches no route
  // redirects to the front page, so a report that leads nowhere looks exactly
  // like one nobody clicked — the test above pins the seven slug reports
  // against the pages behind them and says nothing about these.
  const anywhere = { product: "sonic", stream: "master", variant: "broadcom" };

  it("resolves to a screen", () => {
    const leading = CATALOG.filter((report) => report.to);
    expect(leading.length).toBeGreaterThan(0);
    for (const report of leading) {
      const address = report.to?.(anywhere) ?? "";
      const [path] = address.split("?");
      const hit = ROUTES.some((pattern) => matchPath(pattern, path ?? "") !== null);
      expect(hit, `${report.name} leads to ${address}, which matches no route`).toBe(true);
    }
  });

  it("resolves for a slug report too, through the reports page", () => {
    // A report with a page of its own is reached at /reports/<slug>, which is
    // the route the reports screen renders behind.
    const slugged = CATALOG.filter((each) => each.slug);
    expect(slugged.length).toBeGreaterThan(0);
    for (const report of slugged) {
      const address = `/reports/${report.slug}`;
      expect(
        ROUTES.some((pattern) => matchPath(pattern, address) !== null),
        `${report.name} leads to ${address}, which matches no route`,
      ).toBe(true);
    }
  });
});

describe("what a catalog row carries with it", () => {
  // The record reads its narrowing from the address rather than from the
  // picker, so an entry that drops the selection opens every product the
  // reader can see from a page scoped to one — a different population under
  // the same name.
  it("carries the product into the record", () => {
    const exception = CATALOG.find((report) => report.name === "The exception report")!;
    const wide = leadsTo(exception, {}).to!;
    expect(wide).toContain("alone=true");
    expect(wide).not.toContain("product=");

    const narrowed = leadsTo(exception, { product: "sonic" }).to!;
    expect(narrowed).toContain("product=sonic");
    // And the filters the entry exists for are still on it.
    expect(narrowed).toContain("alone=true");
    expect(narrowed).toContain("outcome=not-applicable");
  });

  it("carries it into an address that has no query of its own yet", () => {
    const changes = CATALOG.find((report) => report.name === "Administrative changes")!;
    expect(leadsTo(changes, { product: "sonic" }).to).toBe("/audit?product=sonic");
    expect(leadsTo(changes, {}).to).toBe("/audit");
  });
});
