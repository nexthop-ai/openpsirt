import { describe, expect, it } from "vitest";
import { CATALOG, leadsTo, reportAt, scopeWords } from "./catalog";
import { PAGES } from "./Report";

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
