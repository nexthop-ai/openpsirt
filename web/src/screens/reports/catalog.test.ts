// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { GROUPS, ON_SCREENS, leadsTo, scopeWords } from "./catalog";
import { PAGES } from "./Report";
import { matchPath } from "react-router-dom";
import { ROUTES as NAMED } from "../../app/routes";

// The router's patterns as a list, because what is asked here is whether an
// address matches any of them rather than which.
const ROUTES = Object.values(NAMED);

// Every entry the catalog screen draws, in either of its two lists.
const CATALOG = [...GROUPS.flatMap((group) => group.reports), ...ON_SCREENS];

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

  // Two names over one screen read as two reports, and somebody opens both to
  // find the same page.
  it("lists each address once", () => {
    const whole = { product: "sonic", stream: "master", variant: "broadcom" };
    const addresses = CATALOG.map((report) => leadsTo(report, whole).to);
    expect(addresses.length).toBeGreaterThan(0);
    expect(new Set(addresses).size).toBe(addresses.length);
  });

  it("names each entry once", () => {
    const names = CATALOG.map((report) => report.name);
    expect(new Set(names).size).toBe(names.length);
  });
});

describe("where a catalog row leads", () => {
  it("addresses a report the catalog owns by its name", () => {
    const overview = CATALOG.find((report) => report.slug === "program-overview");
    expect(overview).toBeDefined();
    expect(leadsTo(overview!, {})).toEqual({ to: "/reports/program-overview", needs: null });
  });

  it("says what to pick rather than leading nowhere", () => {
    const compare = CATALOG.find((report) => report.name === "Release comparison")!;
    expect(leadsTo(compare, {})).toEqual({ to: null, needs: "product" });
    expect(leadsTo(compare, { product: "sonic" })).toEqual({
      to: "/products/sonic/comparison",
      needs: null,
    });
  });

  it("asks for a whole build where the screen it points at needs one", () => {
    const upgrades = CATALOG.find((report) => report.name === "Pending upgrades")!;
    // A product alone is not enough: the screen exists for one build and no
    // other, so an entry into it on a partial scope would open on a selection
    // that means nothing.
    expect(leadsTo(upgrades, { product: "sonic" })).toEqual({ to: null, needs: "build" });
    expect(leadsTo(upgrades, { product: "sonic", stream: "master" }).needs).toBe("build");
    const whole = { product: "sonic", stream: "master", variant: "broadcom" };
    expect(leadsTo(upgrades, whole).to).toBe(
      "/products/sonic/streams/master/variants/broadcom/pending-upgrades",
    );
  });

  it("leads somewhere that needs nothing picked", () => {
    const disclosing = CATALOG.find((report) => report.name === "Disclosing")!;
    expect(leadsTo(disclosing, {}).to).toBe("/disclosing");
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
  // Entries that build an address from a scope by hand are pinned against the
  // router here; the slug reports are pinned by the test above. An address
  // that matches no route redirects to the front page, so a report that leads
  // nowhere looks exactly like one nobody clicked.
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
