// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import * as routes from "./routes";
import { findingAt } from "./routes";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { table, unrouted } from "../../scripts/addresses.mjs";

// Awkward on purpose: a separator of every kind an address has, so a part
// left unescaped moves a segment or starts a query and fails the match.
const odd = "a/b c?d#e&f=g%";
const build = { product: odd, stream: odd, variant: odd };

// One call of every builder, with every part it takes. The set of names is
// held against what the module exports, so a builder added without a sample
// fails here rather than going unchecked.
const SAMPLES: Record<string, () => string[]> = {
  productAt: () => [routes.productAt(odd)],
  streamsAt: () => [routes.streamsAt(odd)],
  streamAt: () => [routes.streamAt(odd, odd)],
  variantsAt: () => [routes.variantsAt(odd)],
  comparisonAt: () => [routes.comparisonAt(odd), routes.comparisonAt(odd, { from: odd, to: odd })],
  inventoryComparisonAt: () => [routes.inventoryComparisonAt(odd, { from: odd, to: odd })],
  inboxAt: () => [routes.inboxAt(odd), routes.inboxAt(odd, true)],
  inboxReportAt: () => [routes.inboxReportAt(odd, odd)],
  componentAt: () => [routes.componentAt(odd, odd), routes.componentAt(odd, odd, odd, build)],
  allFindingsAt: () => [routes.allFindingsAt(), routes.allFindingsAt({ q: odd })],
  productFindingsAt: () => [routes.productFindingsAt(odd, { q: odd })],
  buildFindingsAt: () => [routes.buildFindingsAt(build, { q: odd })],
  findingAt: () => [
    routes.findingAt(build, { vulnerability: odd, component: odd }),
    routes.findingAt(
      build,
      { vulnerability: odd, component: odd, version: odd, ecosystem: odd, namespace: odd },
      odd,
      odd,
    ),
  ],
  treeAt: () => [routes.treeAt(build), routes.treeAt(build, { at: odd, path: odd })],
  decideAt: () => [routes.decideAt(build, odd, { version: odd, ecosystem: odd, namespace: odd })],
  inventoriesAt: () => [routes.inventoriesAt(build)],
  inventoryChangesAt: () => [routes.inventoryChangesAt(build, 7)],
  runAt: () => [routes.runAt(build, 7)],
  upgradesAt: () => [routes.upgradesAt(build)],
  matchCoverageAt: () => [routes.matchCoverageAt(build)],
  vexAt: () => [routes.vexAt(build)],
  sameScreenAt: () => [routes.sameScreenAt(build, ""), routes.sameScreenAt(build, "components")],
  sameProductScreenAt: () => [routes.sameProductScreenAt(odd, "/inbox")],
  claimAt: () => [routes.claimAt(7)],
  decisionAt: () => [routes.decisionAt(7)],
  issueAt: () => [routes.issueAt(odd)],
  personAt: () => [routes.personAt(odd)],
  advisoryAt: () => [routes.advisoryAt(odd)],
  reportAt: () => [routes.reportAt(odd), routes.reportAt(odd, { days: "90" })],
  settingsAt: () => [routes.settingsAt(odd)],
  reviewQueueAt: () => [routes.reviewQueueAt(), routes.reviewQueueAt({ product: odd, mine: true })],
  recordAt: () => [routes.recordAt(odd, odd)],
  auditAt: () => [routes.auditAt({ alone: "true", outcome: odd })],
  refiled: () => [routes.refiled(routes.issueAt("CVE-1"), "CVE-1", odd)],
};

describe("every address the interface builds", () => {
  it("has a sample here for every builder, and a builder for every sample", () => {
    const builders = Object.entries(routes)
      .filter(([, value]) => typeof value === "function")
      .map(([name]) => name)
      .sort();
    expect(
      builders.length,
      "routes.ts exports no builder, so this checked nothing",
    ).toBeGreaterThan(0);
    expect(Object.keys(SAMPLES).sort()).toEqual(builders);
  });

  it("is a route the router answers, asking only for what the screen reads", () => {
    const known = table();
    let checked = 0;
    for (const [name, make] of Object.entries(SAMPLES)) {
      for (const address of make()) {
        checked++;
        expect(unrouted(known, address), `${name} built ${address}`).toBe("");
      }
    }
    expect(checked).toBeGreaterThan(0);
  });

  it("is each pattern of the router, with every part in place", () => {
    for (const [name, pattern] of Object.entries(routes.ROUTES)) {
      expect(pattern, name).toBe(table()[name].path);
    }
  });
});

describe("where a row opens", () => {
  it("carries the version, because a component name is not unique in a build", () => {
    expect(
      findingAt(
        { product: "sonic", stream: "main", variant: "broadcom" },
        {
          vulnerability: "CVE-2024-1",
          component: "zlib",
          version: "1.2.11",
        },
      ),
    ).toBe(
      "/products/sonic/streams/main/variants/broadcom/findings/CVE-2024-1/components/zlib?version=1.2.11",
    );
  });

  it("carries the list as one value, so a filter added to the list needs nothing here", () => {
    const at = findingAt(
      { product: "sonic", stream: "main", variant: "broadcom" },
      { vulnerability: "CVE-2024-1", component: "zlib", version: "" },
      "state=undecided&offset=50",
    );
    const asked = new URLSearchParams(at.split("?")[1]);
    expect(asked.get("from")).toBe("state=undecided&offset=50");
    expect(asked.has("version")).toBe(false);
  });

  // A rule prepares a claim and a person proposes it, so what travels to the
  // finding is which filter was picked. The name rather than the words: the
  // filter decides what it says, and a copy in the address would go stale the
  // moment somebody saved over the name.
  it("names the saved filter a prepared claim comes from", () => {
    const at = findingAt(
      { product: "sonic", stream: "main", variant: "broadcom" },
      { vulnerability: "CVE-2024-1", component: "zlib", version: "" },
      "state=undecided",
      "overdue kernel",
    );
    expect(new URLSearchParams(at.split("?")[1]).get("rule")).toBe("overdue kernel");
  });

  it("says nothing about a rule where no filter prepares one", () => {
    const at = findingAt(
      { product: "sonic", stream: "main", variant: "broadcom" },
      { vulnerability: "CVE-2024-1", component: "zlib", version: "" },
      "",
    );
    expect(new URLSearchParams(at.split("?")[1]).has("rule")).toBe(false);
  });
});
