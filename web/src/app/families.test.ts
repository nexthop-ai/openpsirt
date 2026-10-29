// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { counted, heldLine, holding, readsNothing } from "./families";
import type { Who } from "./session";
import { reaching, readingDependencies } from "../test/reach";

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

describe("how a reader holds a family of findings", () => {
  it("leaves out a family the reader reads in no product", () => {
    const at = holding(
      who([reaching("sonic", { may_see: true, reads_security_testing: true })]),
      "dependency",
      "sonic",
    );
    expect(at.held).toBe("nowhere");
    expect(counted(at)).toBe(false);
  });

  it("names the product a family is read elsewhere than, and draws no count", () => {
    const at = holding(
      who([readingDependencies("edge"), reaching("sonic", { may_see: true })]),
      "dependency",
      "sonic",
    );
    expect(at.held).toBe("elsewhere");
    expect(counted(at)).toBe(false);
    expect(heldLine(at)).toBe("You don't read dependency findings in sonic.");
  });

  it("counts a family read whole here as a real zero, with nothing said beside it", () => {
    const at = holding(who([readingDependencies("sonic")]), "dependency", "SONiC");
    expect(at.held).toBe("here");
    expect(counted(at)).toBe(true);
    expect(heldLine(at)).toBe("");
  });

  it("says a count is of disclosed findings where only those are read here", () => {
    const at = holding(
      who([reaching("sonic", { may_see: true, reads_public: true })]),
      "dependency",
      "sonic",
    );
    expect(at.held).toBe("disclosed");
    expect(counted(at)).toBe(true);
    expect(heldLine(at)).toBe("Counting disclosed findings, the ones you read here.");
  });

  it("names the products read disclosed only, across products where others are read whole", () => {
    const at = holding(
      who([readingDependencies("edge"), reaching("sonic", { may_see: true, reads_public: true })]),
      "dependency",
    );
    expect(heldLine(at)).toBe("Counting only disclosed findings in sonic.");
  });

  it("gives code findings no disclosed half", () => {
    const at = holding(
      who([reaching("sonic", { may_see: true, reads_public: true, reads_security_testing: true })]),
      "code",
      "sonic",
    );
    expect(at.held).toBe("here");
  });

  it("names code findings read in another product", () => {
    const at = holding(
      who([reaching("edge", { may_see: true, reads_security_testing: true })]),
      "code",
      "sonic",
    );
    expect(heldLine(at)).toBe("You don't read code findings in sonic.");
  });

  it("finds an auditor reading no finding in any product", () => {
    expect(readsNothing(who([reaching("sonic")], { audits: true }))).toBe(true);
    expect(readsNothing(who([readingDependencies("sonic")], { audits: true }))).toBe(false);
    expect(
      readsNothing(who([reaching("sonic", { may_see: true, reads_security_testing: true })])),
    ).toBe(false);
  });

  it("holds every figure until the session answers", () => {
    expect(counted(holding(undefined, "dependency", "sonic"))).toBe(true);
    expect(readsNothing(undefined)).toBe(false);
  });
});
