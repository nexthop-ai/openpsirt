import { describe, expect, it } from "vitest";
import { called, reaches, ROLES, wouldReachNothing } from "./roles";

describe("the roles as somebody granting one reads them", () => {
  it("gives every role a label that is not its own token", () => {
    // The defect a justification shown in words fixed for justifications, in
    // the other place a vocabulary is chosen from: what is granted here
    // decides who can read findings nobody has announced.
    for (const each of ROLES) {
      expect(each.label).not.toBe(each.role);
      expect(each.means.length).toBeGreaterThan(10);
    }
  });

  it("shows a role it does not know rather than nothing", () => {
    expect(called("public-read")).toBe("Read, disclosed");
    expect(called("something-new")).toBe("something-new");
    expect(called()).toBe("");
  });

  it("knows which roles reach nothing on their own", () => {
    expect(reaches("approver")).toBe(false);
    expect(reaches("assigner")).toBe(false);
    expect(reaches("public-read")).toBe(true);
    // An unknown role is assumed to grant something rather than being
    // reported as an empty one: warning about a role we cannot describe would
    // be inventing a fact.
    expect(reaches("something-new")).toBe(true);
  });
});

describe("granting somebody an empty tool", () => {
  it("says so when a capability lands where they read nothing", () => {
    expect(wouldReachNothing("approver", [])).toBe(true);
    expect(wouldReachNothing("assigner", [{ role: "approver" }])).toBe(true);
  });

  it("says nothing when they can already read the product", () => {
    expect(wouldReachNothing("approver", [{ role: "public-read" }])).toBe(false);
    expect(wouldReachNothing("approver", [{ role: "private-triage" }])).toBe(false);
  });

  it("says nothing about a role that reaches on its own", () => {
    expect(wouldReachNothing("public-read", [])).toBe(false);
  });

  it("does not count a grant that has been withdrawn", () => {
    // Saying somebody reads a product because they used to is the same
    // mistake as not warning at all, in the direction that hides it.
    expect(wouldReachNothing("approver", [{ role: "public-read", effective: false }])).toBe(true);
  });
});
