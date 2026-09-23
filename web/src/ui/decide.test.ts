// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { draftKeyFor, mayMitigate, mustMitigate, type At } from "./Decide";

const at: At = {
  product: "sonic",
  stream: "master",
  variant: "broadcom",
  vulnerability: "CVE-2026-1",
  component: "stdlib",
  version: "go1.25.6",
};

// The key decides which reasoning comes back into which form, and the text it
// carries is what a second person is asked to agree to. Anything it does not
// name is something two different judgments can share a draft across.
describe("where a decision's reasoning is kept", () => {
  it("names every part of what is being decided", () => {
    expect(draftKeyFor(at)).toBe("decide:sonic:master:broadcom:CVE-2026-1:stdlib:go1.25.6");
  });

  it("does not share a draft between two versions of one component", () => {
    // A build ships one name at more than one version often enough that this
    // is the ordinary case, not a corner: text typed about `go1.25.6` came
    // back pre-filled against `go1.24.9`, which is different code at a
    // different number of places.
    expect(draftKeyFor({ ...at, version: "go1.24.9" })).not.toBe(draftKeyFor(at));
  });

  it("does not share a draft across builds of one product", () => {
    expect(draftKeyFor({ ...at, variant: "mellanox" })).not.toBe(draftKeyFor(at));
    expect(draftKeyFor({ ...at, stream: "202411" })).not.toBe(draftKeyFor(at));
  });

  it("does not share a draft across issues or components", () => {
    expect(draftKeyFor({ ...at, vulnerability: "CVE-2026-2" })).not.toBe(draftKeyFor(at));
    expect(draftKeyFor({ ...at, component: "openssl" })).not.toBe(draftKeyFor(at));
  });

  it("gives a component shipped with no version a key of its own", () => {
    expect(draftKeyFor({ ...at, version: "" })).toBe(
      "decide:sonic:master:broadcom:CVE-2026-1:stdlib:",
    );
  });
});

describe("which outcomes may say what a holder can do", () => {
  it("requires it where the claim is that something already stops it", () => {
    expect(mustMitigate("not-applicable", "inline_mitigations_already_exist")).toBe(true);
    expect(mayMitigate("not-applicable", "inline_mitigations_already_exist")).toBe(true);
  });

  it("offers it on will-not-fix without requiring it", () => {
    // The half that reaches a customer. A flaw that is staying is closed by no
    // scan and issued in no advisory, so the published document's affected
    // statement is the only way it is ever said — and that statement is only
    // published where there is something to do instead.
    expect(mayMitigate("wont-fix", "")).toBe(true);
    expect(mustMitigate("wont-fix", "")).toBe(false);
  });

  it("offers it nowhere else", () => {
    // Every other outcome is a claim about priority rather than a claim that
    // something is handled, and the server refuses a mitigation on one.
    for (const outcome of ["affected", "deferred", "already-fixed", "upgrade-needed"]) {
      expect(mayMitigate(outcome, "")).toBe(false);
    }
    // Not applicable for one of the other recognized reasons is a claim about
    // code, which lapses when the code moves and needs nothing said about it.
    expect(mayMitigate("not-applicable", "vulnerable_code_not_present")).toBe(false);
  });
});
