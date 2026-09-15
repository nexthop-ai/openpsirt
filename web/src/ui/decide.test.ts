import { describe, expect, it } from "vitest";
import { draftKeyFor, type At } from "./Decide";

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
