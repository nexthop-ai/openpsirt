import { describe, expect, it } from "vitest";
import { buildKey, fromBuildKey } from "./builds";

// The key identifies a build in a checkbox set and in two React lists. Two
// builds sharing one there means two rows sharing reconciliation state: which
// option a select holds, which row a table highlights — and, in the checkbox
// set, which builds a bump is recorded against.
describe("what names one build", () => {
  it("keeps two builds apart whose names run together", () => {
    // `main` + `arm` + `64` and `main` + `arm64` + nothing are two builds and
    // concatenate to one string. Both of the keys that omitted the separator
    // produced exactly this collision.
    expect(buildKey({ stream: "main", variant: "arm" }, "64")).not.toBe(
      buildKey({ stream: "main", variant: "arm64" }),
    );
  });

  it("keeps the version rather than appending the word undefined", () => {
    // `+ undefined` appends the text, which is how a version went missing
    // from a key that looked like it carried one.
    expect(buildKey({ stream: "main", variant: "arm" })).not.toContain("undefined");
    expect(fromBuildKey(buildKey({ stream: "main", variant: "arm" })).version).toBe("");
  });

  it("reads back the three names it was given", () => {
    expect(fromBuildKey(buildKey({ stream: "202411", variant: "broadcom" }, "8.14.1"))).toEqual({
      stream: "202411",
      variant: "broadcom",
      version: "8.14.1",
    });
  });

  it("tells two versions of one build apart", () => {
    const build = { stream: "master", variant: "broadcom" };
    expect(buildKey(build, "8.14.1")).not.toBe(buildKey(build, "8.15.0"));
  });

  it("gives the same build the same key", () => {
    expect(buildKey({ stream: "master", variant: "broadcom" }, "8.14.1")).toBe(
      buildKey({ stream: "master", variant: "broadcom" }, "8.14.1"),
    );
  });
});
