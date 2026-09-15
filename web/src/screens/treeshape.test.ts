import { describe, expect, it } from "vitest";
import { keyOf, partsOf } from "./treeshape";

// The key is what every piece of the tree's state is held against: what is
// open, what has been drawn already, what sits under each node, and which
// three values the request for a node's children carries. Keyed on the name
// alone, a component the build ships twice could not be opened at all — the
// request asking for its children named something that means two things, and
// the server refuses that rather than guessing.
describe("what tells one component from another in the tree", () => {
  it("tells two versions of one name apart", () => {
    expect(keyOf({ component: "openssl", version: "3.0.2" })).not.toBe(
      keyOf({ component: "openssl", version: "1.1.1" }),
    );
  });

  it("tells two kinds of package with one name and one version apart", () => {
    expect(keyOf({ component: "curl", version: "8.14.1", ecosystem: "deb" })).not.toBe(
      keyOf({ component: "curl", version: "8.14.1", ecosystem: "apk" }),
    );
  });

  it("gives the same component the same key", () => {
    expect(keyOf({ component: "curl", version: "8.14.1", ecosystem: "deb" })).toBe(
      keyOf({ component: "curl", version: "8.14.1", ecosystem: "deb" }),
    );
  });

  it("reads back the three values a request needs", () => {
    const node = { component: "curl", version: "8.14.1", ecosystem: "deb" };
    expect(partsOf(keyOf(node))).toEqual(node);
  });

  it("reads back what a node states nothing for", () => {
    expect(partsOf(keyOf({ component: "sonic-broadcom" }))).toEqual({
      component: "sonic-broadcom",
      version: "",
      ecosystem: "",
    });
  });
});
