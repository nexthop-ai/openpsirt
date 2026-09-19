import { beforeEach, describe, expect, it } from "vitest";
import { findingsPath, needsBuild, onFindings, remember, rescoped, scopeQuery } from "./scope";

const BUILD = "/products/sonic/streams/master/variants/broadcom";

describe("which screens need a whole build", () => {
  it("keeps the five that are about a way down", () => {
    // Each of these exists for one build and no other, because there is no
    // dependency graph across branches.
    expect(needsBuild(`${BUILD}/components`)).toBe(true);
    expect(needsBuild(`${BUILD}/components/libnl-3-200/decide`)).toBe(true);
    expect(needsBuild(`${BUILD}/scans`)).toBe(true);
    expect(needsBuild(`${BUILD}/findings/CVE-2026-1/components/libnl-3-200`)).toBe(true);
  });

  it("lets the findings list take whatever is selected", () => {
    // It was refused a partial scope on the same justification as the five
    // above, and the justification never held for it.
    expect(needsBuild(`${BUILD}/findings`)).toBe(false);
    expect(needsBuild("/products/sonic/findings")).toBe(false);
    expect(onFindings(`${BUILD}/findings`)).toBe(true);
    expect(onFindings("/products/sonic/findings")).toBe(true);
    expect(onFindings(`${BUILD}/components`)).toBe(false);
  });
});

describe("where a selection's findings live", () => {
  it("keeps a whole build on the address its other screens share", () => {
    expect(findingsPath({ product: "sonic", stream: "master", variant: "broadcom" })).toBe(
      `${BUILD}/findings`,
    );
  });

  it("carries the levels that are set, and only those", () => {
    expect(findingsPath({ product: "sonic" })).toBe("/products/sonic/findings");
    expect(findingsPath({ product: "sonic", stream: "master" })).toBe(
      "/products/sonic/findings?stream=master",
    );
    // The levels are independent: a variant across every branch is a real
    // question rather than a mistake.
    expect(findingsPath({ product: "sonic", variant: "broadcom" })).toBe(
      "/products/sonic/findings?variant=broadcom",
    );
  });

  it("escapes what somebody named", () => {
    expect(findingsPath({ product: "a/b", stream: "release 1.0" })).toBe(
      "/products/a%2Fb/findings?stream=release+1.0",
    );
  });

  it("spans every product when none is picked", () => {
    expect(findingsPath({})).toBe("/findings");
  });
});

describe("changing scope stays on the screen", () => {
  it("swaps the build under a build-scoped screen", () => {
    expect(
      rescoped(`${BUILD}/components`, {
        product: "sonic",
        stream: "202411",
        variant: "mellanox",
      }),
    ).toBe("/products/sonic/streams/202411/variants/mellanox/components");
  });

  it("narrows the wider list onto the build it was given", () => {
    expect(
      rescoped("/products/sonic/findings", {
        product: "sonic",
        stream: "master",
        variant: "broadcom",
      }),
    ).toBe(`${BUILD}/findings`);
  });

  it("leaves anything else where it is", () => {
    expect(
      rescoped("/review-queue", { product: "sonic", stream: "master", variant: "broadcom" }),
    ).toBe(null);
  });

  it("rewrites the address on the screens whose path names the product", () => {
    // Staying put on these is not staying put: the path re-supplies the old
    // product, which overwrites the choice that was just made.
    expect(rescoped("/products/sonic", { product: "gnmi" })).toBe("/products/gnmi");
    expect(rescoped("/products/sonic/streams", { product: "gnmi" })).toBe("/products/gnmi/streams");
    expect(rescoped("/products/sonic/variants", { product: "gnmi" })).toBe(
      "/products/gnmi/variants",
    );
    expect(rescoped("/products/sonic/comparison", { product: "gnmi" })).toBe(
      "/products/gnmi/comparison",
    );
  });

  it("drops what belonged to the product that was there", () => {
    // A branch is one product's, so it cannot carry across to another; the
    // address falls back to the new product's branch list.
    expect(rescoped("/products/sonic/streams/master", { product: "gnmi" })).toBe(
      "/products/gnmi/streams",
    );
    // A component is the same: it exists in one product's builds.
    expect(rescoped("/products/sonic/components/libnl-3-200", { product: "gnmi" })).toBe(
      "/products/gnmi",
    );
    // A branch that is part of the new selection is kept.
    expect(rescoped("/products/sonic/streams/master", { product: "gnmi", stream: "202411" })).toBe(
      "/products/gnmi/streams/202411",
    );
  });

  it("sends every product to the catalog", () => {
    expect(rescoped("/products/sonic", {})).toBe("/products");
    expect(rescoped("/products/sonic/streams/master", {})).toBe("/products");
  });

  it("stays put where the address already names what was chosen", () => {
    expect(rescoped("/products/sonic", { product: "sonic" })).toBe(null);
    expect(rescoped("/products/sonic/streams/master", { product: "sonic", stream: "master" })).toBe(
      null,
    );
  });

  it("escapes a product somebody named with a slash in it", () => {
    expect(rescoped("/products/sonic", { product: "a/b" })).toBe("/products/a%2Fb");
  });

  it("refuses a partial selection on a screen that exists for one build", () => {
    // Those five screens are about a way down and have no answer for "every
    // branch", so there is nowhere to land.
    expect(rescoped(`${BUILD}/components`, { product: "sonic" })).toBe(null);
  });
});

// The parameters every narrowed screen sends, straight into a request. A level
// that cannot stand alone leaking into the query is a refusal from the server
// for a selection nobody can make in the interface.
describe("the selection as a request", () => {
  it("sends nothing at all where nothing is selected", () => {
    expect(scopeQuery({})).toEqual({});
  });

  it("drops a level that cannot stand without the one above it", () => {
    // A branch or a variant without a product is refused by the server rather
    // than guessed at, so sending one turns a selection nobody can make into
    // an error somebody has to read.
    expect(scopeQuery({ stream: "master" })).toEqual({});
    expect(scopeQuery({ variant: "broadcom" })).toEqual({});
    expect(scopeQuery({ stream: "master", variant: "broadcom" })).toEqual({});
  });

  it("sends each level that is selected, and no level that is not", () => {
    expect(scopeQuery({ product: "sonic" })).toEqual({ product: "sonic" });
    // A variant without a branch is a real selection: the same hardware
    // across every release.
    expect(scopeQuery({ product: "sonic", variant: "broadcom" })).toEqual({
      product: "sonic",
      variant: "broadcom",
    });
    expect(scopeQuery({ product: "sonic", stream: "master", variant: "broadcom" })).toEqual({
      product: "sonic",
      stream: "master",
      variant: "broadcom",
    });
  });
});

describe("what is remembered about where somebody is working", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
  });

  it("keeps the selection for the tab rather than for the browser", () => {
    // The session store, not the local one: it is where somebody is working
    // right now rather than a preference, and a second tab looking at another
    // product must not drag the first one with it.
    remember({ product: "sonic", stream: "master" });
    expect(window.localStorage.getItem("openpsirt.scope")).toBeNull();
    expect(JSON.parse(window.sessionStorage.getItem("openpsirt.scope") ?? "null")).toEqual({
      product: "sonic",
      stream: "master",
    });
  });

  it("survives a browser that refuses storage", () => {
    // A browser that will not keep it still works; it just forgets. Throwing
    // here would take a screen down over a preference.
    const kept = window.sessionStorage.setItem;
    window.sessionStorage.setItem = () => {
      throw new Error("storage is off");
    };
    expect(() => remember({ product: "sonic" })).not.toThrow();
    window.sessionStorage.setItem = kept;
  });
});
