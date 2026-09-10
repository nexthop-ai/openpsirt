import { describe, expect, it } from "vitest";
import { findingsPath, needsBuild, onFindings, rescoped } from "./scope";

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
});
