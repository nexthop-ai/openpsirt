// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { fileAt, linkTo } from "./links";

describe("an address a browser fetches directly", () => {
  it("escapes each placeholder as a path segment", () => {
    expect(linkTo("/v1/advisories/{advisory}/document", { path: { advisory: "a/b c" } })).toBe(
      "/v1/advisories/a%2Fb%20c/document",
    );
  });

  it("carries the question as it was asked, and nothing where nothing was", () => {
    expect(
      linkTo("/v1/findings", { query: { outcome: ["deferred", "wont-fix"], q: "open ssl" } }),
    ).toBe("/v1/findings?outcome=deferred&outcome=wont-fix&q=open+ssl");
    expect(linkTo("/v1/findings", { query: "" })).toBe("/v1/findings");
    expect(linkTo("/v1/findings")).toBe("/v1/findings");
  });

  it("refuses a placeholder left without a value", () => {
    const unfilled = { path: {} } as unknown as { path: { advisory: string } };
    expect(() => linkTo("/v1/advisories/{advisory}/document", unfilled)).toThrow("{advisory}");
  });
});

describe("a report file's address", () => {
  it("fills the format as the extension, beside the route's own placeholders", () => {
    expect(
      fileAt("/v1/trend.{format}", "csv", { query: new URLSearchParams({ weeks: "12" }) }),
    ).toBe("/v1/trend.csv?weeks=12");
    expect(
      fileAt("/v1/products/{product}/comparison.{format}", "json", { path: { product: "son ic" } }),
    ).toBe("/v1/products/son%20ic/comparison.json");
    expect(fileAt("/v1/deferrals/repeated.{format}", "json")).toBe("/v1/deferrals/repeated.json");
  });
});
