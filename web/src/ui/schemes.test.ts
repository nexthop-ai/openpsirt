// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import shared from "../../../testdata/link-schemes.json";
import { linkable } from "./addressable";
import { render } from "./markdown";
import { LINK_SCHEMES } from "./schemes";

// The server's submission check compares its own lists with the same file, so
// a scheme it starts to accept and this stops linking fails on the side that
// was not changed.
describe("link schemes", () => {
  it("are the ones the server lets a link leaving the deployment name", () => {
    expect(shared.address.length).toBeGreaterThan(0);
    expect([...LINK_SCHEMES]).toEqual(shared.address);
  });

  it("are every scheme a link may use, less the two rewritten into paths", () => {
    expect(shared.link.filter((scheme) => scheme !== "attachment" && scheme !== "issue")).toEqual(
      shared.address,
    );
  });

  it("each keep a link when rendered", () => {
    const samples: Record<string, string> = {
      http: "http://example.com/a",
      https: "https://example.com/a",
      mailto: "mailto:psirt@example.com",
    };
    for (const scheme of shared.address) {
      const sample = samples[scheme];
      expect(sample, `a sample address for ${scheme}`).toBeDefined();
      expect(render(`[here](${sample})`), scheme).toContain(`href="${sample}"`);
    }
  });

  it("link a third party's address only where it names a page", () => {
    expect(linkable("https://example.com/a")).toBe("https://example.com/a");
    expect(linkable("http://example.com/a")).toBe("http://example.com/a");
    expect(linkable("mailto:psirt@example.com")).toBeNull();
  });
});
