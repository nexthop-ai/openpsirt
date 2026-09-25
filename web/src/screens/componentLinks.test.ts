// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { Body } from "../api/client";
import { openIssues } from "./componentLinks";

const build = (issues: number) =>
  ({
    stream: "master",
    variant: "broadcom",
    issues,
    packages: [{ name: "curl" }, { name: "libcurl4t64" }],
  }) as Body<"PerBuildBody">;

describe("the component page's action", () => {
  it("names how many issues are open and leads to them for every binary", () => {
    expect(openIssues("sonic", build(1840))).toEqual({
      label: "1,840 open issues →",
      to: "/products/sonic/streams/master/variants/broadcom/findings?component=curl&component=libcurl4t64",
    });
  });

  it("says issue for one", () => {
    expect(openIssues("sonic", build(1))?.label).toBe("1 open issue →");
  });

  it("is absent when nothing is open", () => {
    expect(openIssues("sonic", build(0))).toBeUndefined();
  });
});
