// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { Body } from "../api/client";
import { openIssues, promiseLinks } from "./componentLinks";

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

describe("where a promised upgrade is followed", () => {
  const builds = (...names: [string, string][]) =>
    names.map(([stream, variant]) => ({ stream, variant }));

  it("links to each build's pending upgrades for three builds or fewer", () => {
    expect(promiseLinks("sonic", builds(["4.2", "broadcom"], ["main", "mellanox"]))).toEqual([
      {
        label: "Pending upgrades in 4.2 · broadcom →",
        to: "/products/sonic/streams/4.2/variants/broadcom/pending-upgrades",
      },
      {
        label: "Pending upgrades in main · mellanox →",
        to: "/products/sonic/streams/main/variants/mellanox/pending-upgrades",
      },
    ]);
  });

  it("links once to the release four builds share", () => {
    expect(
      promiseLinks("sonic", builds(["4.2", "a"], ["4.2", "b"], ["4.2", "c"], ["4.2", "d"])),
    ).toEqual([{ label: "4.2 →", to: "/products/sonic/streams/4.2" }]);
  });

  it("links once to the product's releases where four builds span several", () => {
    expect(
      promiseLinks("sonic", builds(["4.2", "a"], ["4.3", "a"], ["4.2", "c"], ["main", "d"])),
    ).toEqual([{ label: "Releases →", to: "/products/sonic/streams" }]);
  });
});
