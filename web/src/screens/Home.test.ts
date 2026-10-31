// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { blockingPath } from "./HomeDependencies";

describe("the link under the readiness blockers", () => {
  it("opens the list without the defaults the count was not taken with", () => {
    const path = blockingPath({ product: "sonic", branch_or_tag: "master", variant: "broadcom" });
    expect(
      path.startsWith("/products/sonic/branches-and-tags/master/variants/broadcom/findings?"),
    ).toBe(true);
    const asked = new URLSearchParams(path.slice(path.indexOf("?")));
    expect(asked.getAll("state")).toEqual(["undecided", "waiting", "lapsed"]);
    expect(asked.get("planned")).toBe("either");
    expect(asked.getAll("on")).toEqual(["branch", "tag"]);
    expect(asked.getAll("support")).toEqual(["in-support", "past-eol"]);
  });
});
