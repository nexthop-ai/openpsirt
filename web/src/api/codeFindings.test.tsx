// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { useAssignCodeFinding } from "./codeFindings";
import { acted } from "../test/acted";
import { mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const build = { product: "sonic", branch_or_tag: "master", variant: "broadcom" };

describe("a code finding handed to a holder, once it lands", () => {
  it("moves the holdings and every list of who holds what", async () => {
    const { invalidated } = await acted(
      mount.render,
      mount.host,
      "PUT",
      () => useAssignCodeFinding(build, "abc"),
      { kind: "team" as const, identity: "kernel" },
    );
    expect(invalidated).toEqual(expect.arrayContaining(["assigned", "holdings", "team-assigned"]));
  });
});
