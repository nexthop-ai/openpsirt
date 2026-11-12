// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { useTrust } from "./upstream";
import { acted } from "../test/acted";
import { mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

describe("trust in an upstream withdrawn, once it lands", () => {
  it("moves what a component screen draws as the upstream's statements", async () => {
    const { invalidated } = await acted(
      mount.render,
      mount.host,
      "DELETE",
      () => useTrust("sonic").withdraw,
      undefined,
    );
    expect(invalidated).toContain("upstream-said");
  });
});
