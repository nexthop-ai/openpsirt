// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Every check that reads the whole interface, in one file so that the source
// is parsed once for all of them. A test file is a module graph of its own,
// so checks in separate files each parse every file again.

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { sweep as addresses } from "./addresses.mjs";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { sweep as queryKeys } from "./query-keys.mjs";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { sweep as prose, sweepNames as names } from "./screen-copy.mjs";

// The whole tree is parsed once, which takes 1.3 s on two cores under the full
// suite with coverage on and several seconds on a 2-vCPU CI runner. The
// default five seconds is a limit that runner reaches; this one leaves room
// for it and still ends a scan that has stopped making progress.
const WHOLE_TREE_MS = 30_000;

describe("the interface", { timeout: WHOLE_TREE_MS }, () => {
  it("builds no address outside routes.ts, writes none the router does not answer, and looked", () => {
    const result = addresses();
    expect(result.files, "no source file was read, so this checked nothing").toBeGreaterThan(0);
    expect(result.literals, "no string was read, so this checked nothing").toBeGreaterThan(0);
    expect(result.routes, "the route table is empty, so this checked nothing").toBeGreaterThan(0);
    expect(
      result.screens,
      "no screen was read from the router, so this checked nothing",
    ).toBeGreaterThan(0);
    expect(result.found).toEqual([]);
    expect(result.unread).toEqual([]);
  });

  it("has no invalidation that reaches no read, and looked at some", () => {
    const { found, invalidations, reads } = queryKeys();
    expect(invalidations, "no invalidation was found, so this checked nothing").toBeGreaterThan(0);
    expect(reads, "no read was found, so this checked nothing").toBeGreaterThan(0);
    expect(found).toEqual([]);
  });

  it("has no standing prose, and looked at some", () => {
    const { found, examined } = prose();
    expect(
      examined,
      "no paragraph was found in the interface, so this checked nothing",
    ).toBeGreaterThan(0);
    expect(found).toEqual([]);
  });

  it("has no vague control and no asking label, and looked at some", () => {
    const { found, examined } = names();
    expect(
      examined,
      "no control, heading or label was found, so this checked nothing",
    ).toBeGreaterThan(0);
    expect(found).toEqual([]);
  });
});
