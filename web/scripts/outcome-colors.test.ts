// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { armsIn, outcomesIn, sweep, uncolored } from "./outcome-colors.mjs";

describe("a decision's color", () => {
  it("reports an outcome no arm colors", () => {
    const outcomes = outcomesIn(`      outcome: "not-applicable" | "affected" | "mismatched";\n`);
    expect(
      uncolored(
        outcomes,
        armsIn(".decided.affected,\n.decided.not-applicable {\n  --c: var(--ok);\n}"),
      ),
    ).toEqual(["mismatched"]);
  });

  it("passes an outcome an arm colors", () => {
    const outcomes = outcomesIn(
      `      outcome?: ("not-applicable" | "affected" | "mismatched")[] | null;\n`,
    );
    const css = ".decided.affected {\n}\n.decided.mismatched,\n.decided.not-applicable {\n}";
    expect(uncolored(outcomes, armsIn(css))).toEqual([]);
  });

  it("colors every outcome the client names, and read some", () => {
    const { outcomes, missing } = sweep();
    expect(outcomes.length, "no outcome was read, so this checked nothing").toBeGreaterThan(0);
    expect(missing).toEqual([]);
  });
});
