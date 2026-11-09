// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Linter } from "eslint";
import { describe, expect, it } from "vitest";
// @ts-expect-error - the linter configuration, which is plain ESM with no types of its own
import { reasonedDisables as rule } from "../eslint.config.js";

function reported(code: string): number[] {
  const linter = new Linter();
  return linter
    .verify(code, {
      plugins: { local: { rules: { "reasoned-disables": rule } } },
      rules: { "local/reasoned-disables": "error" },
    })
    .filter((message) => message.ruleId === "local/reasoned-disables")
    .map((message) => message.line);
}

describe("a disable directive", () => {
  it("is reported where it gives no reason", () => {
    expect(
      reported(
        [
          "// eslint-disable-next-line no-console",
          "console.log(1);",
          "console.log(2); // eslint-disable-line no-console",
          "/* eslint-disable no-console */",
        ].join("\n"),
      ),
    ).toEqual([1, 3, 4]);
  });

  it("is reported where the separator has nothing after it", () => {
    expect(reported("// eslint-disable-next-line no-console --\nconsole.log(1);")).toEqual([1]);
  });

  it("passes where a reason follows the separator", () => {
    expect(
      reported(
        [
          "// eslint-disable-next-line no-console -- The one place output is the point.",
          "console.log(1);",
          "/* eslint-disable no-console -- A script printing its report. */",
        ].join("\n"),
      ),
    ).toEqual([]);
  });

  it("passes a comment that is not a directive, and enabling a rule again", () => {
    expect(
      reported(
        [
          "// eslint-disables are reasoned elsewhere",
          "/* eslint-enable no-console */",
          "const x = 1;",
          "void x;",
        ].join("\n"),
      ),
    ).toEqual([]);
  });
});
