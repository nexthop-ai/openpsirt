// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { unnamed, webSources } from "./exported.mjs";

describe("an export in the web source", () => {
  it("is named by some other file", () => {
    const { found, examined } = unnamed(webSources()) as { found: string[]; examined: number };
    if (examined === 0) throw new Error("no exports were read, so this checked nothing");
    expect(found).toEqual([]);
  });

  it("is reported where no other file names it", () => {
    const { found } = unnamed({
      "a.ts": "export const kept = 1;\nexport function spare() {}\n",
      "b.ts": 'import { kept } from "./a";\n',
    }) as { found: string[] };
    expect(found).toEqual(["a.ts: spare"]);
  });

  it("is not reported where only a test names it", () => {
    const { found } = unnamed({
      "a.ts": "export const kept = 1;\n",
      "a.test.ts": 'import { kept } from "./a";\n',
    }) as { found: string[] };
    expect(found).toEqual([]);
  });
});
