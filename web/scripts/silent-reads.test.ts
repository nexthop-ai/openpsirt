// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { silentReads, sweep } from "./silent-reads.mjs";

describe("a read defaulted to an empty list", () => {
  it("is reported where nothing in its file consults its failure", () => {
    expect(silentReads("x.tsx", `const rows = products.data?.items ?? [];`)).toEqual({
      examined: 1,
      found: ["x.tsx:1: products"],
    });
  });

  it("is reported for any one field of the data, not only its items", () => {
    expect(silentReads("x.tsx", `const pairs = compared.data?.pairs ?? [];`).found).toEqual([
      "x.tsx:1: compared",
    ]);
  });

  it("is reported where a call stands in place of a name", () => {
    expect(silentReads("x.tsx", `const offered = useSearch(typed).data ?? [];`).found).toEqual([
      "x.tsx:1: a call's data",
    ]);
  });

  it("passes where its failure is consulted", () => {
    const ways = [
      `products.isError && <Failed error={products.error} />`,
      `<Reading query={products} what="x">{() => null}</Reading>`,
      `<Unread of={products} what="x" />`,
      `<Count of={[products, teams]}>{() => 1}</Count>`,
      `known(products)`,
      `[teams, products].find((q) => q.isError)`,
    ];
    for (const way of ways) {
      expect(
        silentReads("x.tsx", `const rows = products.data?.items ?? [];\n${way}`).found,
        way,
      ).toEqual([]);
    }
  });

  it("passes where a comment says why it may be quiet", () => {
    expect(
      silentReads(
        "x.tsx",
        `// silent-read: a suggestion list\nconst offered = useSearch(typed).data ?? [];`,
      ).found,
    ).toEqual([]);
  });

  it("is reported where the comment gives no reason", () => {
    expect(
      silentReads("x.tsx", `// silent-read:\nconst offered = useSearch(typed).data ?? [];`).found,
    ).toHaveLength(1);
  });

  it("finds no silent read anywhere in the interface", () => {
    const { files, examined, found } = sweep();
    expect(files, "no sources were found, so this checked nothing").toBeGreaterThan(0);
    expect(examined, "no defaulted reads were found, so this checked nothing").toBeGreaterThan(0);
    expect(found).toEqual([]);
  });
});
