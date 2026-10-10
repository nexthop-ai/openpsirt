// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { keysIn, reaches, stale } from "./query-keys.mjs";

// Both directions per shape — one input that must be reported and one that
// must not — because the failure that matters here is the check going quiet.

const found = (...sources: string[]) =>
  stale(sources.map((text, i) => ({ file: `f${i}.tsx`, ...keysIn(text) }))).map(
    (each: { key: string[] }) => each.key,
  );

describe("an invalidation that reaches no read", () => {
  it("is reported where no read's key starts with it", () => {
    expect(
      found(
        `useQuery({ queryKey: ["whoami"], queryFn });`,
        `q.invalidateQueries({ queryKey: ["me"] });`,
      ),
    ).toEqual([["me"]]);
  });

  it("is not reported where a read's key starts with it", () => {
    expect(
      found(
        `useQuery({ queryKey: ["home", "trend", scope], queryFn });`,
        `q.invalidateQueries({ queryKey: ["home"] });`,
      ),
    ).toEqual([]);
  });

  it("is reported where the words it shares with a read are not at the start", () => {
    expect(
      found(
        `useQuery({ queryKey: ["home", "trend", scope], queryFn });`,
        `q.invalidateQueries({ queryKey: ["trend"] });`,
      ),
    ).toEqual([["trend"]]);
  });

  it("reaches a read whose key goes on past its literal part", () => {
    expect(
      found(
        `useQuery({ queryKey: ["streams", product], queryFn });`,
        `q.invalidateQueries({ queryKey: ["streams", "sonic"] });`,
      ),
    ).toEqual([]);
    expect(reaches({ words: ["streams", "sonic"] }, { words: ["streams"], open: false })).toBe(
      false,
    );
  });

  it("reads keys declared inside a list of queries", () => {
    expect(
      found(
        `useQueries({ queries: rows.map((row) => ({ queryKey: ["release-counts", row] })) });`,
        `q.invalidateQueries({ queryKey: ["release-counts"] });`,
      ),
    ).toEqual([]);
  });

  it("does not count a key named to remove or refetch queries as a read", () => {
    expect(
      found(
        `q.removeQueries({ queryKey: ["gone"] });`,
        `q.invalidateQueries({ queryKey: ["gone"] });`,
      ),
    ).toEqual([["gone"]]);
  });
});
