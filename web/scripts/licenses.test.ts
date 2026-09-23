// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { satisfies } from "./licenses.mjs";

// The interface ships inside the binary, so a copyleft dependency there is the
// installer's problem — and it was not checked at all while the Go half was.
//
// An SPDX expression is not a license name: "MIT AND ISC" is satisfied only if
// both are allowed, "(MPL-2.0 OR Apache-2.0)" by either. Treating the whole
// string as a name refuses both, and adding both strings to the allowlist
// accepts every other expression spelled the same way. This gate had no test,
// and its only consumer is an exit code.

const permissive = new Set(["MIT", "ISC", "Apache-2.0", "BSD-3-Clause", "0BSD"]);
const ok = (expression: string) => satisfies(expression, permissive) as boolean;

describe("what an allowlist admits", () => {
  it("takes a plain name that is on it", () => {
    expect(ok("MIT")).toBe(true);
  });

  it("refuses a plain name that is not", () => {
    expect(ok("GPL-3.0")).toBe(false);
  });
});

describe("an expression is read, not matched", () => {
  it("requires both sides of an AND", () => {
    expect(ok("MIT AND ISC")).toBe(true);
    expect(ok("MIT AND GPL-3.0")).toBe(false);
  });

  it("takes either side of an OR", () => {
    expect(ok("MPL-2.0 OR Apache-2.0")).toBe(true);
    expect(ok("GPL-3.0 OR AGPL-3.0")).toBe(false);
  });

  it("reads parentheses as grouping", () => {
    expect(ok("(MIT OR GPL-3.0) AND ISC")).toBe(true);
    expect(ok("(GPL-3.0 OR AGPL-3.0) AND MIT")).toBe(false);
  });

  it("takes a trailing plus as this version or later", () => {
    expect(ok("Apache-2.0+")).toBe(true);
    expect(ok("GPL-3.0+")).toBe(false);
  });
});

describe("what it will not guess at", () => {
  it("refuses an expression it cannot read to the end", () => {
    // Accepting whatever the first token happened to be is how an expression
    // nobody has read gets admitted on the strength of its opening word.
    expect(ok("MIT WITH Classpath-exception-2.0")).toBe(false);
    expect(ok("MIT ISC")).toBe(false);
  });

  it("refuses nothing at all", () => {
    expect(ok("")).toBe(false);
  });

  it("refuses a truncated expression rather than throwing on it", () => {
    // The gate's only output is an exit code, so a parser that throws exits
    // with a stack trace and never names the package whose license field was
    // the problem — which is the one thing somebody reading the failure needs.
    expect(() => ok("(MIT")).not.toThrow();
    expect(ok("(MIT")).toBe(false);
    expect(ok("MIT AND")).toBe(false);
    expect(ok("MIT OR")).toBe(false);
    expect(ok("(((")).toBe(false);
    expect(ok(")")).toBe(false);
  });
});
