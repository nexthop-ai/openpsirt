// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { tokensIn, withoutComments } from "./tokens.mjs";

// A `var(--thing)` naming a token that does not exist is an error nowhere: CSS
// drops the declaration, the element keeps whatever it inherited, and the
// screen looks nearly right. This gate puts every reference to the set of
// definitions, and every definition to the set of references.
//
// **Asked through the reader the walk uses**, not of the comment stripper on
// its own. Asked of the stripper, every case here passes while the calls to it
// are deleted — which is the missing-call shape this gate exists to catch,
// happening inside the gate.

const read = (source: string) => {
  const { defined, named } = tokensIn(source) as {
    defined: Map<string, string>;
    named: Map<string, string[]>;
  };
  return { defined: [...defined.keys()], named: [...named.keys()] };
};

describe("what a file defines and what it names", () => {
  it("reads a definition and a reference", () => {
    expect(read(`:root { --a: 1px; }\n.x { width: var(--a); }`)).toEqual({
      defined: ["--a"],
      named: ["--a"],
    });
  });

  it("reads a token set in a style object a component hands an element", () => {
    // A token set per element is as defined as one set on a selector, and the
    // swatch that draws two colors is exactly that.
    expect(read(`<div style={{ "--swatch": color }} />`).defined).toEqual(["--swatch"]);
  });

  it("leaves a reference carrying its own fallback", () => {
    // `var(--gone, 8px)` is a deliberate default: the author said what happens
    // when it is absent.
    expect(read(`.x { gap: var(--gone, 8px); }`).named).toEqual([]);
  });
});

describe("a comment is prose, not a reference", () => {
  it("does not read a token out of a line comment", () => {
    // The block explaining why a color is not composed at run time has to
    // write the shape it is not composing, and that read as a token named and
    // defined nowhere.
    const got = read(`// var(--sev-critical) is not composed here\n:root { --a: 1px; }`);
    expect(got.named).toEqual([]);
    expect(got.defined).toEqual(["--a"]);
  });

  it("does not read a definition out of a block comment", () => {
    expect(read(`/* a --gone: 8px was here */\n:root { --a: 1px; }`).defined).toEqual(["--a"]);
  });

  it("keeps a token inside a string that holds a double slash", () => {
    // A `//` inside quotes is part of the value, not the start of a comment.
    // Cutting there would take the rest of the line with it.
    expect(read(`const at = "https://example.test";\n.x { color: var(--kept); }`).named).toEqual([
      "--kept",
    ]);
  });

  it("changes nothing where there is no comment", () => {
    const source = `:root { --sev-high: #d9700a; }`;
    expect(withoutComments(source)).toBe(source);
  });
});
