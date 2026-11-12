// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { hiddenByPosition, printedActions, sweep } from "./printed-heads.mjs";
// @ts-expect-error - as above
import { parse } from "./parsed.mjs";

const read = (text: string) => printedActions("x.tsx", parse(text, "x.tsx"));

describe("a screen head on paper", () => {
  it("reports an action under the head with nothing keeping it off paper", () => {
    const found = read(
      `const x = <div className="screen-head"><h2>T</h2><span><button>Go</button></span></div>;`,
    );
    expect(found.found).toEqual(["x.tsx:1"]);
  });

  it("passes an action marked noprint, and a breadcrumb", () => {
    const found = read(`const x = <div className="screen-head">
      <span className="crumbs"><b>run 7</b></span>
      <span className="noprint"><button>Go</button></span></div>;`);
    expect(found).toEqual({ examined: 2, found: [] });
  });

  it("reports an action drawn only on a condition, and passes one marked noprint", () => {
    const found = read(`const x = <div className="screen-head"><h2>T</h2>
      {ok && (<span><button>Go</button></span>)}
      {ok ? <span className="noprint"><a href="/">CSV</a></span> : null}</div>;`);
    expect(found).toEqual({ examined: 2, found: ["x.tsx:2"] });
  });

  it("reports a print rule hiding every span under a head", () => {
    expect(hiddenByPosition(`.tabs2, .screen-head > span { display: none !important; }`)).toEqual([
      ".screen-head > span",
    ]);
    expect(hiddenByPosition(`.screen-head > span:last-child { flex: none; }`)).toEqual([]);
  });

  it("prints every head's breadcrumb and counts, and none of its actions", () => {
    const { examined, found, hidden } = sweep();
    expect(
      examined,
      "no span under a screen head was found, so this checked nothing",
    ).toBeGreaterThan(0);
    expect(found).toEqual([]);
    expect(hidden).toEqual([]);
  });
});
