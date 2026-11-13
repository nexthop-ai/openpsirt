// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { componentRoots, hiddenByPosition, printedActions, sweep } from "./printed-heads.mjs";
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

  it("reports an action a component draws at its root under a head", () => {
    const parts = parse(
      `export function Add() { return (<><span><button>Add</button></span><i /></>); }
       export function Crumb() { return <span className="crumbs"><b>run 7</b></span>; }
       export function Maybe({ on }) { if (on) { return <span><button>Go</button></span>; } return null; }
       export const Arrow = () => <span><a className="btn">CSV</a></span>;`,
      "ui/parts.tsx",
    );
    // A component of the same name elsewhere, which the head does not import.
    const other = parse(
      `export function Crumb() { return <span><button>X</button></span>; }`,
      "y.tsx",
    );
    const declared = new Map([
      ["ui/parts.tsx", componentRoots("ui/parts.tsx", parts)],
      ["y.tsx", componentRoots("y.tsx", other)],
    ]);
    const found = printedActions(
      "screens/x.tsx",
      parse(
        `import { Add, Crumb, Maybe, Arrow as Drawn } from "../ui/parts";
         const x = <div className="screen-head"><h2>T</h2><Crumb /><Add /><Maybe on /><Drawn /></div>;`,
        "screens/x.tsx",
      ),
      declared,
    );
    expect(found).toEqual({
      examined: 4,
      found: ["ui/parts.tsx:1", "ui/parts.tsx:3", "ui/parts.tsx:4"],
    });
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
