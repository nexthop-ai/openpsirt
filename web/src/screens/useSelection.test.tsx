// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act, useEffect } from "react";
import { describe, expect, it } from "vitest";
import { questionIn, untaken, useSelection } from "./useSelection";
import type { Row } from "./list";
import { mounted } from "../test/mount";

const mount = mounted();

// The hook as the findings list holds it, drawn into a host so its state
// behaves as React keeps it. What it returned last is read from `held`.
const held: { current?: ReturnType<typeof useSelection> } = {};
function Holding({ asked }: { asked: string }) {
  const now = useSelection(new URLSearchParams(asked));
  useEffect(() => {
    held.current = now;
  });
  return null;
}

function selection(): ReturnType<typeof useSelection> {
  if (!held.current) throw new Error("nothing is holding a selection");
  return held.current;
}

const one = (vulnerability: string) => ({ vulnerability, fold: "curl@8" }) as Row;

// The definition of a change of question decides when the selection is emptied,
// and the selection is what a bulk act writes against. Both directions matter:
// too narrow and rows chosen under one question are written under another; too
// wide and turning the page throws away what somebody ticked.
describe("what the list is asking", () => {
  it("is the same question from a different row", () => {
    // The selection is deliberately wider than a page — the bar says "across
    // pages" — so paging must not empty it.
    expect(questionIn(new URLSearchParams("state=undecided&offset=50"))).toBe(
      questionIn(new URLSearchParams("state=undecided")),
    );
    expect(questionIn(new URLSearchParams("state=undecided&offset=50"))).toBe(
      questionIn(new URLSearchParams("state=undecided&offset=200")),
    );
  });

  it("is a different question when a filter moves", () => {
    // A triager filtering to low, ticking thirty and then clicking critical
    // had a bar still saying thirty while four rows were listed — and handing
    // them over wrote assignments for twenty-six rows nobody could see.
    expect(questionIn(new URLSearchParams("floor=low"))).not.toBe(
      questionIn(new URLSearchParams("floor=critical")),
    );
    expect(questionIn(new URLSearchParams(""))).not.toBe(
      questionIn(new URLSearchParams("state=undecided")),
    );
  });

  it("is a different question when a filter is added or removed", () => {
    expect(questionIn(new URLSearchParams("state=undecided&offset=50"))).not.toBe(
      questionIn(new URLSearchParams("state=undecided&exploited=1&offset=50")),
    );
  });

  it("leaves the page size in the question", () => {
    // Changing how many rows a page holds re-cuts the population the selection
    // was made out of, unlike moving through it.
    expect(questionIn(new URLSearchParams("page=50"))).not.toBe(
      questionIn(new URLSearchParams("page=200")),
    );
  });
});

describe("what an act did not take", () => {
  const row = (vulnerability: string, fold: string) => ({ vulnerability, fold }) as Row;
  const picked = new Map<string, Row>([
    ["a", row("CVE-1", "curl@8")],
    ["b", row("CVE-2", "curl@8")],
    ["c", row("CVE-1", "openssl@3")],
  ]);
  it("keeps the rows the server names as left, by issue and fold", () => {
    expect(untaken(picked, [{ vulnerability: "CVE-1", fold: "curl@8" }]).map(([k]) => k)).toEqual([
      "a",
    ]);
  });
  it("keeps nothing when everything moved", () => {
    expect(untaken(picked, [])).toEqual([]);
  });
});

describe("a bulk act over the selection", () => {
  it("leaves ticked exactly the rows it refused", async () => {
    mount.render(<Holding asked="state=open" />);
    act(() =>
      selection().pickAll([one("CVE-1"), one("CVE-2"), one("CVE-3")], ["a", "b", "c"], true),
    );
    await act(() =>
      selection().through(async (row) => {
        if (row.vulnerability === "CVE-2") throw new Error("refused");
      }),
    );
    expect([...selection().picked.keys()]).toEqual(["b"]);
    expect(selection().failed).toBe(1);
  });

  it("keeps a row ticked while the act was running", async () => {
    mount.render(<Holding asked="state=open" />);
    act(() => selection().pick("a", one("CVE-1"), true));
    let release: () => void = () => undefined;
    let done: Promise<void> = Promise.resolve();
    act(() => {
      done = selection().through(
        () =>
          new Promise<void>((resolve) => {
            release = resolve;
          }),
      );
    });
    act(() => selection().pick("late", one("CVE-9"), true));
    await act(async () => {
      release();
      await done;
    });
    expect([...selection().picked.keys()]).toEqual(["late"]);
    expect(selection().failed).toBe(0);
  });

  it("is emptied by a new question and kept by a new page", () => {
    mount.render(<Holding asked="state=open" />);
    act(() => selection().pickAll([one("CVE-1"), one("CVE-2")], ["a", "b"], true));
    mount.render(<Holding asked="state=open&offset=50" />);
    expect(selection().picked.size).toBe(2);
    mount.render(<Holding asked="state=closed&offset=50" />);
    expect(selection().picked.size).toBe(0);
  });

  it("takes a page back out, and forgets everything when cleared or asked anew", () => {
    mount.render(<Holding asked="state=open" />);
    act(() =>
      selection().pickAll([one("CVE-1"), one("CVE-2"), one("CVE-3")], ["a", "b", "c"], true),
    );
    act(() => selection().pickAll([one("CVE-1"), one("CVE-2")], ["a", "b"], false));
    expect([...selection().picked.keys()]).toEqual(["c"]);
    act(() => selection().clear());
    expect(selection().picked.size).toBe(0);
    act(() => selection().pick("a", one("CVE-1"), true));
    let next = new URLSearchParams();
    act(() => {
      next = selection().asking(new URLSearchParams("state=open&offset=100&severity=high"));
    });
    expect(next.has("offset")).toBe(false);
    expect(selection().picked.size).toBe(0);
  });
});
