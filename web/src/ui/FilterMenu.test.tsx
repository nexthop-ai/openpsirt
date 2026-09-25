// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FilterMenu, type MenuOption } from "./FilterMenu";

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

const STATES: readonly MenuOption[] = [
  ["", "Any"],
  ["undecided", "Undecided"],
  ["waiting", "Pending approval"],
  ["agreed", "Decided"],
];

const STEPS: readonly MenuOption[] = [
  ["", "Any"],
  ["often", "Often and up"],
  ["always", "Always"],
];

let host: HTMLDivElement;
let outside: HTMLButtonElement;
let root: Root;
let last: string[] = [];

function Harness({ multi, start }: { multi: boolean; start: string[] }) {
  const [chosen, setChosen] = useState(start);
  return (
    <FilterMenu
      label={multi ? "Decision" : "Severity"}
      options={multi ? STATES : STEPS}
      chosen={chosen}
      multi={multi}
      onChange={(next) => {
        last = next;
        setChosen(next);
      }}
    />
  );
}

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  last = [];
  host = document.createElement("div");
  outside = document.createElement("button");
  document.body.append(host, outside);
  root = createRoot(host);
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
  outside.remove();
});

const trigger = () => host.querySelector<HTMLButtonElement>(".filterbtn")!;
const menu = () => host.querySelector('[role="menu"]');
const items = () => Array.from(host.querySelectorAll<HTMLButtonElement>('[role^="menuitem"]'));

function press(key: string) {
  const target = document.activeElement ?? host;
  act(() => {
    target.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true }));
  });
}

describe("filter menu", () => {
  it("names itself and what it is set to, and says when it narrows", () => {
    act(() => root.render(<Harness multi start={[]} />));
    expect(trigger().textContent).toContain("Decision");
    expect(trigger().textContent).toContain("Any");
    expect(trigger().dataset.on).toBeUndefined();
  });

  it("names one value and counts the rest", () => {
    act(() => root.render(<Harness multi start={["undecided", "waiting"]} />));
    expect(trigger().textContent).toContain("Undecided +1");
    expect(trigger().dataset.on).toBe("yes");
  });

  it("opens on click and closes on a click outside", () => {
    act(() => root.render(<Harness multi start={[]} />));
    expect(menu()).toBeNull();
    act(() => trigger().click());
    expect(menu()).not.toBeNull();
    expect(trigger().getAttribute("aria-expanded")).toBe("true");
    act(() => {
      outside.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));
    });
    expect(menu()).toBeNull();
  });

  it("ticks several values and stays open", () => {
    act(() => root.render(<Harness multi start={[]} />));
    act(() => trigger().click());
    expect(items().map((each) => each.getAttribute("role"))).toEqual([
      "menuitemcheckbox",
      "menuitemcheckbox",
      "menuitemcheckbox",
    ]);
    act(() => items()[1]!.click());
    act(() => items()[0]!.click());
    expect(last).toEqual(["undecided", "waiting"]);
    expect(menu()).not.toBeNull();
    act(() => items()[0]!.click());
    expect(last).toEqual(["waiting"]);
  });

  it("picks one value, closes, and gives focus back", () => {
    act(() => root.render(<Harness multi={false} start={[]} />));
    act(() => trigger().click());
    expect(items()[0]!.getAttribute("aria-checked")).toBe("true");
    act(() => items()[2]!.click());
    expect(last).toEqual(["always"]);
    expect(menu()).toBeNull();
    expect(document.activeElement).toBe(trigger());
    act(() => trigger().click());
    act(() => items()[0]!.click());
    expect(last).toEqual([]);
  });

  it("moves with the arrow keys, wrapping, and closes on Escape", () => {
    act(() => root.render(<Harness multi={false} start={["often"]} />));
    act(() => trigger().focus());
    press("ArrowDown");
    expect(menu()).not.toBeNull();
    expect(document.activeElement).toBe(items()[1]);
    press("ArrowDown");
    expect(document.activeElement).toBe(items()[2]);
    press("ArrowDown");
    expect(document.activeElement).toBe(items()[0]);
    press("End");
    expect(document.activeElement).toBe(items()[2]);
    press("Escape");
    expect(menu()).toBeNull();
    expect(document.activeElement).toBe(trigger());
    expect(last).toEqual([]);
  });
});
