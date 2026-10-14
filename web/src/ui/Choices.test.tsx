// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act, useState } from "react";
import { beforeEach, describe, expect, it } from "vitest";
import { mounted } from "../test/mount";
import { Choices, type Choice } from "./Choices";

const STATES: readonly Choice[] = [
  ["undecided", "Undecided"],
  ["waiting", "Pending approval"],
  ["agreed", "Decided"],
];

const mount = mounted();
let last: string[] = [];

function Harness({ start }: { start: string[] }) {
  const [chosen, setChosen] = useState(start);
  return (
    <Choices
      label="Decision"
      options={STATES}
      chosen={chosen}
      onChange={(next) => {
        last = next;
        setChosen(next);
      }}
    />
  );
}

beforeEach(() => {
  last = [];
});

const trigger = () => mount.host().querySelector<HTMLButtonElement>(".choicesat")!;
const list = () => mount.host().querySelector(".choicelist");
const boxes = () =>
  Array.from(mount.host().querySelectorAll<HTMLInputElement>('.choicelist input[type="checkbox"]'));

function press(key: string) {
  const target = document.activeElement ?? mount.host();
  act(() => {
    target.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true }));
  });
}

describe("choices", () => {
  it("names one value and counts the rest, as the filter bar's menus do", () => {
    mount.render(<Harness start={["undecided", "waiting"]} />);
    expect(trigger().textContent).toContain("Undecided +1");
  });

  it("keeps a selection in the order offered, however it was ticked", () => {
    mount.render(<Harness start={["agreed"]} />);
    act(() => trigger().click());
    act(() => boxes()[0]!.click());
    expect(last).toEqual(["undecided", "agreed"]);
  });

  it("opens from the keyboard on the first box ticked", () => {
    mount.render(<Harness start={["waiting"]} />);
    act(() => trigger().focus());
    press("ArrowDown");
    expect(list()).not.toBeNull();
    expect(document.activeElement).toBe(boxes()[1]);
  });

  it("moves between the boxes with the arrows, Home and End, wrapping at either end", () => {
    mount.render(<Harness start={[]} />);
    act(() => trigger().focus());
    press("ArrowDown");
    expect(document.activeElement).toBe(boxes()[0]);
    press("ArrowUp");
    expect(document.activeElement).toBe(boxes()[2]);
    press("ArrowDown");
    expect(document.activeElement).toBe(boxes()[0]);
    press("End");
    expect(document.activeElement).toBe(boxes()[2]);
    press("Home");
    expect(document.activeElement).toBe(boxes()[0]);
  });

  it("closes on Escape and returns to the control", () => {
    mount.render(<Harness start={[]} />);
    act(() => trigger().click());
    expect(list()).not.toBeNull();
    press("Escape");
    expect(list()).toBeNull();
    expect(document.activeElement).toBe(trigger());
  });
});
