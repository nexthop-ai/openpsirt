// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ChoiceCards, stepFor } from "./ChoiceCards";

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

const OPTIONS = [
  { value: "outside", label: "Sent in from outside", note: "Gets a disclosure date" },
  { value: "here", label: "Found here" },
  { value: "unknown", label: "Nobody knows" },
] as const;

type Value = (typeof OPTIONS)[number]["value"];

function Harness({ start }: { start: Value | "" }) {
  const [value, setValue] = useState<Value | "">(start);
  return <ChoiceCards label="Source" value={value} onChange={setValue} options={OPTIONS} />;
}

let host: HTMLDivElement;
let root: Root;

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

const cards = () => Array.from(host.querySelectorAll<HTMLButtonElement>('[role="radio"]'));
const checked = () => cards().map((each) => each.getAttribute("aria-checked"));
const stops = () => cards().map((each) => each.tabIndex);

function press(key: string) {
  const target = document.activeElement ?? host;
  act(() => {
    target.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true }));
  });
}

describe("choice cards", () => {
  it("offers the first card as the one tab stop when nothing is picked", () => {
    act(() => root.render(<Harness start="" />));
    expect(host.querySelector('[role="radiogroup"]')?.getAttribute("aria-label")).toBe("Source");
    expect(checked()).toEqual(["false", "false", "false"]);
    expect(stops()).toEqual([0, -1, -1]);
  });

  it("picks a card on click, and moves the tab stop to it", () => {
    act(() => root.render(<Harness start="" />));
    act(() => cards()[1]!.click());
    expect(checked()).toEqual(["false", "true", "false"]);
    expect(stops()).toEqual([-1, 0, -1]);
  });

  it("moves and picks with the arrow keys, wrapping at the ends", () => {
    act(() => root.render(<Harness start="unknown" />));
    act(() => cards()[2]!.focus());
    press("ArrowRight");
    expect(checked()).toEqual(["true", "false", "false"]);
    expect(document.activeElement).toBe(cards()[0]);
    press("ArrowUp");
    expect(checked()).toEqual(["false", "false", "true"]);
    press("Home");
    expect(checked()).toEqual(["true", "false", "false"]);
    press("End");
    expect(checked()).toEqual(["false", "false", "true"]);
    expect(document.activeElement).toBe(cards()[2]);
  });

  it("leaves a key it does not handle alone", () => {
    act(() => root.render(<Harness start="here" />));
    act(() => cards()[1]!.focus());
    press("a");
    expect(checked()).toEqual(["false", "true", "false"]);
  });

  it("shows the consequence inside the card", () => {
    act(() => root.render(<Harness start="" />));
    expect(cards()[0]!.textContent).toContain("Gets a disclosure date");
  });
});

describe("stepFor", () => {
  it("starts from the first or the last where nothing is picked", () => {
    expect(stepFor("ArrowDown", -1, 3)).toBe(0);
    expect(stepFor("ArrowLeft", -1, 3)).toBe(2);
  });

  it("answers nothing for an empty group", () => {
    expect(stepFor("ArrowDown", -1, 0)).toBeUndefined();
  });
});
