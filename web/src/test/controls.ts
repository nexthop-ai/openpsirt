// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";

// What a person does to a drawn screen, each through React's own act.

// The button whose text is exactly the label, or a failure naming it.
export function button(host: HTMLElement, label: string): HTMLButtonElement {
  const found = Array.from(host.querySelectorAll("button")).find(
    (each) => each.textContent?.trim() === label,
  );
  if (!found) throw new Error(`no button ${label}`);
  return found;
}

// Presses the button whose text is exactly the label.
export function press(host: HTMLElement, label: string): void {
  const found = button(host, label);
  act(() => found.click());
}

// Sets a field's value the way typing or picking does, so React's own
// change handler runs.
export function change(
  field: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement | null,
  value: string,
): void {
  if (!field) throw new Error("no such field");
  const proto =
    field instanceof HTMLSelectElement
      ? HTMLSelectElement
      : field instanceof HTMLTextAreaElement
        ? HTMLTextAreaElement
        : HTMLInputElement;
  act(() => {
    Object.getOwnPropertyDescriptor(proto.prototype, "value")?.set?.call(field, value);
    field.dispatchEvent(
      new Event(field instanceof HTMLSelectElement ? "change" : "input", { bubbles: true }),
    );
  });
}

// Ticks or unticks the checkbox inside the label whose text holds the words.
export function tick(host: HTMLElement, words: string): void {
  const label = Array.from(host.querySelectorAll("label")).find((each) =>
    each.textContent?.includes(words),
  );
  const box = label?.querySelector<HTMLInputElement>('input[type="checkbox"]');
  if (!box) throw new Error(`no checkbox ${words}`);
  act(() => box.click());
}

// Picks the radio card whose label is exactly the words.
export function pick(host: HTMLElement, words: string): void {
  const card = Array.from(host.querySelectorAll<HTMLElement>('[role="radio"]')).find(
    (each) => each.querySelector("b")?.textContent === words,
  );
  if (!card) throw new Error(`no choice ${words}`);
  act(() => card.click());
}
