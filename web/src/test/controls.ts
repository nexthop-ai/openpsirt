// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";

// What a person does to a drawn screen, each through React's own act.

// The button whose text is exactly the label, among those inside a node.
export function button(within: ParentNode, label: string): HTMLButtonElement {
  const found = Array.from(within.querySelectorAll("button")).find(
    (each) => each.textContent?.trim() === label,
  );
  if (!found) throw new Error(`no button reads "${label}"`);
  return found;
}

// Presses the button whose text is exactly the label, and lets what the
// press started settle.
export async function press(within: ParentNode, label: string): Promise<void> {
  const found = button(within, label);
  await act(async () => found.click());
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

// The field a label names, by the label's text.
export function labeled(within: ParentNode, text: string): HTMLInputElement {
  const label = Array.from(within.querySelectorAll("label")).find(
    (each) => each.textContent?.trim() === text,
  );
  const id = label?.getAttribute("for");
  const found = id
    ? within.querySelector<HTMLInputElement>(`#${CSS.escape(id)}`)
    : label?.querySelector<HTMLInputElement>("input");
  if (!found) throw new Error(`no field labeled "${text}"`);
  return found;
}

// What one request was sent with, as the generated client takes it.
export type Init = {
  params?: { path?: Record<string, unknown>; query?: Record<string, unknown> };
  body?: unknown;
};

// The one request a write sent, failing where it sent none or several.
export function only(sent: () => unknown[]): [path: string, init: Init] {
  const all = sent() as [string, Init][];
  if (all.length !== 1) throw new Error(`sent ${all.length} requests where one was expected`);
  return all[0] as [string, Init];
}
