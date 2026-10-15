// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";

// Acts a test takes on a drawn screen, through the events React listens for.

// The button whose text is exactly this, among those inside a node.
export function button(within: ParentNode, text: string): HTMLButtonElement {
  const found = Array.from(within.querySelectorAll("button")).find(
    (each) => each.textContent?.trim() === text,
  );
  if (!found) throw new Error(`no button reads "${text}"`);
  return found;
}

// Presses the button whose text is exactly this.
export async function press(within: ParentNode, text: string): Promise<void> {
  const found = button(within, text);
  await act(async () => found.click());
}

// Types a value into a text field, a number field or a text area.
export function type(field: HTMLInputElement | HTMLTextAreaElement | null, value: string): void {
  if (!field) throw new Error("no such field");
  const proto =
    field instanceof HTMLTextAreaElement
      ? HTMLTextAreaElement.prototype
      : HTMLInputElement.prototype;
  act(() => {
    Object.getOwnPropertyDescriptor(proto, "value")?.set?.call(field, value);
    field.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

// Picks an option of a select by its value.
export function choose(field: HTMLSelectElement | null, value: string): void {
  if (!field) throw new Error("no such select");
  act(() => {
    Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")?.set?.call(field, value);
    field.dispatchEvent(new Event("change", { bubbles: true }));
  });
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
