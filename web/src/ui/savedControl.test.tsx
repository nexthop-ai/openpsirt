// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { location, mounted, screen, serve, settle } from "../test/mount";
import { Saved } from "./Saved";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

// A controlled select moved the way a person moves it.
function pick(select: HTMLSelectElement, value: string) {
  Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")?.set?.call(select, value);
  select.dispatchEvent(new Event("change", { bubbles: true }));
}

// A controlled field changed the way a person changes it.
function type(field: HTMLInputElement, value: string) {
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(field, value);
  field.dispatchEvent(new Event("input", { bubbles: true }));
}

function button(label: string): HTMLButtonElement | undefined {
  return Array.from(mount.host().querySelectorAll<HTMLButtonElement>("button")).find(
    (each) => each.textContent === label,
  );
}

// The person's filters, and every PUT the control sends.
function keeping(items: { name: string; query: string }[]) {
  serve((path) =>
    path === "/v1/session/me/saved-filters" ? { data: { items, total: items.length } } : undefined,
  );
  const put = vi.spyOn(api, "PUT").mockImplementation((async () => ({
    data: undefined,
    error: undefined,
    response: new Response(null, { status: 204 }),
  })) as never);
  return () => put.mock.calls as unknown as [string, { body: { query: string } }][];
}

// Saves the list on screen under a name.
async function save(name: string) {
  act(() => button("Save this")?.click());
  const field = mount.host().querySelector<HTMLInputElement>('input[type="text"]');
  if (!field) throw new Error("no name field");
  act(() => type(field, name));
  act(() => button("Save")?.click());
  await settle();
}

describe("a saved filter", () => {
  it("opens within the branch and variant on screen", async () => {
    keeping([{ name: "kernel", query: "component=linux" }]);
    mount.render(
      screen(
        <Saved onBuild={false} onPicked={() => {}} />,
        "/f?stream=main&severity=critical&variant=x86",
      ),
    );
    await settle();
    const select = mount.host().querySelector<HTMLSelectElement>("select");
    if (!select) throw new Error("no saved filters control");
    act(() => pick(select, "kernel"));
    await settle();
    expect(location()).toBe("/f?component=linux&stream=main&variant=x86");
    // Open, because what it keeps is what the list is narrowed by.
    expect(select.value).toBe("kernel");
  });

  it("is kept without its scope, and saying so", async () => {
    const sent = keeping([]);
    mount.render(
      screen(<Saved onBuild={false} onPicked={() => {}} />, "/f?stream=main&exploited=1"),
    );
    await settle();
    await save("exploited");
    expect(sent()[0]?.[1].body.query).toBe("exploited=1");
    expect(mount.host().querySelector('[role="status"]')?.textContent).toBe(
      "Saved. Applies to whatever branch and variant you're viewing.",
    );
  });

  it("says so when saved on one build, whose branch and variant are in the path", async () => {
    keeping([]);
    mount.render(screen(<Saved onBuild onPicked={() => {}} />, "/f?exploited=1"));
    await settle();
    await save("exploited");
    expect(mount.host().querySelector('[role="status"]')?.textContent).toBe(
      "Saved. Applies to whatever branch and variant you're viewing.",
    );
  });

  it("says only that it saved where there was no scope to leave out", async () => {
    const sent = keeping([]);
    mount.render(screen(<Saved onBuild={false} onPicked={() => {}} />, "/f?exploited=1"));
    await settle();
    await save("exploited");
    expect(sent()[0]?.[1].body.query).toBe("exploited=1");
    expect(mount.host().querySelector('[role="status"]')?.textContent).toBe("Saved.");
  });
});
