// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { Findings } from "./Findings";
import { location, mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const me = { identity: "ana", name: "Ana", admin: false, kind: "person", reach: [] };

// Two filters keeping one query, which only their names tell apart.
const kept = [
  { name: "alpha", query: "component=linux" },
  { name: "beta", query: "component=linux" },
];

// The list across every product, with the person's filters, and every name
// the control is asked to forget.
async function draw(address: string) {
  serve((path) => {
    if (path === "/v1/session/me") return { data: me };
    if (path === "/v1/session/me/saved-filters") return { data: { items: kept, total: 2 } };
    return { data: { items: [], total: 0 } };
  });
  const forgot = vi.spyOn(api, "DELETE").mockImplementation((async () => ({
    data: undefined,
    error: undefined,
    response: new Response(null, { status: 204 }),
  })) as never);
  mount.render(screen(<Findings />, address, "/findings"));
  await settle();
  return () =>
    (forgot.mock.calls as unknown as [string, { params: { path: { name: string } } }][]).map(
      ([, init]) => init.params.path.name,
    );
}

const control = () =>
  mount.host().querySelector<HTMLSelectElement>('select[aria-label="Open a saved filter"]');
const button = (label: string) =>
  Array.from(mount.host().querySelectorAll<HTMLButtonElement>("button")).find(
    (each) => each.textContent === label,
  );
const query = () => new URLSearchParams(location().split("?")[1] ?? "");

function pick(value: string) {
  const select = control();
  if (!select) throw new Error("no saved filters control");
  Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")?.set?.call(select, value);
  select.dispatchEvent(new Event("change", { bubbles: true }));
}

describe("the saved filter a list is open under", () => {
  it.each(["alpha", "beta"])(
    "is the one picked, of two keeping one query, and Forget takes that one (%s)",
    async (name) => {
      const forgotten = await draw("/findings");
      act(() => pick(name));
      await settle();
      expect(query().get("component")).toBe("linux");
      expect(query().get("rule")).toBe(name);
      expect(control()?.value).toBe(name);
      act(() => button("Forget")?.click());
      await settle();
      expect(forgotten()).toEqual([name]);
    },
  );

  it("is none once a filter changes after picking, and the name leaves the address", async () => {
    await draw("/findings");
    act(() => pick("beta"));
    await settle();
    act(() => button("New today")?.click());
    await settle();
    expect(query().get("rule")).toBeNull();
    expect(control()?.value).toBe("");
  });

  it("is found by its query where the address names none", async () => {
    await draw("/findings?component=linux");
    expect(control()?.value).toBe("alpha");
  });
});
