// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Disclosing } from "./Disclosing";
import { Work } from "./Work";
import { location, screen, serve, settle, mounted } from "../test/mount";

// A list narrowed or switched starts at its own beginning, and a page past the
// end of a list says how to get back rather than that the list is empty.
const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const me = { identity: "ana", name: "Ana", admin: false, kind: "person", reach: [] };

describe("the assignments screen", () => {
  it("offers the way back from a page past the end of what somebody holds", async () => {
    serve((path) => {
      if (path === "/v1/session/me") return { data: me };
      if (path === "/v1/people/{identity}/assignments") return { data: { items: [], total: 10 } };
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Work />, "/work?tab=people&person=alice&offset=50"));
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).not.toContain("They are not holding anything.");
    expect(mount.host().querySelector("button.chip")).not.toBeNull();
  });

  it("starts another holder's list at its beginning", async () => {
    serve((path) => {
      if (path === "/v1/session/me") return { data: me };
      if (path === "/v1/assignments") {
        return { data: { items: [{ person: "bob", open: 3 }], total: 1 } };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Work />, "/work?tab=people&offset=50"));
    await settle();
    const bob = Array.from(mount.host().querySelectorAll("button")).find((each) =>
      each.textContent?.includes("bob"),
    );
    act(() => bob?.click());
    await settle();
    expect(location()).toContain("person=bob");
    expect(location()).not.toContain("offset");
  });
});

describe("the disclosing screen", () => {
  it("starts a narrowed list at its beginning", async () => {
    const asked: unknown[] = [];
    serve((path, init) => {
      if (path === "/v1/disclosing") {
        asked.push((init as { params: { query: { offset: number } } }).params.query.offset);
        return { data: { items: [], total: 250 } };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Disclosing />, "/disclosing"));
    await settle();
    const next = Array.from(mount.host().querySelectorAll<HTMLButtonElement>("button.chip")).at(-1);
    act(() => next?.click());
    await settle();
    const within = mount.host().querySelector<HTMLSelectElement>("select");
    act(() => {
      if (!within) return;
      within.value = "7";
      within.dispatchEvent(new Event("change", { bubbles: true }));
    });
    await settle();
    expect(asked.at(-1)).toBe(0);
  });
});
