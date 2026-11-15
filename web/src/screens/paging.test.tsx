// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { describe, expect, it } from "vitest";
import { DisclosureDeadlines } from "./DisclosureDeadlines";
import { Assignments } from "./Assignments";
import { location, screen, serve, settle, mounted } from "../test/mount";
import { change, press } from "../test/controls";
import { readingDependencies } from "../test/reach";

// A list narrowed or switched starts at its own beginning, and a page past the
// end of a list says how to get back rather than that the list is empty.
const mount = mounted();

// A reader of dependency findings, who sees who else holds them.
const me = {
  identity: "ana",
  name: "Ana",
  admin: false,
  kind: "person",
  reach: [readingDependencies("sonic")],
};

describe("the assignments screen", () => {
  it("offers the way back from a page past the end of what somebody holds", async () => {
    serve((path) => {
      if (path === "/v1/session/me") return { data: me };
      if (path === "/v1/people/{identity}/assignments") return { data: { items: [], total: 10 } };
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Assignments />, "/assignments?tab=people&person=alice&offset=50"));
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
    mount.render(screen(<Assignments />, "/assignments?tab=people&offset=50"));
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

describe("the disclosure deadlines screen", () => {
  it("starts a narrowed list at its beginning", async () => {
    const asked: unknown[] = [];
    serve((path, init) => {
      if (path === "/v1/session/me") return { data: me };
      if (path === "/v1/disclosure-deadlines") {
        asked.push((init as { params: { query: { offset: number } } }).params.query.offset);
        return { data: { items: [], total: 250 } };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<DisclosureDeadlines />, "/disclosure-deadlines"));
    await settle();
    await press(mount.host(), "Next");
    await settle();
    expect(asked).toEqual([0, 100]);
    change(mount.host().querySelector("select"), "7");
    await settle();
    expect(asked.at(-1)).toBe(0);
  });
});
