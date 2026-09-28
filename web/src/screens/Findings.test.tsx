// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Findings } from "./Findings";
import { location, mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const me = { identity: "ana", name: "Ana", admin: false, kind: "person", reach: [] };

async function draw(address: string) {
  serve((path) => (path === "/v1/session/me" ? { data: me } : { data: { items: [], total: 0 } }));
  mount.render(screen(<Findings />, address, "/findings"));
  await settle();
}

const buttons = () => Array.from(mount.host().querySelectorAll<HTMLButtonElement>("button"));
const chip = (text: string) => buttons().find((each) => each.textContent?.includes(text));
// The chips above the list, each as "Label: value", without the clear-all.
const chips = () =>
  Array.from(mount.host().querySelectorAll<HTMLButtonElement>(".narrowed button.chip")).map(
    (each) => (each.textContent ?? "").replace("×", "").trim(),
  );
const query = () => new URLSearchParams(location().split("?")[1] ?? "");

describe("the filters narrowing the findings list", () => {
  // Verified by making the chip's click clear every filter: the decision
  // states go with it and the test fails.
  it("removes one chip's filter and leaves the rest of the address", async () => {
    await draw("/findings?exploited=1&only=exploited&sent_back=1");
    const exploited = chip("Known exploited:");
    expect(exploited, "no chip for known exploited").toBeDefined();
    act(() => exploited?.click());
    await settle();
    expect(query().get("exploited")).toBeNull();
    expect(query().get("only")).toBeNull();
    expect(query().get("sent_back")).toBe("1");
  });

  // Verified by writing the flag with `set` alone: `only=exploited` is left in
  // the address, still narrows the list, and the test fails on it.
  it("unticks known exploited however the address spelled it", async () => {
    await draw("/findings?only=exploited");
    act(() => chip("More filters")?.click());
    await settle();
    const box = Array.from(mount.host().querySelectorAll("label.check")).find(
      (each) => each.textContent === "Known exploited",
    );
    const input = box?.querySelector<HTMLInputElement>("input");
    expect(input?.checked, "the flag does not read only=exploited as on").toBe(true);
    act(() => input?.click());
    await settle();
    expect(query().get("only")).toBeNull();
    expect(query().get("exploited")).toBeNull();
  });

  // Verified by dropping the offset delete from the list's filter change: the
  // address keeps offset=50 and the test fails on it.
  it("starts a list narrowed from the panel at its first page", async () => {
    await draw("/findings?offset=50");
    act(() => chip("More filters")?.click());
    await settle();
    const box = Array.from(mount.host().querySelectorAll("label.check")).find(
      (each) => each.textContent === "Sent back to its author",
    );
    act(() => box?.querySelector<HTMLInputElement>("input")?.click());
    await settle();
    expect(query().get("sent_back")).toBe("1");
    expect(query().get("offset")).toBeNull();
  });

  // The list's own defaults (release kind, support, planned work) are filters
  // like any other and draw chips, so clearing all has to widen past them
  // rather than drop every parameter and let the defaults come back.
  //
  // Verified by clearing all with an empty address: the default chips are
  // drawn again and the test fails on them.
  it("clears every chip it counts, the list's own defaults included", async () => {
    await draw("/findings?sent_back=1");
    const drawn = chips();
    expect(drawn).toContain("Sent back to its author: only");
    const all = chip(`Clear all ${drawn.length} filters`);
    expect(all, `no clear-all naming ${drawn.length}`).toBeDefined();
    act(() => all?.click());
    await settle();
    expect(chips()).toEqual([]);
    expect(query().get("sent_back")).toBeNull();
  });
});
