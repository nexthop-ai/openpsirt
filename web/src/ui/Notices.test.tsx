// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Notices } from "./Notices";
import { answer, location, mounted, screen, serve, settle, type Answer } from "../test/mount";
import { only, press } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const WAITING: Answer = {
  data: {
    total: 2,
    items: [
      {
        id: 7,
        kind: "assigned",
        body: "You were given CVE-2026-1",
        link: "/findings/x",
        at: "2026-01-01T00:00:00Z",
      },
      {
        id: 8,
        kind: "queue-stuck",
        lifetime: "condition",
        body: "The queue is stuck",
        at: "2026-01-01T00:00:00Z",
      },
    ],
  },
};

async function opened(read: Answer = WAITING) {
  serve((path) => (path === "/v1/notifications" ? read : undefined));
  const gone = answer("DELETE", () => ({ data: {} }));
  mount.render(screen(<Notices />, "/start"));
  await settle();
  const bell = mount.host().querySelector<HTMLButtonElement>("button.bell");
  await act(async () => bell?.click());
  return { bell, gone };
}

describe("the notices waiting on somebody", () => {
  it("says how many are waiting on the bell", async () => {
    const { bell } = await opened();
    expect(bell?.getAttribute("aria-label")).toBe("2 waiting on you");
  });

  it("takes one notice off by its own identifier", async () => {
    const { gone } = await opened();
    const [first] = Array.from(mount.host().querySelectorAll<HTMLButtonElement>("li button"));
    await act(async () => first?.click());
    await settle();
    const [path, init] = only(gone);
    expect(path).toBe("/v1/notifications/{id}");
    expect(init.params?.path).toEqual({ id: 7 });
  });

  it("clears all of them in one request", async () => {
    const { gone } = await opened();
    await press(mount.host(), "Clear all");
    await settle();
    expect(only(gone)[0]).toBe("/v1/notifications");
  });

  it("says a condition comes back rather than going away", async () => {
    await opened();
    const [, second] = Array.from(mount.host().querySelectorAll<HTMLButtonElement>("li button"));
    expect(second?.title).toContain("It will come back");
    expect(mount.host().querySelectorAll(".noticekind.holds")).toHaveLength(1);
  });

  it("closes on following a notice's link", async () => {
    await opened();
    const link = mount.host().querySelector<HTMLAnchorElement>("li a");
    await act(async () => link?.click());
    expect(location()).toBe("/findings/x");
    expect(mount.host().querySelector(".noticelist")).toBeNull();
  });

  it("says the notices could not be read rather than that none are waiting", async () => {
    const { bell } = await opened({ status: 503 });
    expect(bell?.getAttribute("aria-label")).toBe("Notices could not be read");
    expect(mount.host().textContent).not.toContain("Nothing is waiting on you.");
  });
});
