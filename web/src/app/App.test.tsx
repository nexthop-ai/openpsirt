// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { mounted, screen, serve, settle, type Answer } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const WHO = {
  identity: "ana",
  name: "Ana",
  admin: false,
  kind: "person" as const,
  reach: [],
  outcomes: [],
};

// Draws the application at an address, with the identity read answered as
// given and every other read answered empty.
async function drawn(who: () => Answer, at = "/nowhere/at/all") {
  const asked = serve((path) => {
    if (path === "/v1/session/me") return who();
    if (path === "/v1/sign-in") return { data: { items: [] } };
    return { data: { items: [], total: 0 } };
  });
  mount.render(screen(<App />, at));
  await settle();
  return () =>
    (asked.mock.calls as unknown as [string][]).filter(([path]) => path === "/v1/session/me")
      .length;
}

const text = () => mount.host().textContent ?? "";

describe("the application before anybody is known", () => {
  it("says the identity could not be read rather than offering a sign-in", async () => {
    await drawn(() => ({ status: 503 }));
    expect(text()).toContain("The signed-in person could not be read.");
    expect(text()).toContain("Try again");
    expect(mount.host().querySelector(".topsearch")).toBeNull();
  });

  it("asks again when Try again is pressed, and draws the screen it gets", async () => {
    let answer: Answer = { status: 503 };
    const asks = await drawn(() => answer);
    expect(asks()).toBe(1);
    answer = { data: WHO };
    const again = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Try again",
    );
    await act(async () => again?.click());
    await settle();
    expect(asks()).toBe(2);
    expect(text()).not.toContain("The signed-in person could not be read.");
    expect(mount.host().querySelector(".topsearch")).not.toBeNull();
  });

  it("offers a way in to a browser nobody is signed in on", async () => {
    await drawn(() => ({ status: 401 }));
    expect(text()).toContain("Sign in to continue");
    expect(text()).not.toContain("The signed-in person could not be read.");
    expect(mount.host().querySelector(".topsearch")).toBeNull();
  });
});

describe("the application for somebody signed in", () => {
  it("keeps an address it does not answer in the bar and says so", async () => {
    await drawn(() => ({ data: WHO }));
    expect(mount.host().querySelector(".topsearch")).not.toBeNull();
    expect(text()).toContain("A link from outside the application can also point at a screen");
  });
});
