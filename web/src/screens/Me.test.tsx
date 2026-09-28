// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { Me } from "./Me";
import { screen, serve, settle, mounted, type Answer } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const me = {
  identity: "ana",
  name: "Ana",
  admin: false,
  kind: "person",
  reach: [],
  reachable: true,
  digest: false,
};

function deployment(tokens: Answer, digest = { on: false }) {
  serve((path) => {
    if (path === "/v1/session/me") return { data: { ...me, digest: digest.on } };
    if (path === "/v1/tokens") return tokens;
    return { data: { items: [], total: 0 } };
  });
}

describe("a person's own page", () => {
  it("says the tokens could not be read rather than that none are held", async () => {
    deployment({ status: 503 });
    mount.render(screen(<Me />));
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("Your tokens could not be read.");
    expect(text).not.toContain("You hold no tokens.");
  });

  it("says a token nobody has used was never used, and one with no end never expires", async () => {
    deployment({ data: { items: [{ name: "ci" }], total: 1 } });
    mount.render(screen(<Me />));
    await settle();
    const cells = Array.from(mount.host().querySelectorAll("td.hint")).map((c) => c.textContent);
    expect(cells).toContain("never");
    expect(cells).toContain("—");
  });

  it("shows the digest as set once the server has taken it", async () => {
    const digest = { on: false };
    deployment({ data: { items: [], total: 0 } }, digest);
    vi.spyOn(api, "PUT").mockImplementation((async () => {
      digest.on = true;
      return { data: undefined, error: undefined, response: new Response(null, { status: 204 }) };
    }) as never);
    mount.render(screen(<Me />));
    await settle();
    const box = () =>
      Array.from(mount.host().querySelectorAll<HTMLInputElement>('input[type="checkbox"]'))[0];
    expect(box()?.checked).toBe(false);
    act(() => box()?.click());
    await settle();
    expect(box()?.checked).toBe(true);
  });
});
