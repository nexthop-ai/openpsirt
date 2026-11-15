// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { describe, expect, it } from "vitest";
import { Me } from "./Me";
import { ROLES } from "../ui/roles";
import { answer, screen, serve, settle, mounted, type Answer } from "../test/mount";
import { button, change, only, press } from "../test/controls";

const mount = mounted();

const me = {
  identity: "ana",
  name: "Ana",
  admin: false,
  kind: "person",
  reach: [],
  reachable: true,
  digest: false,
};

function deployment(tokens: Answer, digest = { on: false }, everywhere = false) {
  serve((path) => {
    if (path === "/v1/session/me") return { data: { ...me, digest: digest.on, everywhere } };
    if (path === "/v1/tokens") return tokens;
    if (path === "/v1/products") return { data: { items: [{ name: "sonic" }, { name: "edge" }] } };
    return { data: { items: [], total: 0 } };
  });
}

describe("a person's own page", () => {
  it("says a role across every product covers each product once declared", async () => {
    deployment({ data: { items: [], total: 0 } }, { on: false }, true);
    mount.render(screen(<Me />));
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("Every product, as each is declared.");
    expect(text).not.toContain("An administrator grants access.");
  });

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
    answer("PUT", () => {
      digest.on = true;
      return { status: 204 };
    });
    mount.render(screen(<Me />));
    await settle();
    const box = () =>
      Array.from(mount.host().querySelectorAll<HTMLInputElement>('input[type="checkbox"]'))[0];
    expect(box()?.checked).toBe(false);
    act(() => box()?.click());
    await settle();
    expect(box()?.checked).toBe(true);
  });

  describe("making a token", () => {
    const field = <T extends Element>(selector: string) => {
      const found = mount.host().querySelector<T>(selector);
      if (!found) throw new Error(`no field ${selector}`);
      return found;
    };
    const named = () => field<HTMLInputElement>('input[placeholder="nightly report"]');
    const lasting = () => field<HTMLInputElement>('input[type="number"]');

    async function drawn() {
      deployment({ data: { items: [{ name: "nightly" }], total: 1 } });
      mount.render(screen(<Me />));
      await settle();
    }

    it("narrows a reading-only token to every reading role and the one product picked", async () => {
      await drawn();
      const sent = answer("POST", () => ({ data: { name: "nightly", secret: "s3cr3t" } }));
      change(named(), "nightly");
      change(field<HTMLSelectElement>('select[aria-label="The token\'s reach"]'), "sonic");
      change(field<HTMLSelectElement>('select[aria-label="The token\'s roles"]'), "read");
      await press(mount.host(), "Make a token");
      await settle();
      const [path, init] = only(sent);
      expect(path).toBe("/v1/tokens");
      expect(init.body).toEqual({
        name: "nightly",
        lifetime: "720h",
        product: "sonic",
        holds: ROLES.filter((each) => each.role.endsWith("-read")).map((each) => each.role),
      });
    });

    it("carries every role and reaches every product where nothing narrows it", async () => {
      await drawn();
      const sent = answer("POST", () => ({ data: { name: "nightly", secret: "s3cr3t" } }));
      change(named(), "  nightly  ");
      await press(mount.host(), "Make a token");
      await settle();
      expect(only(sent)[1].body).toEqual({ name: "nightly", lifetime: "720h" });
    });

    it("makes no token without a lifetime", async () => {
      await drawn();
      change(named(), "nightly");
      expect(button(mount.host(), "Make a token").disabled).toBe(false);
      change(lasting(), "");
      expect(button(mount.host(), "Make a token").disabled).toBe(true);
    });

    it("shows the secret once, until it is dismissed", async () => {
      await drawn();
      answer("POST", () => ({ data: { name: "nightly", secret: "s3cr3t" } }));
      change(named(), "nightly");
      await press(mount.host(), "Make a token");
      await settle();
      expect(mount.host().textContent).toContain("s3cr3t — shown once.");
      await press(mount.host(), "Done");
      expect(mount.host().textContent).not.toContain("s3cr3t");
    });

    it("withdraws a token by its name", async () => {
      await drawn();
      const sent = answer("DELETE", () => ({ status: 204 }));
      await press(mount.host(), "Withdraw");
      await settle();
      const [path, init] = only(sent);
      expect(path).toBe("/v1/tokens/{name}");
      expect(init.params?.path).toEqual({ name: "nightly" });
    });
  });
});
