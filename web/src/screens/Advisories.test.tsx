// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { Advisories } from "./Advisories";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

function press(label: string) {
  const found = Array.from(mount.host().querySelectorAll("button")).find(
    (each) => each.textContent?.trim() === label,
  );
  if (!found) throw new Error(`no button ${label}`);
  act(() => found.click());
}

function change(field: HTMLInputElement | HTMLSelectElement | null, value: string) {
  if (!field) throw new Error("no such field");
  const proto = field instanceof HTMLSelectElement ? HTMLSelectElement : HTMLInputElement;
  act(() => {
    Object.getOwnPropertyDescriptor(proto.prototype, "value")?.set?.call(field, value);
    field.dispatchEvent(
      new Event(field instanceof HTMLSelectElement ? "change" : "input", { bubbles: true }),
    );
  });
}

describe("starting an advisory", () => {
  it("keeps a name minted by a refused start when the card is closed and opened again", async () => {
    serve((path) => {
      if (path === "/v1/session/me") {
        return {
          data: {
            identity: "ana",
            name: "Ana",
            admin: false,
            kind: "person",
            reach: [{ product: "sonic", name: "sonic", may_triage: true }],
          },
        };
      }
      if (path === "/v1/products") return { data: { items: [{ name: "sonic" }] } };
      return { data: { items: [], total: 0 } };
    });
    const posted = vi.spyOn(api, "POST").mockImplementation((async (path: string) =>
      path === "/v1/advisories"
        ? { data: { advisory: "SONIC-2026-1" }, response: new Response(null, { status: 201 }) }
        : {
            error: { detail: "a scanner's report" },
            response: new Response(null, { status: 422 }),
          }) as never);
    mount.render(screen(<Advisories />));
    await settle();

    const attempt = async () => {
      press("Start an advisory");
      await settle();
      change(mount.host().querySelector(".card select"), "sonic");
      change(
        mount.host().querySelector<HTMLInputElement>('.card input[list="advisory-flaws"]'),
        "CVE-2026-1",
      );
      press("Start");
      await settle();
    };
    await attempt();
    press("Start an advisory");
    await settle();
    await attempt();

    const minted = (posted.mock.calls as unknown as [string][]).filter(
      ([path]) => path === "/v1/advisories",
    );
    expect(minted).toHaveLength(1);
  });
});
