// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Settings } from "./Settings";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const ADMIN = {
  identity: "ana",
  name: "Ana",
  admin: true,
  kind: "person" as const,
  reach: [],
  outcomes: [],
};

function type(field: HTMLInputElement | null, value: string) {
  if (!field) throw new Error("no such field");
  act(() => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(field, value);
    field.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

async function shown(setting: Record<string, unknown>) {
  serve((path) =>
    path === "/v1/settings"
      ? {
          data: {
            items: [
              {
                name: "disclosure.after",
                section: "disclosure",
                title: "Default embargo period",
                summary: "How long.",
                ...setting,
              },
            ],
          },
        }
      : { data: { items: [] } },
  );
  mount.render(screen(<Settings who={ADMIN} />, "/settings/disclosure", "/settings/:section"));
  await settle();
}

const saves = () =>
  Array.from(mount.host().querySelectorAll("button")).filter((b) => b.textContent === "Save");

describe("a duration setting", () => {
  it("offers no save for a default nobody touched", async () => {
    await shown({ kind: "duration", value: "2160h0m0s", default: true });
    expect(saves()).toHaveLength(0);
  });

  it("offers a save once a different length is typed", async () => {
    await shown({ kind: "duration", value: "2160h0m0s", default: true });
    type(mount.host().querySelector<HTMLInputElement>('input[type="number"]'), "30");
    expect(saves()).toHaveLength(1);
  });

  it("offers no save for a fraction, which would be stored rounded", async () => {
    await shown({ kind: "duration", value: "2160h0m0s", default: true });
    type(mount.host().querySelector<HTMLInputElement>('input[type="number"]'), "1.5");
    expect(saves()).toHaveLength(0);
    expect(mount.host().textContent).toContain("A whole number of one or more.");
  });
});
