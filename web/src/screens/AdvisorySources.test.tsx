// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AdvisorySources, KNOWN_SUPPLIERS } from "./AdvisorySources";
import { screen, serve, settle, mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

// The panel with a product picked and the add form open, over a product that
// already reads the given suppliers.
async function adding(already: { name: string; url: string }[]) {
  serve((path) => {
    if (path === "/v1/products") return { data: { items: [{ name: "sonic" }], total: 1 } };
    if (path === "/v1/products/{product}/advisory-sources") {
      return { data: { items: already } };
    }
    return { data: { items: [], total: 0 } };
  });
  mount.render(screen(<AdvisorySources />, "/settings/suppliers"));
  await settle();
  const select = mount.host().querySelector<HTMLSelectElement>("select[aria-label=Product]");
  if (!select) throw new Error("no product list");
  act(() => {
    const set = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")?.set;
    set?.call(select, "sonic");
    select.dispatchEvent(new Event("change", { bubbles: true }));
  });
  await settle();
  const open = Array.from(document.querySelectorAll("button")).find(
    (each) => each.textContent?.trim() === "Add supplier",
  );
  act(() => open?.click());
  await settle();
}

function preset(label: string) {
  return Array.from(document.querySelectorAll<HTMLButtonElement>("button.chip")).find(
    (each) => each.textContent === label,
  );
}

function field(label: string) {
  const id = `declare-${label.replace(/\s+/g, "-").toLowerCase()}`;
  return document.getElementById(id) as HTMLInputElement | null;
}

describe("the well-known suppliers", () => {
  it("fills the form with the publisher's name and directory", async () => {
    await adding([]);
    const suse = KNOWN_SUPPLIERS.find((each) => each.name === "suse");
    act(() => preset("SUSE")?.click());
    await settle();
    expect(field("Name")?.value).toBe("suse");
    expect(field("Provider directory")?.value).toBe(suse?.url);
  });

  it("offers no publisher the product already reads, by name or by address", async () => {
    const redhat = KNOWN_SUPPLIERS.find((each) => each.name === "redhat");
    await adding([
      { name: "RedHat", url: "https://example.com/elsewhere.json" },
      { name: "our-suse", url: KNOWN_SUPPLIERS.find((each) => each.name === "suse")?.url ?? "" },
    ]);
    expect(redhat).toBeDefined();
    expect(preset("Red Hat")?.disabled).toBe(true);
    expect(preset("SUSE")?.disabled).toBe(true);
    expect(preset("Cisco")?.disabled).toBe(false);
  });
});
