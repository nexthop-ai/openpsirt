// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SupplierAdvisoryFeeds, KNOWN_SUPPLIERS } from "./SupplierAdvisoryFeeds";
import { api } from "../api/client";
import { accept, screen, serve, settle, mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

// The panel with a product picked and the add form open, over a product that
// already reads the given suppliers.
async function adding(already: { name: string; url: string }[]) {
  serve((path) => {
    if (path === "/v1/products") return { data: { items: [{ name: "sonic" }], total: 1 } };
    if (path === "/v1/products/{product}/supplier-advisory-feeds") {
      return { data: { items: already } };
    }
    return { data: { items: [], total: 0 } };
  });
  mount.render(screen(<SupplierAdvisoryFeeds />, "/settings/suppliers"));
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
    (each) => each.textContent?.trim() === "Add feed",
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
  it("fills the form with the publisher's name and directory, and adds nothing", async () => {
    await adding([]);
    const sent = vi.spyOn(api, "POST");
    const suse = KNOWN_SUPPLIERS.find((each) => each.name === "suse");
    act(() => preset("SUSE")?.click());
    await settle();
    expect(field("Name")?.value).toBe("suse");
    expect(field("Provider directory")?.value).toBe(suse?.url);
    expect(sent).not.toHaveBeenCalled();
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

// The panel with a product picked, over a product that reads no supplier.
async function picked() {
  serve((path) => {
    if (path === "/v1/products") return { data: { items: [{ name: "sonic" }], total: 1 } };
    return { data: { items: [], total: 0 } };
  });
  mount.render(screen(<SupplierAdvisoryFeeds />, "/settings/suppliers"));
  await settle();
  const select = mount.host().querySelector<HTMLSelectElement>("select[aria-label=Product]");
  if (!select) throw new Error("no product list");
  choose(select, "sonic");
  await settle();
}

function choose(select: HTMLSelectElement, value: string) {
  act(() => {
    Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")?.set?.call(select, value);
    select.dispatchEvent(new Event("change", { bubbles: true }));
  });
}

describe("uploading a VEX statement set", () => {
  it("sends the publisher typed, which a document naming none needs", async () => {
    await picked();
    const sent = accept(() => ({
      data: { publisher: "debian-vex.json", recorded: 1, superseded: 0 },
    }));
    const kind = Array.from(document.querySelectorAll<HTMLSelectElement>("select")).find((each) =>
      Array.from(each.options).some((option) => option.value === "statements"),
    );
    if (!kind) throw new Error("no kind list");
    choose(kind, "statements");
    await settle();
    expect(document.body.textContent).not.toContain("whole previous statement set");
    const typed = Array.from(document.querySelectorAll<HTMLLabelElement>("label.field"))
      .find((each) => each.textContent?.startsWith("Publisher"))
      ?.querySelector("input");
    if (!typed) throw new Error("no publisher box");
    act(() => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(
        typed,
        " debian-vex.json ",
      );
      typed.dispatchEvent(new Event("input", { bubbles: true }));
    });
    const chooser = mount.host().querySelector<HTMLInputElement>('input[type="file"]');
    if (!chooser) throw new Error("no file control");
    Object.defineProperty(chooser, "files", { value: [new File(["{}"], "empty.json")] });
    act(() => {
      chooser.dispatchEvent(new Event("change", { bubbles: true }));
    });
    await settle();
    const button = Array.from(document.querySelectorAll("button")).find(
      (each) => each.textContent?.trim() === "Upload",
    );
    act(() => button?.click());
    await settle();
    const [path, init] = sent()[0] ?? [];
    expect(path).toBe("/v1/products/{product}/vex-documents");
    expect((init as { params: { query?: { publisher?: string } } }).params.query).toEqual({
      publisher: "debian-vex.json",
    });
  });
});
