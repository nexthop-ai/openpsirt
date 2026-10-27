// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { describe, expect, it } from "vitest";
import { Shell } from "./Shell";
import { location, mounted, screen, serve, settle, type Answer } from "../test/mount";
import type { Who } from "./session";

const mount = mounted();

const who = {
  identity: "ana",
  name: "Ana",
  admin: false,
  kind: "person" as const,
  reach: [],
  outcomes: [],
};

// Where the top search lands for a term, given how the issue route answers.
async function searched(term: string, issue: Answer): Promise<string> {
  serve((path) => (path === "/v1/issues/{issue}" ? issue : { data: { items: [], total: 0 } }));
  mount.render(screen(<Shell who={who}>{null}</Shell>, "/start"));
  await settle();
  const box = mount
    .host()
    .querySelector<HTMLInputElement>('input[aria-label="Find an issue, or a component"]');
  if (!box) throw new Error("no top search");
  act(() => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(box, term);
    box.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await act(async () => box.form?.requestSubmit());
  await settle();
  return location();
}

describe("the top search", () => {
  it("opens an issue somebody here carries", async () => {
    const at = await searched("CVE-2026-1", { data: { items: [{}], total: 1 } });
    expect(at).toContain("CVE-2026-1");
  });

  it("searches components for a term no issue here answers to", async () => {
    const at = await searched("openssl", { data: { items: [], total: 0 } });
    expect(at).toContain("q=openssl");
    expect(mount.host().textContent).not.toContain("could not be looked up");
  });

  it("stays put when the issue could not be read", async () => {
    const at = await searched("openssl", { status: 503 });
    expect(at).toBe("/start");
    expect(mount.host().textContent).toContain("could not be looked up");
  });
});

// The rail as drawn for one reach, at one address.
async function railAt(at: string, reach: Record<string, unknown>[]) {
  window.sessionStorage.clear();
  serve(() => ({ data: { items: [], total: 0 } }));
  mount.render(
    screen(<Shell who={{ ...who, reach: reach as unknown as Who["reach"] }}>{null}</Shell>, at),
  );
  await settle();
}

const entry = (label: string) =>
  [...mount.host().querySelectorAll<HTMLElement>("a, button")].find(
    (each) => each.textContent?.trim() === label,
  );

describe("the code findings entry", () => {
  it("is absent for somebody who reads internal material nowhere", async () => {
    await railAt("/products/sonic", [{ product: "sonic", reads_private: true }]);
    expect(entry("Security testing")).toBeUndefined();
  });

  it("declines and says so where no product is picked", async () => {
    await railAt("/start", [{ product: "sonic", reads_internal: true }]);
    expect(entry("Security testing")?.tagName).toBe("BUTTON");
    expect(entry("Security testing")?.title).toBe("Pick a product");
  });

  it("declines and says so where the reader may not read internal material", async () => {
    await railAt("/products/other", [{ product: "sonic", reads_internal: true }]);
    expect(entry("Security testing")?.tagName).toBe("BUTTON");
    expect(entry("Security testing")?.title).toBe(
      "You can't read internal material in this product",
    );
  });

  it("opens the product's queue on the branch and variant picked", async () => {
    await railAt("/products/sonic/branches-and-tags/main/variants/x86", [
      { product: "sonic", reads_internal: true },
    ]);
    expect(entry("Security testing")?.getAttribute("href")).toBe(
      "/products/sonic/code-findings?branch_or_tag=main&variant=x86",
    );
  });

  it("opens every build's queue where only the product is picked", async () => {
    await railAt("/products/sonic", [{ product: "sonic", reads_internal: true }]);
    expect(entry("Security testing")?.getAttribute("href")).toBe("/products/sonic/code-findings");
  });
});
