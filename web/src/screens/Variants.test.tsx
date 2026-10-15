// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Variants } from "./Variants";
import { answer, mounted, screen, serve, settle } from "../test/mount";
import { change, labeled, only, press } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const ITEMS = [
  { name: "arm", open: 3 },
  { name: "x86", customer_facing: false, retired: true },
];

async function drawn(at: string, pattern: string, admin = true) {
  const spy = serve((path) => {
    if (path === "/v1/session/me")
      return {
        data: { identity: "ana", name: "Ana", admin, kind: "person", reach: [], outcomes: [] },
      };
    if (path === "/v1/products/{product}/variants") return { data: { items: ITEMS } };
    if (path === "/v1/products/{product}/streams/{stream}/variants")
      return { data: { items: ITEMS } };
    return undefined;
  });
  const writes = {
    post: answer("POST", () => ({ data: {} })),
    patch: answer("PATCH", () => ({ data: {} })),
    del: answer("DELETE", () => ({ data: {} })),
  };
  mount.render(screen(<Variants />, at, pattern));
  await settle();
  return { spy, ...writes };
}

const product = () => drawn("/products/sonic/variants", "/products/:product/variants");
const text = () => mount.host().textContent ?? "";
const buttons = () => Array.from(mount.host().querySelectorAll("button")).map((b) => b.textContent);

describe("the variants a product is built as", () => {
  it("reads a variant nothing classified as shipping to customers", async () => {
    await product();
    const rows = Array.from(mount.host().querySelectorAll("tbody tr"));
    expect(rows[0]?.textContent).toContain("Yes");
    expect(rows[1]?.textContent).toContain("No — internal only");
  });

  it("changes whether one ships without asking to rename it", async () => {
    const { patch } = await product();
    const edits = Array.from(mount.host().querySelectorAll("button")).filter(
      (each) => each.textContent === "Edit",
    );
    await act(async () => edits[0]?.click());
    change(mount.host().querySelector<HTMLSelectElement>("#edit-facing"), "no");
    await press(mount.host(), "Save");
    await settle();
    const [path, init] = only(patch);
    expect(path).toBe("/v1/products/{product}/variants/{variant}");
    expect(init.params?.path).toEqual({ product: "sonic", variant: "arm" });
    expect(init.body).toEqual({ customer_facing: false });
  });

  it("declares a variant under the product, shipping unless said otherwise", async () => {
    const { post } = await product();
    await press(mount.host(), "Add variant");
    change(labeled(mount.host(), "Name"), " mellanox ");
    const add = Array.from(mount.host().querySelectorAll("button")).filter(
      (each) => each.textContent?.trim() === "Add variant",
    );
    await act(async () => add.at(-1)?.click());
    await settle();
    expect(only(post)[1].body).toEqual({ name: "mellanox", customer_facing: true });
  });

  it("retires the variant the row names", async () => {
    const { del } = await product();
    const retire = Array.from(mount.host().querySelectorAll("button")).filter(
      (each) => each.textContent === "Retire",
    );
    await act(async () => retire[1]?.click());
    await settle();
    expect(only(del)[1].params?.path).toEqual({ product: "sonic", variant: "x86" });
  });

  it("offers nobody but an administrator a change", async () => {
    await drawn("/products/sonic/variants", "/products/:product/variants", false);
    expect(buttons()).not.toContain("Edit");
    expect(buttons()).not.toContain("Retire");
  });
});

describe("the variants one release was built as", () => {
  it("asks the release, links each build's findings and names a retired one", async () => {
    const { spy } = await drawn(
      "/products/sonic/streams/master/variants",
      "/products/:product/streams/:stream/variants",
    );
    const asked = (spy.mock.calls as unknown as [string][]).map(([path]) => path);
    expect(asked).toContain("/v1/products/{product}/streams/{stream}/variants");
    expect(asked).not.toContain("/v1/products/{product}/variants");
    expect(text()).toContain("Retired");
    expect(buttons()).not.toContain("Edit");
    const link = mount.host().querySelector("tbody a");
    expect(link?.getAttribute("href")).toContain("/streams/master/variants/arm");
  });
});
