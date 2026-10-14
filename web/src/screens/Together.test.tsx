// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Together } from "./Together";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const ISSUES =
  "/v1/products/{product}/streams/{stream}/variants/{variant}/components/{component}/issues";

describe("narrowing a bulk decision", () => {
  it("keeps the component it was opened for", async () => {
    const reads = serve(() => ({ data: { items: [], total: 0 } }));
    mount.render(
      screen(
        <Together />,
        "/products/sonic/streams/master/variants/x/components/openssl/decide?version=1.1.1w&ecosystem=deb",
        "/products/:product/streams/:stream/variants/:variant/components/:component/decide",
      ),
    );
    await settle();
    const box = mount.host().querySelector<HTMLInputElement>(".searchbox input");
    if (!box) throw new Error("no narrowing box");
    act(() => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(
        box,
        "driver",
      );
      box.dispatchEvent(new Event("input", { bubbles: true }));
    });
    act(() => {
      box.form?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    });
    await settle();
    const calls = reads.mock.calls as unknown as [string, { params: { query: object } }][];
    const last = calls.filter(([path]) => path === ISSUES).at(-1);
    expect(last?.[1].params.query).toMatchObject({
      contains: "driver",
      version: "1.1.1w",
      ecosystem: "deb",
    });
  });
});
