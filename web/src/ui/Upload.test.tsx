// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { mounted, screen, serve, settle } from "../test/mount";
import { UploadDrawer } from "./Upload";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

// A controlled select moved the way a person moves it.
function pick(select: HTMLSelectElement, value: string) {
  const set = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")?.set;
  set?.call(select, value);
  select.dispatchEvent(new Event("change", { bubbles: true }));
}

describe("an upload that is already held", () => {
  it("names the build it was sent to, whatever the target became while it was on its way", async () => {
    serve((path) => {
      if (path === "/v1/products") return { data: { items: [{ name: "sonic" }] } };
      if (path === "/v1/products/{product}/streams") {
        return { data: { items: [{ name: "master" }, { name: "release" }] } };
      }
      if (path === "/v1/products/{product}/variants") {
        return { data: { items: [{ name: "broadcom" }] } };
      }
      return { data: { items: [] } };
    });
    let answer: (value: unknown) => void = () => undefined;
    const sent = vi.spyOn(api, "POST").mockImplementation(
      (() =>
        new Promise((done) => {
          answer = done;
        })) as never,
    );

    mount.render(
      screen(
        <UploadDrawer open onClose={() => undefined} />,
        "/products/sonic/streams/master/variants/broadcom/inventories",
        "/products/:product/streams/:stream/variants/:variant/inventories",
      ),
    );
    await settle();
    const host = mount.host();
    const input = host.querySelector<HTMLInputElement>('input[type="file"]');
    expect(input, "no file input").not.toBeNull();
    const file = new File(["{}"], "bom.json", { type: "application/json" });
    Object.defineProperty(input, "files", { value: [file], configurable: true });
    act(() => {
      input?.dispatchEvent(new Event("change", { bubbles: true }));
    });
    const upload = Array.from(host.querySelectorAll("button")).find(
      (each) => each.textContent === "Upload",
    );
    await act(async () => upload?.click());
    expect(sent).toHaveBeenCalledTimes(1);

    // The branch moved while the file was on its way.
    const branch = host.querySelector<HTMLSelectElement>('select[aria-label="Branch or tag"]');
    act(() => {
      if (branch) pick(branch, "release");
    });
    expect(branch?.value).toBe("release");

    await act(async () => {
      answer({
        data: { outcome: "already_held", scan_id: 7 },
        response: new Response(null, { status: 200 }),
      });
    });
    await settle();
    expect(host.textContent).toContain("sonic · master · broadcom already holds this inventory");
  });
});
