// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { describe, expect, it } from "vitest";
import { Components } from "./Components";
import { location, mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

describe("the components screen", () => {
  it("asks for a name and searches nothing where none is in the address", async () => {
    const spy = serve(() => ({ data: { items: [] } }));
    mount.render(screen(<Components />, "/components", "/components"));
    await settle();
    expect(mount.host().textContent).toContain("Type part of a component’s name.");
    expect(spy).not.toHaveBeenCalledWith("/v1/components", expect.anything());
  });

  it("lands on the components the name matches", async () => {
    serve(() => ({ data: { items: [] } }));
    mount.render(screen(<Components />, "/components", "*"));
    await settle();
    const box = mount
      .host()
      .querySelector<HTMLInputElement>('input[aria-label="Part of a component’s name"]');
    if (!box) throw new Error("no name box");
    act(() => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(
        box,
        " openssl ",
      );
      box.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await act(async () => box.form?.requestSubmit());
    await settle();
    expect(location()).toBe("/search/openssl");
  });
});
