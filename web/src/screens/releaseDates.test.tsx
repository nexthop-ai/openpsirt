// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EndOfLife } from "../ui/EndOfLife";
import { Branches } from "./Branches";
import { answer, mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

function type(field: HTMLInputElement | null, value: string) {
  if (!field) throw new Error("no such field");
  act(() => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(field, value);
    field.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

const save = () =>
  Array.from(mount.host().querySelectorAll("button")).find((b) => b.textContent === "Save");

describe("a tag's release date", () => {
  it("is written once, on Save, however many changes the box fires", async () => {
    serve((path) => {
      if (path === "/v1/session/me") {
        return { data: { identity: "ana", name: "Ana", admin: true, kind: "person", reach: [] } };
      }
      if (path === "/v1/products/{product}/streams") {
        return { data: { items: [{ name: "v1.0", kind: "tag", parent: "master" }] } };
      }
      return { data: { items: [] } };
    });
    const put = answer("PUT", () => ({ status: 204 }));
    mount.render(screen(<Branches />, "/products/sonic/streams", "/products/:product/streams"));
    await settle();
    const box = mount.host().querySelector<HTMLInputElement>('input[aria-label="Released"]');
    type(box, "0002-01-01");
    type(box, "0202-01-01");
    type(box, "2026-01-01");
    expect(put()).toHaveLength(0);
    act(() => save()?.click());
    await settle();
    expect(put()).toHaveLength(1);
    const sent = put()[0] as [string, { body: { released_on: string } }];
    expect(sent[1].body.released_on).toBe("2026-01-01");
  });
});

describe("an inherited end of support", () => {
  it("can be stated as the same date, so it stops following", () => {
    const onSet = vi.fn();
    mount.render(
      <EndOfLife what="v1.0 goes out of support" on="2027-01-01" inherited admin onSet={onSet} />,
    );
    expect(save()).toBeUndefined();
    type(mount.host().querySelector<HTMLInputElement>('input[type="date"]'), "2027-01-01");
    act(() => save()?.click());
    expect(onSet).toHaveBeenCalledWith("2027-01-01");
  });
});
