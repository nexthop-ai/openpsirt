// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Branches } from "./Branches";
import { button, change, press } from "../test/controls";
import { answer, mounted, screen, serve, settle, type Sent } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const ADDRESS = "/products/sonic/streams";
const PATTERN = "/products/:product/streams";

function serving(admin: boolean) {
  serve((path) => {
    if (path === "/v1/session/me") {
      return { data: { identity: "ana", name: "Ana", admin, kind: "person", reach: [] } };
    }
    if (path === "/v1/products/{product}/streams") {
      return {
        data: {
          items: [
            { name: "master", kind: "branch", open: 3 },
            { name: "202411", kind: "tag", parent: "master", released_on: "2024-11-01" },
          ],
        },
      };
    }
    return undefined;
  });
}

// The open drawer, where the form's own buttons are.
function drawer(): HTMLElement {
  const open = mount.host().querySelector<HTMLElement>(".drawer.open");
  if (!open) throw new Error("no drawer is open");
  return open;
}

const bodyOf = (sent: Sent) => (sent[1] as { body: unknown }).body;
const pathOf = (sent: Sent) => (sent[1] as { params: { path: unknown } }).params.path;

describe("the branches and tags of a product", () => {
  it("declares a tag with the branch it was cut from", async () => {
    serving(true);
    const posted = answer("POST", () => ({ data: {} }));
    mount.render(screen(<Branches />, ADDRESS, PATTERN));
    await settle();
    await press(mount.host(), "Add branch or tag");
    expect(button(drawer(), "Add branch").disabled).toBe(true);
    change(drawer().querySelector("#declare-name"), " 202505 ");
    change(drawer().querySelector("#declare-kind"), "tag");
    change(drawer().querySelector("#declare-cut-from"), "master");
    await press(drawer(), "Add tag");
    await settle();
    expect(posted().map(bodyOf)).toEqual([{ name: "202505", kind: "tag", parent: "master" }]);
  });

  it("declares a branch with no parent, even after one was picked for a tag", async () => {
    serving(true);
    const posted = answer("POST", () => ({ data: {} }));
    mount.render(screen(<Branches />, ADDRESS, PATTERN));
    await settle();
    await press(mount.host(), "Add branch or tag");
    change(drawer().querySelector("#declare-name"), "next");
    change(drawer().querySelector("#declare-kind"), "tag");
    change(drawer().querySelector("#declare-cut-from"), "master");
    change(drawer().querySelector("#declare-kind"), "branch");
    await press(drawer(), "Add branch");
    await settle();
    expect(posted().map(bodyOf)).toEqual([{ name: "next", kind: "branch" }]);
  });

  it("renames the release whose row was edited", async () => {
    serving(true);
    const patched = answer("PATCH", () => ({ data: {} }));
    mount.render(screen(<Branches />, ADDRESS, PATTERN));
    await settle();
    const edits = Array.from(mount.host().querySelectorAll("button")).filter(
      (each) => each.textContent === "Edit",
    );
    act(() => edits[1]?.click());
    await settle();
    change(drawer().querySelector("#declare-name"), " 2024.11 ");
    await press(drawer(), "Save");
    await settle();
    expect(patched().map(pathOf)).toEqual([{ product: "sonic", stream: "202411" }]);
    expect(patched().map(bodyOf)).toEqual([{ name: "2024.11" }]);
  });

  it("retires the release on the row pressed", async () => {
    serving(true);
    const removed = answer("DELETE", () => ({ data: {} }));
    mount.render(screen(<Branches />, ADDRESS, PATTERN));
    await settle();
    await press(mount.host(), "Retire");
    await settle();
    expect(removed().map(pathOf)).toEqual([{ product: "sonic", stream: "master" }]);
  });

  it("offers nothing to change to somebody who is not an administrator", async () => {
    serving(false);
    mount.render(screen(<Branches />, ADDRESS, PATTERN));
    await settle();
    expect(mount.host().textContent).toContain("Branches and tags");
    for (const label of ["Add branch or tag", "Edit", "Retire"]) {
      expect(() => button(mount.host(), label)).toThrow();
    }
  });
});
