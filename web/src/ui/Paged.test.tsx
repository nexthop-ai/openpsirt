// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { describe, expect, it, vi } from "vitest";
import { Paged } from "./Paged";
import { mounted } from "../test/mount";

const mount = mounted();

describe("a page past the end of a list", () => {
  it("says it holds nothing, and goes back to the last page that holds anything", () => {
    const onGo = vi.fn();
    mount.render(<Paged shown={0} total={140} offset={250} limit={50} onGo={onGo} />);
    expect(mount.host().textContent).toContain("Nothing on this page of 140");
    expect(mount.host().textContent).not.toContain("Showing");
    const previous = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Previous",
    );
    act(() => previous?.click());
    expect(onGo).toHaveBeenCalledWith(100);
  });

  it("goes back one page from a page that holds rows", () => {
    const onGo = vi.fn();
    mount.render(<Paged shown={10} total={110} offset={100} limit={50} onGo={onGo} />);
    expect(mount.host().textContent).toContain("Showing 101–110 of 110");
    const previous = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Previous",
    );
    act(() => previous?.click());
    expect(onGo).toHaveBeenCalledWith(50);
  });
});
