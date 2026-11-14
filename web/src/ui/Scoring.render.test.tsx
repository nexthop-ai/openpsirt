// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Scoring } from "./Scoring";
import { change } from "../test/controls";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

describe("a score seeded from a vector", () => {
  it("never composes a value its scheme does not offer", async () => {
    serve(() => ({ data: {} }));
    const onChange = vi.fn();
    mount.render(
      screen(<Scoring vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:P/S:U/C:H/I:H/A:H" onChange={onChange} />),
    );
    await settle();
    const open = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Change the score",
    );
    act(() => open?.click());
    change(mount.host().querySelector<HTMLSelectElement>("#cvss-C"), "L");
    expect(onChange).toHaveBeenLastCalledWith("");
  });
});
