// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act, useEffect } from "react";
import { MemoryRouter, useNavigate, type NavigateFunction } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mounted } from "../test/mount";
import { TO_THE_TOP, useTopOnArrival } from "./arrival";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const held: { go: NavigateFunction } = { go: () => undefined };
const go: NavigateFunction = ((to: never, options?: never) =>
  held.go(to, options)) as NavigateFunction;

function Frame() {
  useTopOnArrival();
  const navigate = useNavigate();
  useEffect(() => {
    held.go = navigate;
  });
  return null;
}

describe("scrolling to the top on arrival", () => {
  it("scrolls on a new screen, not on Back, and not on a push to the same screen", () => {
    const scrolled = vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
    mount.render(
      <MemoryRouter initialEntries={["/findings", "/home"]} initialIndex={1}>
        <Frame />
      </MemoryRouter>,
    );
    scrolled.mockClear();

    act(() => go("/queue"));
    expect(scrolled, "a new screen").toHaveBeenCalledTimes(1);

    scrolled.mockClear();
    act(() => go(-2));
    expect(scrolled, "Back").not.toHaveBeenCalled();

    // A filter ticked on the list somebody came Back to.
    act(() => go("/findings?state=undecided"));
    expect(scrolled, "a push on the same path").not.toHaveBeenCalled();
  });

  it("scrolls on a rail entry for the screen already open, and not on Back to it", () => {
    const scrolled = vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
    mount.render(
      <MemoryRouter initialEntries={["/record"]}>
        <Frame />
      </MemoryRouter>,
    );
    scrolled.mockClear();

    act(() => go("/record", { state: TO_THE_TOP }));
    expect(scrolled, "the same address, from the rail").toHaveBeenCalledTimes(1);

    act(() => go("/record?change=role"));
    scrolled.mockClear();
    act(() => go(-1));
    expect(scrolled, "Back to an entry the rail opened").not.toHaveBeenCalled();
  });
});
