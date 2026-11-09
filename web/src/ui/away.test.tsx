// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act, useRef } from "react";
import { describe, expect, it } from "vitest";
import { mounted } from "../test/mount";
import { useClickAway } from "./away";

const mount = mounted();

function Box({ close }: { close: () => void }) {
  const box = useRef<HTMLDivElement>(null);
  useClickAway(box, true, close);
  return <div ref={box}>inside</div>;
}

function pressOutside() {
  act(() => {
    document.body.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));
  });
}

describe("click away", () => {
  it("calls the close of the latest render, never one an earlier render passed", () => {
    const calls: string[] = [];
    mount.render(<Box close={() => calls.push("first")} />);
    mount.render(<Box close={() => calls.push("second")} />);
    pressOutside();
    expect(calls).toEqual(["second"]);
  });
});
