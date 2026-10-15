// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { Suggest } from "./Suggest";
import { mounted } from "../test/mount";
import { change } from "../test/controls";

const mount = mounted();

function Host({ onPick, options }: { onPick: (name: string) => void; options: string[] }) {
  const [value, setValue] = useState("");
  return (
    <>
      <Suggest id="s" value={value} onChange={setValue} onPick={onPick} options={options} />
      <output>{value}</output>
    </>
  );
}

function drawn(options = ["linux", "libnl"]) {
  const onPick = vi.fn<(name: string) => void>();
  mount.render(<Host onPick={onPick} options={options} />);
  const box = mount.host().querySelector<HTMLInputElement>("#s");
  if (!box) throw new Error("no box");
  return { box, onPick };
}

const shown = () =>
  Array.from(mount.host().querySelectorAll('[role="option"]')).map((each) => each.textContent);

function key(box: HTMLInputElement, name: string) {
  act(() => {
    box.dispatchEvent(new KeyboardEvent("keydown", { key: name, bubbles: true }));
  });
}

describe("a text box that suggests", () => {
  it("offers nothing until two characters are typed", () => {
    const { box } = drawn();
    change(box, "l");
    expect(shown()).toEqual([]);
    change(box, "li");
    expect(shown()).toEqual(["linux", "libnl"]);
  });

  it("picks from the keyboard, wrapping past either end", () => {
    const { box, onPick } = drawn();
    change(box, "li");
    key(box, "ArrowUp");
    key(box, "Enter");
    expect(onPick).toHaveBeenCalledWith("libnl");
    expect(mount.host().querySelector("output")?.textContent).toBe("libnl");
    expect(shown()).toEqual([]);
  });

  it("closes on Escape", () => {
    const { box } = drawn();
    change(box, "li");
    key(box, "Escape");
    expect(shown()).toEqual([]);
  });

  it("says nothing is called what was typed", () => {
    const { box } = drawn([]);
    change(box, "zz");
    expect(mount.host().textContent).toContain("Nothing here is called that.");
  });
});
