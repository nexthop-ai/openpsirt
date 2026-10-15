// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act, useState } from "react";
import { describe, expect, it } from "vitest";
import { Words } from "./Words";
import { mounted } from "../test/mount";
import { change } from "../test/controls";

const mount = mounted();

function Host({ start = [] as string[] }) {
  const [words, setWords] = useState(start);
  return (
    <>
      <Words
        label="Tags"
        words={words}
        onChange={setWords}
        named={(word) => (word === "k" ? { called: "kernel", full: "The kernel team" } : undefined)}
      />
      <output>{words.join("|")}</output>
    </>
  );
}

const field = () => mount.host().querySelector<HTMLInputElement>("input");
const held = () => mount.host().querySelector("output")?.textContent;

function key(name: string) {
  act(() => {
    field()?.dispatchEvent(new KeyboardEvent("keydown", { key: name, bubbles: true }));
  });
}

describe("a field of words", () => {
  it("takes each word a comma finishes and keeps typing after the last", () => {
    mount.render(<Host />);
    change(field(), "a, b ,a, c");
    expect(held()).toBe("a|b");
    expect(field()?.value).toBe(" c");
  });

  it("takes a word on Enter, and ignores one already held", () => {
    mount.render(<Host start={["a"]} />);
    change(field(), " b ");
    key("Enter");
    change(field(), "a");
    key("Enter");
    expect(held()).toBe("a|b");
    expect(field()?.value).toBe("");
  });

  it("takes the last word back on Backspace in an empty field", () => {
    mount.render(<Host start={["a", "b"]} />);
    key("Backspace");
    expect(held()).toBe("a");
  });

  it("removes the word pressed, saying what it names", () => {
    mount.render(<Host start={["k", "x"]} />);
    const chip = mount.host().querySelector<HTMLButtonElement>("button.chip");
    expect(chip?.title).toBe("The kernel team. Remove this one");
    expect(chip?.textContent).toContain("k kernel");
    act(() => chip?.click());
    expect(held()).toBe("x");
  });
});
