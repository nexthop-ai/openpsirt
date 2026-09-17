import { describe, expect, it } from "vitest";

import { meansFor, moved, typingIn } from "./keys";

// What a key means over a list of findings, and — the part worth pinning —
// when it means nothing. A triager typing "j" into a justification does not
// mean "next row", and a key that fired anyway would move the list out from
// under the form they were filling in.

describe("what a key means over the rows", () => {
  it("moves, opens, closes and follows", () => {
    expect(meansFor({ key: "j" }, false)).toBe("next");
    expect(meansFor({ key: "ArrowDown" }, false)).toBe("next");
    expect(meansFor({ key: "k" }, false)).toBe("previous");
    expect(meansFor({ key: "ArrowUp" }, false)).toBe("previous");
    expect(meansFor({ key: "Enter" }, false)).toBe("open");
    expect(meansFor({ key: "Escape" }, false)).toBe("close");
    expect(meansFor({ key: "o" }, false)).toBe("openFull");
  });

  it("means nothing while somebody is typing", () => {
    for (const key of ["j", "k", "o", "Enter", "ArrowDown"]) {
      expect(meansFor({ key }, true), key).toBeNull();
    }
  });

  it("leaves a modified key to the browser", () => {
    expect(meansFor({ key: "j", metaKey: true }, false)).toBeNull();
    expect(meansFor({ key: "o", ctrlKey: true }, false)).toBeNull();
    expect(meansFor({ key: "ArrowDown", altKey: true }, false)).toBeNull();
  });

  it("answers nothing for a key that is not ours", () => {
    expect(meansFor({ key: "x" }, false)).toBeNull();
    expect(meansFor({ key: "/" }, false)).toBeNull();
  });
});

describe("whether what has focus takes typing", () => {
  const element = (tag: string, editable = false) => {
    const made = document.createElement(tag);
    if (editable) made.setAttribute("contenteditable", "true");
    return made;
  };

  it("says so for the three controls that do", () => {
    expect(typingIn(element("input"))).toBe(true);
    expect(typingIn(element("textarea"))).toBe(true);
    expect(typingIn(element("select"))).toBe(true);
  });

  it("says so for the editor's own body", () => {
    const editing = element("div", true);
    // jsdom does not compute isContentEditable from the attribute, and what
    // the browser answers is the property — so the property is what is asked.
    Object.defineProperty(editing, "isContentEditable", { value: true });
    expect(typingIn(editing)).toBe(true);
  });

  it("says no for a row, a button and nothing at all", () => {
    expect(typingIn(element("tr"))).toBe(false);
    expect(typingIn(element("button"))).toBe(false);
    expect(typingIn(null)).toBe(false);
  });
});

describe("where the cursor lands", () => {
  it("starts at the first row and at the last", () => {
    expect(moved(-1, 1, 50)).toBe(0);
    expect(moved(-1, -1, 50)).toBe(49);
  });

  it("stops at each end rather than wrapping", () => {
    // The list is paged, so wrapping from the last row to the first would say
    // the page is the whole list.
    expect(moved(49, 1, 50)).toBe(49);
    expect(moved(0, -1, 50)).toBe(0);
  });

  it("has nowhere to go on an empty page", () => {
    expect(moved(-1, 1, 0)).toBe(-1);
    expect(moved(3, -1, 0)).toBe(-1);
  });
});
