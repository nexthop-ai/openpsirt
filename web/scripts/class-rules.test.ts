import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { positionedModifiers, rulesIn } from "./class-rules.mjs";

// A class used as a modifier beside another, which also has a rule of its own
// that takes an element out of normal flow, positions anything carrying both
// by a rule written for something else. The gate that finds those had no test.

describe("how a stylesheet is read", () => {
  it("reads a bare class as a declaration", () => {
    const { declared } = rulesIn(`.chip { padding: 2px; }`);
    expect(declared.get("chip")).toContain("padding: 2px");
  });

  it("reads the second class of a pair as a modifier", () => {
    const { declared, modifiers } = rulesIn(`.chip.over { color: red; }`);
    expect(modifiers.get("over")).toBe(".chip.over");
    // And the first is not: it is what the modifier modifies.
    expect(declared.has("chip")).toBe(false);
  });

  it("reads each side of a comma as its own selector", () => {
    const { declared, modifiers } = rulesIn(`.chip, .tag.over { color: red; }`);
    expect(declared.has("chip")).toBe(true);
    expect(modifiers.get("over")).toBe(".tag.over");
  });

  it("drops comments before reading", () => {
    // A rule is read as the text before its brace, and a comment sitting above
    // one is part of that text — so a prose paragraph above `.overpane` was
    // read as the selector and the rule was never seen.
    const { declared } = rulesIn(`/* a note about .overpane */\n.overpane { position: fixed; }`);
    expect(declared.get("overpane")).toContain("position: fixed");
  });

  it("leaves a selector that is not only class names", () => {
    const { declared, modifiers } = rulesIn(
      `.chip:hover { color: red; }\n.chip > .tag { color: blue; }\ndiv { margin: 0; }`,
    );
    expect(declared.size).toBe(0);
    expect(modifiers.size).toBe(0);
  });

  it("gathers a class declared in more than one rule", () => {
    const { declared } = rulesIn(`.chip { padding: 2px; }\n.chip { color: red; }`);
    expect(declared.get("chip")).toContain("padding: 2px");
    expect(declared.get("chip")).toContain("color: red");
  });
});

describe("which modifiers cannot be right", () => {
  const found = (css: string) => positionedModifiers(rulesIn(css));

  it("reports a modifier whose own rule positions", () => {
    expect(found(`.over { position: fixed; }\n.chip.over { color: red; }`)).toEqual(["over"]);
  });

  it("reports each of the three ways out of normal flow", () => {
    for (const rule of ["position: fixed", "position: absolute", "position: sticky", "inset: 0"]) {
      expect(found(`.over { ${rule}; }\n.chip.over { color: red; }`)).toEqual(["over"]);
    }
  });

  it("leaves a modifier that shares a name with a text style", () => {
    // `.linkish.id` beside a bare `.id` that sets a font is two rules that
    // agree, and reporting it would make the gate fire on ordinary CSS.
    expect(found(`.id { font-family: mono; }\n.linkish.id { color: red; }`)).toEqual([]);
  });

  it("leaves a modifier with no bare rule at all", () => {
    expect(found(`.chip.over { color: red; }`)).toEqual([]);
  });

  it("leaves a positioning rule nothing uses as a modifier", () => {
    expect(found(`.overpane { position: fixed; }`)).toEqual([]);
  });

  it("does not read position inside another property's value", () => {
    // `background-position` is not `position`, and a gate that reported it
    // would be one people learn to work around.
    expect(found(`.over { background-position: 0 0; }\n.chip.over { color: red; }`)).toEqual([]);
  });
});
