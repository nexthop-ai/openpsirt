import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { withoutComments } from "./tokens.mjs";

// A `var(--thing)` naming a token that does not exist is an error nowhere: CSS
// drops the declaration, the element keeps whatever it inherited, and the
// screen looks nearly right. This gate puts every reference to the set of
// definitions, and every definition to the set of references — and it read
// prose as both.

describe("a comment is prose, not a reference", () => {
  it("drops a line comment", () => {
    // The block explaining why a color is not composed at run time has to
    // write the shape it is not composing, and that read as a token named and
    // defined nowhere.
    expect(
      withoutComments(`// var(--sev-critical) is not composed here\nconst x = 1;`),
    ).not.toContain("var(");
  });

  it("drops a block comment", () => {
    expect(withoutComments(`/* a --gone: 8px was here */\nconst x = 1;`)).not.toContain("--gone");
  });

  it("keeps the code beside a comment", () => {
    const kept = withoutComments(`const x = "var(--kept)"; // and a note about var(--noted)`);
    expect(kept).toContain("var(--kept)");
    expect(kept).not.toContain("var(--noted)");
  });

  it("keeps a token inside a string that holds a double slash", () => {
    // A `//` inside quotes is part of the value, not the start of a comment.
    // Cutting there would take the rest of the line with it, so a definition
    // after one would look like a token nothing refers to.
    const kept = withoutComments(`const at = "https://example.test"; const c = "var(--kept)";`);
    expect(kept).toContain("var(--kept)");
  });

  it("changes nothing where there is no comment", () => {
    const source = `:root { --sev-high: #d9700a; }`;
    expect(withoutComments(source)).toBe(source);
  });
});
