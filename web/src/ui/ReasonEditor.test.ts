import { describe, expect, it } from "vitest";

import { revisable } from "./ReasonEditor";

// Which claims still have something to revise or withdraw.
//
// The two screens that draw the editor each had their own list of the open
// words — one from what became of the claim, one from the decision's state —
// so a claim agreed to in part and set aside in part offered both actions on
// one screen and neither on the other, to the same person about the same
// claim. Said once, as what is finished.
describe("revisable", () => {
  it("offers nothing on a claim that is over", () => {
    for (const state of ["withdrawn", "lapsed"]) {
      expect(revisable(state), state).toBe(false);
    }
  });

  it("offers both on every word that means the claim is still live", () => {
    // Both vocabularies: what the record says became of a claim, and what the
    // API reports as a decision's state.
    for (const state of ["waiting", "sent-back", "undone", "approved", "mixed", "proposed"]) {
      expect(revisable(state), state).toBe(true);
    }
  });

  it("offers nothing where nothing is known", () => {
    expect(revisable("")).toBe(false);
  });
});
