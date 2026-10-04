// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - plain ESM with no types of its own
import { cssRules } from "../../scripts/class-rules.mjs";
// @ts-expect-error - plain ESM with no types of its own
import { stylesheets } from "../../scripts/source.mjs";
import { mounted } from "../test/mount";
import { Exploited, ExploitedHere } from "./Severity";

const mount = mounted();

const badge = () => mount.host().querySelector("span");

// The background each rule written for exactly this selector sets, across
// every stylesheet, in order. The last one is what a badge carrying only those
// classes is drawn with.
function backgrounds(selector: string): string[] {
  const found: string[] = [];
  for (const text of stylesheets() as string[]) {
    for (const rule of cssRules(text) as { selector: string; body: string }[]) {
      if (!rule.selector.split(",").some((part) => part.trim() === selector)) continue;
      const set = /(?:^|;)\s*background\s*:\s*([^;]+)/.exec(rule.body);
      if (set?.[1]) found.push(set[1].trim());
    }
  }
  return found;
}

describe("the two exploitation badges", () => {
  it("names the feed's flag as known exploited and says it is not an attack here", () => {
    mount.render(<Exploited when />);
    expect(badge()?.textContent).toBe("Known exploited");
    expect(badge()?.title).toContain("Not, on its own, a sign this product was attacked");
  });

  it("marks only the record of being exploited here with the class that tells them apart", () => {
    mount.render(<Exploited when />);
    expect(badge()?.classList.contains("here")).toBe(false);
    mount.render(<ExploitedHere when />);
    expect(badge()?.textContent).toBe("Exploited here");
    expect(badge()?.classList.contains("here")).toBe(true);
  });

  it("draws the feed's flag as an outline, with no fill", () => {
    const set = backgrounds(".kev");
    expect(set, "no rule for the feed's badge was found, so this checked nothing").not.toEqual([]);
    expect(set.at(-1)).toBe("transparent");
  });

  it("draws a record of being exploited here filled in the exploited color", () => {
    const set = backgrounds(".kev.here");
    expect(set, "no rule for the record's badge was found, so this checked nothing").not.toEqual(
      [],
    );
    expect(set.at(-1)).toBe("var(--sev-exploited)");
  });

  it("draws neither where the fact is absent", () => {
    mount.render(
      <>
        <Exploited when={false} />
        <ExploitedHere />
      </>,
    );
    expect(mount.host().textContent).toBe("");
  });
});
