// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { milderThan, startingRating } from "./FindingAssess";
import { References } from "./FindingEvidence";
import { ExploitedHere } from "./FindingExploited";
import { screen, mounted } from "../test/mount";
import { FLOORS } from "../ui/severities";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

describe("rating an issue ourselves", () => {
  it("opens on a word the form offers", () => {
    expect(startingRating(undefined, "negligible")).toBe("medium");
    expect(startingRating(undefined, "none")).toBe("medium");
    expect(startingRating("", "high")).toBe("high");
    expect(startingRating("low", "high")).toBe("low");
  });

  it("calls nothing milder than a published word below low", () => {
    for (const rating of FLOORS) {
      expect(milderThan(rating, "negligible"), rating).toBe(false);
      expect(milderThan(rating, "none"), rating).toBe(false);
    }
  });

  it("calls a lower rung milder than the published one", () => {
    expect(milderThan("low", "high")).toBe(true);
    expect(milderThan("critical", "high")).toBe(false);
    expect(milderThan("low", "")).toBe(true);
  });
});

describe("the references a finding cites", () => {
  const refs = Array.from({ length: 15 }, (_, i) => ({
    url: `https://example.test/${i}`,
    kind: "report",
  }));

  it("says how many are folded away, and shows them when asked", () => {
    mount.render(screen(<References refs={refs} />));
    const links = () => mount.host().querySelectorAll("li").length;
    expect(links()).toBe(12);
    const more = Array.from(mount.host().querySelectorAll("button")).find((each) =>
      each.textContent?.includes("3 more"),
    );
    expect(more).toBeDefined();
    act(() => more?.click());
    expect(links()).toBe(15);
  });
});

describe("recording that a product was exploited", () => {
  it("closes a form opened on one issue on arriving at another", () => {
    const draw = (vulnerability: string) =>
      mount.render(
        screen(<ExploitedHere product="sonic" vulnerability={vulnerability} mayTriage />),
      );
    draw("CVE-2026-1");
    const open = Array.from(mount.host().querySelectorAll("button")).find((each) =>
      each.textContent?.includes("Record exploited here"),
    );
    act(() => open?.click());
    expect(mount.host().querySelector("textarea, input")).not.toBeNull();
    draw("CVE-2026-2");
    expect(mount.host().textContent).toContain("Record exploited here");
  });
});
