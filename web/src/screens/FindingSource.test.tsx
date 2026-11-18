// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { describe, expect, it } from "vitest";

import { SourceMatch } from "./FindingSource";
import { accept, mounted, screen, settle } from "../test/mount";
import { change } from "../test/controls";

const mount = mounted();

function press(label: string) {
  const button = Array.from(mount.host().querySelectorAll("button")).find((each) =>
    each.textContent?.includes(label),
  );
  if (!button) throw new Error(`no button ${label}`);
  return act(async () => button.click());
}

describe("a match made through a source package", () => {
  it("says nothing about a match on the package itself", () => {
    mount.render(
      screen(<SourceMatch product="sonic" vulnerability="CVE-1" component="curl" mayTriage />),
    );
    expect(mount.host().textContent).toBe("");
  });

  it("names the source and the files the record lists", () => {
    mount.render(
      screen(
        <SourceMatch
          product="sonic"
          vulnerability="CVE-1"
          component="linux-perf"
          through="linux"
          files={["drivers/phy/ti/phy-omap-usb2.c"]}
          mayTriage={false}
        />,
      ),
    );
    const text = mount.host().textContent ?? "";
    expect(text).toContain("linux");
    expect(text).toContain("drivers/phy/ti/phy-omap-usb2.c");
    expect(text).not.toContain("Correct by source paths");
  });

  it("proposes for the package and source matched, with the paths typed one a line", async () => {
    const sent = accept(() => ({ data: { decision_id: 4, answered: 12 }, status: 201 }));
    mount.render(
      screen(
        <SourceMatch
          product="sonic"
          vulnerability="CVE-1"
          component="linux-perf"
          through="linux"
          files={["drivers/x.c"]}
          mayTriage
        />,
      ),
    );
    await press("Correct by source paths");
    change(
      mount.host().querySelector<HTMLTextAreaElement>("#sourcepaths"),
      "tools/perf\n\n tools/lib \n",
    );
    change(
      mount.host().querySelector<HTMLTextAreaElement>("#sourcereasoning"),
      "Built from tools/.",
    );
    await press("Propose");
    await settle();
    const body = (sent()[0]?.[1] as { body: Record<string, unknown> }).body;
    expect(body).toEqual({
      package: "linux-perf",
      source: "linux",
      paths: ["tools/perf", "tools/lib"],
      justification: "vulnerable_code_not_present",
      reasoning: "Built from tools/.",
    });
    expect(mount.host().textContent).toContain("Answers 12 now");
  });
});
