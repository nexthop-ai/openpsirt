// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import type { Body } from "../api/client";
import { Priors } from "./FindingPriors";
import { button, press } from "../test/controls";
import { mounted } from "../test/mount";

const mount = mounted();

const said: Body<"SaidBody"> = {
  id: 7,
  publisher: "Broadcom",
  status: "not_affected",
  about: "3.8",
  justification: "vulnerable_code_not_present",
  statement: "The driver does not call it.",
  offers: "not-applicable",
  source: "vex",
  document: "bcm-2026-01",
  at: "2026-10-01T00:00:00Z",
};

const similar: Body<"SimilarBody"> = {
  decision_id: 41,
  decision_occurrence_id: 410,
  issues: 3,
  justification: "component_not_present",
  reasoning: "Not built into this image.",
  approved_by: "bob",
  approved_by_name: "Bob",
};

const elsewhere: Body<"ElsewhereBody"> = {
  decision_id: 52,
  decision_occurrence_id: 520,
  product: "edge",
  outcome: "wont-fix",
  reasoning: "Reachable only from the console.",
};

function draw({ extending = false } = {}) {
  const startFrom = vi.fn();
  const setExtending = vi.fn();
  mount.render(
    <Priors
      publishers={[said]}
      similar={[similar]}
      elsewhere={[elsewhere]}
      extending={extending}
      setExtending={setExtending}
      startFrom={startFrom}
      mayTriage
    />,
  );
  return { startFrom, setExtending };
}

describe("what others have said about an undecided finding", () => {
  it("says nothing was received where no publisher has spoken", () => {
    mount.render(
      <Priors
        publishers={[]}
        similar={[]}
        elsewhere={[]}
        extending={false}
        setExtending={vi.fn()}
        startFrom={vi.fn()}
        mayTriage
      />,
    );
    expect(mount.host().textContent).toContain("Nothing received");
  });

  it("starts a decision from a statement citing it and the version it was about", async () => {
    const { startFrom } = draw();
    await press(mount.host(), "Start from this");
    expect(startFrom).toHaveBeenCalledWith({
      fromStatement: 7,
      outcome: "not-applicable",
      justification: "vulnerable_code_not_present",
      reasoning: "Broadcom says not affected of 3.8: The driver does not call it.\n\n",
    });
  });

  it("shows a statement's status notes as written and carries them into the form", async () => {
    const startFrom = vi.fn();
    const notes = "Backported in **3.8-2**; see <b>DSA-1</b>";
    mount.render(
      <Priors
        publishers={[{ ...said, status: "fixed", statement: undefined, notes }]}
        similar={[]}
        elsewhere={[]}
        extending={false}
        setExtending={vi.fn()}
        startFrom={startFrom}
        mayTriage
      />,
    );
    expect(mount.host().textContent).toContain(notes);
    expect(mount.host().querySelector(".why b, .why strong")).toBeNull();
    await press(mount.host(), "Start from this");
    expect(startFrom).toHaveBeenCalledWith(
      expect.objectContaining({
        reasoning: `Broadcom says fixed of 3.8\n${notes}\n\n`,
      }),
    );
  });

  it("applies an approved decision here by extending it", async () => {
    const { startFrom, setExtending } = draw();
    await press(mount.host(), "Apply decision #41 to this issue →");
    expect(setExtending).toHaveBeenCalledWith({ decisionId: 41, decisionOccurrenceId: 410 });
    expect(startFrom).toHaveBeenCalledWith({
      outcome: "not-applicable",
      justification: "component_not_present",
      reasoning: "Not built into this image.",
    });
  });

  it("carries another product's words and never its outcome", async () => {
    const { startFrom } = draw();
    await press(mount.host(), "Start from these words →");
    expect(startFrom).toHaveBeenCalledWith({
      reasoning: "Reachable only from the console.\n\n_Quoted from edge; checked here._",
    });
  });

  it("hides the decisions to apply while one is being extended", () => {
    draw({ extending: true });
    expect(() => button(mount.host(), "Apply decision #41 to this issue →")).toThrow();
    expect(() => button(mount.host(), "Start from these words →")).toThrow();
    expect(button(mount.host(), "Start from this")).toBeTruthy();
  });
});
