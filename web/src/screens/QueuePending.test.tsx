// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { describe, expect, it } from "vitest";
import { Embargoes, Ratings } from "./QueuePending";
import { accept, client, mounted, screen, settle, watchInvalidations } from "../test/mount";
import { only } from "../test/controls";

const mount = mounted();

// The Agree button on the card for one issue.
function agreeOn(issue: string): HTMLButtonElement {
  const card = Array.from(mount.host().querySelectorAll(".card")).find(
    (each) => each.querySelector(".id")?.textContent === issue,
  );
  const found = Array.from(card?.querySelectorAll("button") ?? []).find(
    (each) => each.textContent === "Agree",
  );
  if (!found) throw new Error(`no Agree on ${issue}`);
  return found;
}

describe("a disclosure movement waiting for a second person", () => {
  const movement = (id: number, vulnerability: string, mine: boolean) => ({
    id,
    vulnerability,
    product: "sonic",
    by: mine ? "ana" : "bo",
    mine,
    act: "extension" as const,
    asked_at: "2026-11-01T00:00:00Z",
    reason: "The fix slipped.",
    was: "2026-12-01",
    until: "2027-01-01",
    days: 31,
  });

  async function drawn() {
    const queries = client();
    const invalidated = watchInvalidations(queries);
    const sent = accept(() => ({ data: {} }));
    mount.render(
      screen(
        <Embargoes
          waiting={[movement(3, "CVE-2026-3", true), movement(4, "CVE-2026-4", false)]}
          total={2}
        />,
        "/",
        "*",
        queries,
      ),
    );
    await settle();
    return { sent, invalidated };
  }

  it("cannot be agreed to by the person who asked for it", async () => {
    await drawn();
    expect(agreeOn("CVE-2026-3").disabled).toBe(true);
    expect(agreeOn("CVE-2026-4").disabled).toBe(false);
  });

  it("is agreed to at its own approval and moves the movements read", async () => {
    const { sent, invalidated } = await drawn();
    act(() => agreeOn("CVE-2026-4").click());
    await settle();
    const [path, init] = only(sent);
    expect(path).toBe("/v1/disclosure-movements/{id}/approval");
    expect(init.params?.path).toEqual({ id: 4 });
    expect(invalidated()).toEqual(["movements"]);
  });

  it("says a failed read could not be read", () => {
    mount.render(screen(<Embargoes waiting={[]} error={new Error("down")} />));
    expect(mount.host().textContent).toContain(
      "Requests to move a disclosure date could not be read.",
    );
  });

  it("draws nothing where nothing waits", () => {
    mount.render(screen(<Embargoes waiting={[]} total={0} />));
    expect(mount.host().textContent).toBe("");
  });
});

describe("a rating waiting for a second person", () => {
  const rating = (id: number, vulnerability: string, mine: boolean, offTheList: number) => ({
    id,
    vulnerability,
    product: "sonic",
    published: "high",
    severity: "low" as const,
    reasoning: "Not reachable in our builds.",
    open: 5,
    off_the_list: offTheList,
    mine,
  });

  async function drawn() {
    const queries = client();
    const invalidated = watchInvalidations(queries);
    const sent = accept(() => ({ data: {} }));
    mount.render(
      screen(
        <Ratings
          waiting={[rating(5, "CVE-2026-5", true, 0), rating(6, "CVE-2026-6", false, 3)]}
          total={2}
        />,
        "/",
        "*",
        queries,
      ),
    );
    await settle();
    return { sent, invalidated };
  }

  it("says how many findings a rating takes off the working list, and where none, that it does not", async () => {
    await drawn();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("This takes 3 of them off the working list in sonic.");
    expect(text).toContain("Still above sonic's minimum severity: later work, not no work.");
  });

  it("cannot be agreed to by the person who rated it", async () => {
    await drawn();
    expect(agreeOn("CVE-2026-5").disabled).toBe(true);
    expect(agreeOn("CVE-2026-6").disabled).toBe(false);
    expect(mount.host().textContent).toContain("Yours, so somebody else agrees to it.");
  });

  it("is agreed to at its own agreement and moves the queue", async () => {
    const { sent, invalidated } = await drawn();
    act(() => agreeOn("CVE-2026-6").click());
    await settle();
    const [path, init] = only(sent);
    expect(path).toBe("/v1/assessments/{id}/agreement");
    expect(init.params?.path).toEqual({ id: 6 });
    expect(invalidated()).toEqual(["queue"]);
  });

  it("says a failed read could not be read", () => {
    mount.render(screen(<Ratings waiting={[]} error={new Error("down")} />));
    expect(mount.host().textContent).toContain("Ratings awaiting approval could not be read.");
  });
});
