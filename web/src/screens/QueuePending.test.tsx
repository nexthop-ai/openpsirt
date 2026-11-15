// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Embargoes, Ratings } from "./QueuePending";
import { accept, client, mounted, screen, settle, watchInvalidations } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const MOVEMENT = {
  id: 4,
  vulnerability: "CVE-2026-1",
  act: "extension" as const,
  asked_at: "2026-10-01",
  by: "ana",
  days: 30,
  product: "sonic",
  reason: "vendor",
  status: "pending",
  until: "2026-12-01",
  was: "2026-11-01",
};
const RATING = {
  id: 9,
  vulnerability: "CVE-2026-2",
  product: "sonic",
  reasoning: "unreachable",
  severity: "low" as const,
};

const text = () => mount.host().textContent ?? "";

async function agreed(node: React.ReactNode) {
  const sent = accept(() => ({ data: {} }));
  const queries = client();
  const invalidated = watchInvalidations(queries);
  mount.render(screen(node, "/", "*", queries));
  const button = Array.from(mount.host().querySelectorAll("button")).find(
    (each) => each.textContent === "Agree",
  );
  await act(async () => button?.click());
  await settle();
  return { sent: sent().map(([path, init]) => [path, init]), invalidated: invalidated() };
}

describe("a disclosure date waiting for a second person", () => {
  it("agreed to, moves the date by its own request and rereads the movements", async () => {
    const { sent, invalidated } = await agreed(<Embargoes waiting={[MOVEMENT]} total={1} />);
    expect(sent).toEqual([
      ["/v1/disclosure-movements/{id}/approval", { params: { path: { id: 4 } } }],
    ]);
    expect(invalidated).toEqual(["movements"]);
  });

  it("says a failed read could not be read", () => {
    mount.render(screen(<Embargoes waiting={[]} error={new Error("down")} />));
    expect(text()).toContain("Requests to move a disclosure date could not be read.");
  });

  it("draws nothing where nothing waits", () => {
    mount.render(screen(<Embargoes waiting={[]} total={0} />));
    expect(text()).toBe("");
  });
});

describe("a rating waiting for a second person", () => {
  it("agreed to, puts the rating in force by its own request and rereads the queue", async () => {
    const { sent, invalidated } = await agreed(<Ratings waiting={[RATING]} total={1} />);
    expect(sent).toEqual([["/v1/assessments/{id}/agreement", { params: { path: { id: 9 } } }]]);
    expect(invalidated).toEqual(["queue"]);
  });

  it("offers no agreement to its own author", () => {
    mount.render(screen(<Ratings waiting={[{ ...RATING, mine: true }]} />));
    const button = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Agree",
    );
    expect(button?.disabled).toBe(true);
    expect(text()).toContain("Yours, so somebody else agrees to it.");
  });

  it("says a failed read could not be read", () => {
    mount.render(screen(<Ratings waiting={[]} error={new Error("down")} />));
    expect(text()).toContain("Ratings awaiting approval could not be read.");
  });
});
