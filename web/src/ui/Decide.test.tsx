// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Decide, type At } from "./Decide";
import { accept, mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

beforeEach(() => window.sessionStorage.clear());
afterEach(() => vi.restoreAllMocks());

const at: At = {
  product: "sonic",
  stream: "master",
  variant: "broadcom",
  vulnerability: "CVE-2026-1",
  component: "openssl",
  version: "3.0.2",
};

// A controlled field changed the way a person changes it.
function type(field: HTMLInputElement | HTMLTextAreaElement, value: string) {
  const proto = field instanceof HTMLTextAreaElement ? HTMLTextAreaElement : HTMLInputElement;
  Object.getOwnPropertyDescriptor(proto.prototype, "value")?.set?.call(field, value);
  field.dispatchEvent(new Event("input", { bubbles: true }));
}

// A day this many whole days from today, as the date field writes one.
function daysOut(days: number): string {
  const day = new Date();
  day.setUTCDate(day.getUTCDate() + days);
  return day.toISOString().slice(0, 10);
}

describe("proposing a deferral past the threshold", () => {
  // The deployment's threshold is thirty days. The date picked is twenty-five
  // days out, inside it on its own, and the one place was already put off for
  // ten — so only a form that adds what was put off before says a second
  // person is needed.
  //
  // Verified by replacing the place's earlier deferral with zero where the
  // form works out what it covers: the sentence reads "inside the 30-day
  // threshold" and the test fails on it. And by sending the landing date in
  // place of the deferral date: the body check fails.
  it("says a second person must agree, and sends the date and the reasoning", async () => {
    serve((path) => {
      if (path === "/v1/session/me") {
        return {
          data: { identity: "ana", name: "Ana", admin: false, kind: "person", deferral_days: 30 },
        };
      }
      if (path.endsWith("/reach")) return { data: { automatic: [], differing: [] } };
      return { data: { items: [], total: 0 } };
    });
    const sent = accept(() => ({
      data: { claim_id: 9, recorded: 1, covered: 1, left: 0, needs_approval: true },
    }));
    const done = vi.fn();
    mount.render(
      screen(
        <Decide
          at={at}
          places={[{ place: "p1", component: "openssl", deferred_days: 10 }]}
          onDone={done}
        />,
      ),
    );
    await settle();
    const host = mount.host();

    const deferred = Array.from(host.querySelectorAll<HTMLButtonElement>("button.outcome")).find(
      (each) => each.textContent === "Deferred",
    );
    act(() => deferred?.click());
    const until = daysOut(25);
    const date = host.querySelector<HTMLInputElement>('input[type="date"]');
    expect(date, "no date field").not.toBeNull();
    act(() => {
      if (date) type(date, until);
    });
    const reasoning = host.querySelector<HTMLTextAreaElement>("textarea");
    act(() => {
      if (reasoning) type(reasoning, "Waiting on the vendor's next image.");
    });

    // Said beside the date and in the aside, before anything is sent.
    const said = "with what was put off before reaches the 30-day threshold, so a second person";
    const sentences = Array.from(host.querySelectorAll(".hint, .said")).map((each) =>
      each.textContent?.trim(),
    );
    expect(sentences.filter((each) => each?.includes(said))).toHaveLength(2);

    const submit = Array.from(host.querySelectorAll<HTMLButtonElement>("button")).find(
      (each) => each.textContent === "Submit decision",
    );
    expect(submit?.disabled).toBe(false);
    await act(async () => submit?.click());
    await settle();

    expect(sent()).toHaveLength(1);
    const [path, init] = sent()[0] ?? ["", {}];
    expect(path).toBe(
      "/v1/products/{product}/streams/{stream}/variants/{variant}/findings/{vulnerability}/components/{component}/decision",
    );
    expect((init as { body: unknown }).body).toEqual({
      outcome: "deferred",
      deferred_until: until,
      reasoning: "Waiting on the vendor's next image.",
    });
    expect(done).toHaveBeenCalledWith(
      expect.objectContaining({ claimId: 9, needsApproval: true, outcome: "deferred" }),
    );
  });
});
