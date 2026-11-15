// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Decide } from "./Decide";
import { change } from "../test/controls";
import { DECIDING_AT as at, serveDecider } from "../test/deciding";
import { accept, client, mounted, screen, settle, watchInvalidations } from "../test/mount";

const mount = mounted();

beforeEach(() => window.sessionStorage.clear());

// A day this many whole days from today, as the date field writes one.
function daysOut(days: number): string {
  const day = new Date();
  day.setUTCDate(day.getUTCDate() + days);
  return day.toISOString().slice(0, 10);
}

describe("proposing a deferral past the threshold", () => {
  // The deployment's threshold is thirty days. The date picked is twenty-five
  // days out, inside it on its own, and the one occurrence was already put off for
  // ten — so only a form that adds what was put off before says a second
  // person is needed.
  //
  // Verified by replacing the occurrence's earlier deferral with zero where the
  // form works out what it covers: the sentence reads "inside the 30-day
  // threshold" and the test fails on it. And by sending the landing date in
  // place of the deferral date: the body check fails.
  it("says a second person must agree, and sends the date and the reasoning", async () => {
    serveDecider();
    const sent = accept(() => ({
      data: { decision_id: 9, recorded: 1, covered: 1, left: 0, needs_approval: true },
    }));
    const done = vi.fn();
    mount.render(
      screen(
        <Decide
          at={at}
          occurrences={[{ occurrence: "p1", component: "openssl", deferred_days: 10 }]}
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
    change(date, until);
    const reasoning = host.querySelector<HTMLTextAreaElement>("textarea");
    change(reasoning, "Waiting on the vendor's next image.");

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
      "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/findings/{issue}/components/{component}/decision",
    );
    expect((init as { body: unknown }).body).toEqual({
      outcome: "deferred",
      deferred_until: until,
      reasoning: "Waiting on the vendor's next image.",
    });
    expect(done).toHaveBeenCalledWith(
      expect.objectContaining({ decisionId: 9, needsApproval: true, outcome: "deferred" }),
    );
  });
});

describe("the decision form's Ctrl+Enter", () => {
  async function ready(queries = client()) {
    serveDecider();
    const sent = accept(() => ({
      data: { decision_id: 9, recorded: 1, covered: 1, left: 0, needs_approval: false },
    }));
    mount.render(
      screen(
        <>
          <Decide
            at={at}
            occurrences={[{ occurrence: "p1", component: "openssl" }]}
            onDone={() => undefined}
          />
          <textarea aria-label="A comment elsewhere" />
        </>,
        "/",
        "*",
        queries,
      ),
    );
    await settle();
    const host = mount.host();
    const deferred = Array.from(host.querySelectorAll<HTMLButtonElement>("button.outcome")).find(
      (each) => each.textContent === "Deferred",
    );
    act(() => deferred?.click());
    const date = host.querySelector<HTMLInputElement>('input[type="date"]');
    change(date, daysOut(10));
    const reasoning = host.querySelector<HTMLTextAreaElement>(".writing textarea");
    change(reasoning, "Waiting on the vendor's next image.");
    return { sent, host, reasoning };
  }

  function press(on: Element | null) {
    act(() => {
      on?.dispatchEvent(
        new KeyboardEvent("keydown", { key: "Enter", ctrlKey: true, bubbles: true }),
      );
    });
  }

  it("submits from inside the form", async () => {
    const { sent, reasoning } = await ready();
    press(reasoning);
    await settle();
    expect(sent()).toHaveLength(1);
  });

  it("does not submit from a box outside it", async () => {
    const { sent, host } = await ready();
    press(host.querySelector('textarea[aria-label="A comment elsewhere"]'));
    await settle();
    expect(sent()).toHaveLength(0);
  });

  it("refreshes everything a new decision changes, the proposer's own list among it", async () => {
    const queries = client();
    const invalidated = watchInvalidations(queries);
    const { sent, reasoning } = await ready(queries);
    press(reasoning);
    await settle();
    expect(sent()).toHaveLength(1);
    expect(invalidated()).toEqual(
      expect.arrayContaining([
        "my-decisions",
        "decided",
        "decision-occurrence",
        "decision",
        "finding",
        "findings",
      ]),
    );
  });
});
