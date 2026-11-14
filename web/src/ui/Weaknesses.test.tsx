// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act, useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Weaknesses } from "./Weaknesses";
import { mounted, screen, serve, settle } from "../test/mount";
import { change } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

function Host({ start = [] as string[] }) {
  const [chosen, setChosen] = useState(start);
  return (
    <>
      <Weaknesses chosen={chosen} onChange={setChosen} />
      <output>{chosen.join("|")}</output>
    </>
  );
}

async function drawn(start: string[] = [], failing = false) {
  serve((path) =>
    path === "/v1/weaknesses"
      ? failing
        ? { status: 503 }
        : { data: { items: [{ id: "CWE-125", name: "Out-of-bounds Read" }] } }
      : path === "/v1/session/me"
        ? { data: { identity: "ana", kind: "person", reach: [], outcomes: [], most_weaknesses: 3 } }
        : undefined,
  );
  mount.render(screen(<Host start={start} />));
  await settle();
}

const field = () => mount.host().querySelector<HTMLInputElement>("#cwe-typed");
const held = () => mount.host().querySelector("output")?.textContent;

function enter() {
  act(() => {
    field()?.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
  });
}

describe("the kinds of flaw a finding names", () => {
  it("takes an identifier in any case and writes it the one way", async () => {
    await drawn();
    change(field(), "cwe-79");
    enter();
    expect(held()).toBe("CWE-79");
  });

  it("refuses words that are not an identifier, and says how to write one", async () => {
    await drawn();
    change(field(), "buffer things");
    enter();
    expect(held()).toBe("");
    expect(mount.host().textContent).toContain("type CWE- and a number");
  });

  it("stops at the most the server says a finding may carry", async () => {
    await drawn(["CWE-1", "CWE-2", "CWE-3"]);
    change(field(), "CWE-999");
    enter();
    expect(held()?.split("|")).toHaveLength(3);
    expect(mount.host().textContent).toContain("3 at most.");
  });

  it("names a chosen identifier, and removes it when pressed", async () => {
    await drawn(["CWE-125"]);
    expect(mount.host().textContent).toContain("Out-of-bounds Read");
    await act(async () => mount.host().querySelector<HTMLButtonElement>("button.chip")?.click());
    expect(held()).toBe("");
  });

  it("says the names could not be searched, and that a number still works", async () => {
    await drawn([], true);
    change(field(), "read");
    await settle();
    expect(mount.host().textContent).toContain("Couldn’t search the names.");
  });
});
