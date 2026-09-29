// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RuleForm } from "./InboxRuling";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

// A controlled field changed the way a person changes it.
function type(field: HTMLInputElement, value: string) {
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(field, value);
  field.dispatchEvent(new Event("input", { bubbles: true }));
}

// The form with duplicate chosen and an issue typed, once typing has paused.
async function duplicateOf(issue: string) {
  mount.render(screen(<RuleForm product="sonic" references={["sonic-R-2026-1"]} />));
  await settle();
  const duplicate = Array.from(mount.host().querySelectorAll<HTMLButtonElement>("button")).find(
    (each) => each.textContent?.includes("Duplicate"),
  );
  act(() => duplicate?.click());
  const field = mount.host().querySelector<HTMLInputElement>("#duplicate-of");
  if (!field) throw new Error("no issue field");
  act(() => type(field, issue));
  await act(async () => {
    await new Promise((done) => setTimeout(done, 450));
  });
  await settle();
}

describe("ruling a report a duplicate", () => {
  it("says the disclosure date it starts before it is submitted", async () => {
    const asked = serve((path) =>
      path === "/v1/products/{product}/issues/{vulnerability}/duplicate-disclosure"
        ? { data: { disclose_at: "2026-04-10T00:00:00Z" } }
        : { data: {} },
    );
    await duplicateOf("OPENPSIRT-2026-0001");
    expect(mount.host().textContent).toContain("This starts a disclosure date of");
    expect(mount.host().textContent).toContain("on OPENPSIRT-2026-0001.");
    const previews = asked.mock.calls.filter(
      ([path]) => path === "/v1/products/{product}/issues/{vulnerability}/duplicate-disclosure",
    );
    expect(previews).toHaveLength(1);
    expect(previews[0][1]).toMatchObject({
      params: {
        path: { product: "sonic", vulnerability: "OPENPSIRT-2026-0001" },
        query: { report: ["sonic-R-2026-1"] },
      },
    });
  });

  it("says nothing where the ruling starts no date", async () => {
    serve(() => ({ data: {} }));
    await duplicateOf("CVE-2026-0001");
    expect(mount.host().textContent).not.toContain("disclosure date");
  });
});
