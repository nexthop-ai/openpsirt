// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { describe, expect, it } from "vitest";
import { Shell } from "./Shell";
import { location, mounted, screen, serve, settle, type Answer } from "../test/mount";

const mount = mounted();

const who = {
  identity: "ana",
  name: "Ana",
  admin: false,
  kind: "person" as const,
  reach: [],
  outcomes: [],
};

// Where the top search lands for a term, given how the issue route answers.
async function searched(term: string, issue: Answer): Promise<string> {
  serve((path) =>
    path === "/v1/issues/{vulnerability}" ? issue : { data: { items: [], total: 0 } },
  );
  mount.render(screen(<Shell who={who}>{null}</Shell>, "/start"));
  await settle();
  const box = mount
    .host()
    .querySelector<HTMLInputElement>('input[aria-label="Find an issue, or a component"]');
  if (!box) throw new Error("no top search");
  act(() => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(box, term);
    box.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await act(async () => box.form?.requestSubmit());
  await settle();
  return location();
}

describe("the top search", () => {
  it("opens an issue somebody here carries", async () => {
    const at = await searched("CVE-2026-1", { data: { items: [{}], total: 1 } });
    expect(at).toContain("CVE-2026-1");
  });

  it("searches components for a term no issue here answers to", async () => {
    const at = await searched("openssl", { data: { items: [], total: 0 } });
    expect(at).toContain("q=openssl");
  });

  it("stays put when the issue could not be read", async () => {
    const at = await searched("openssl", { status: 503 });
    expect(at).toBe("/start");
  });
});
