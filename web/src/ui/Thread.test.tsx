// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Thread } from "./Thread";
import { belongTo } from "../app/drafts";
import { mounted, screen, serve, settle } from "../test/mount";
import { button, press, change } from "../test/controls";

const mount = mounted();

beforeEach(() => {
  window.localStorage.clear();
  belongTo("oidc:ana");
});
afterEach(() => vi.restoreAllMocks());

const ITEMS = [
  {
    id: 1,
    body: "Mine.",
    written_by: "ana",
    written_by_name: "Ana",
    written_at: "2026-01-01T00:00:00Z",
  },
  { id: 2, body: "Theirs.", written_by: "bo", written_at: "2026-01-02T00:00:00Z" },
];

function useNoHistory(id: number) {
  return useQuery({ queryKey: ["history", id], queryFn: async () => ({ items: [] }) });
}

function drawn(
  notNotified: string[] = [],
  onAdd = vi.fn<(body: string, done: () => void) => void>(),
) {
  serve(() => ({ data: { items: [] } }));
  mount.render(
    screen(
      <Thread
        items={ITEMS}
        mine={(by) => by === "ana"}
        about={{ product: "sonic", vulnerability: "CVE-2026-1" }}
        word="Comment"
        consequence="Everyone on the claim is told."
        placeholder="Say something"
        draftKey="thread:1"
        notNotified={notNotified}
        adding={{ isPending: false, error: null }}
        onAdd={onAdd}
        edit={(piece) => <p>editing {piece.id}</p>}
        useHistory={useNoHistory}
      />,
    ),
  );
  return onAdd;
}

describe("a thread of comments", () => {
  it("offers to edit only what the reader wrote", async () => {
    drawn();
    await settle();
    const edits = Array.from(mount.host().querySelectorAll("button")).filter(
      (each) => each.textContent === "Edit",
    );
    expect(edits).toHaveLength(1);
    await act(async () => edits[0]?.click());
    expect(mount.host().textContent).toContain("editing 1");
  });

  it("adds what was typed, and clears the field once it is taken", async () => {
    const onAdd = drawn();
    await settle();
    const field = mount.host().querySelector<HTMLTextAreaElement>("textarea");
    expect(button(mount.host(), "Comment").disabled).toBe(true);
    change(field, "Checked again.");
    await press(mount.host(), "Comment");
    expect(onAdd).toHaveBeenCalledWith("Checked again.", expect.any(Function));
    const done = onAdd.mock.calls[0]?.[1];
    await act(async () => done?.());
    expect(mount.host().querySelector<HTMLTextAreaElement>("textarea")?.value).toBe("");
  });

  it("names whoever a mention reached nobody for, without saying why", async () => {
    drawn(["carol"]);
    await settle();
    expect(mount.host().textContent).toContain("Nobody was told about @carol");
    expect(mount.host().textContent).toContain("The comment was saved.");
  });
});
