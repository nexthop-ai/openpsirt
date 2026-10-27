// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { useComment, useEditComment, useEditNote, useRevise, useWithdraw } from "./mutations";
import { acted } from "../test/acted";
import { EVERY_DECISION_KEY } from "../test/decisionKeys";
import { mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

describe("an edit to a decision, once it lands", () => {
  it("revising the reasoning sends it to the decision named and moves every decision read", async () => {
    const { sent, invalidated } = await acted(mount.render, mount.host, "PUT", useRevise, {
      id: 102,
      reasoning: "Not reachable from the socket.",
    });
    expect(sent).toEqual([
      [
        "/v1/decisions/{id}/reasoning",
        { params: { path: { id: 102 } }, body: { reasoning: "Not reachable from the socket." } },
      ],
    ]);
    expect(invalidated).toEqual(EVERY_DECISION_KEY);
  });

  it("withdrawing a decision moves every decision read", async () => {
    const { sent, invalidated } = await acted(mount.render, mount.host, "DELETE", useWithdraw, {
      id: 102,
    });
    expect(sent).toEqual([["/v1/decisions/{id}", { params: { path: { id: 102 } } }]]);
    expect(invalidated).toEqual(EVERY_DECISION_KEY);
  });
});

describe("a remark, once it lands", () => {
  it("commenting moves the comments", async () => {
    const { invalidated } = await acted(mount.render, mount.host, "POST", useComment, {
      id: 102,
      body: "Asked upstream.",
    });
    expect(invalidated).toEqual(["comments"]);
  });

  it("editing a comment moves the comments and that comment's earlier wording", async () => {
    const { invalidated } = await acted(mount.render, mount.host, "PUT", useEditComment, {
      id: 9,
      body: "Asked upstream twice.",
    });
    expect(invalidated).toEqual(["comment/9/history", "comments"]);
  });

  it("editing a note moves the notes and that note's earlier wording", async () => {
    const { invalidated } = await acted(mount.render, mount.host, "PUT", useEditNote, {
      id: 5,
      body: "Vendor says next month.",
    });
    expect(invalidated).toEqual(["note/5/history", "notes"]);
  });
});
