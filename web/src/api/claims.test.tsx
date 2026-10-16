// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { useApproveClaim, useRejectClaim, useSplitClaim } from "./claims";
import { acted as shared } from "../test/acted";
import { EVERY_CLAIM_KEY } from "../test/claimKeys";
import { mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

// Each hook is drawn and pressed through a real query client, so a hook that
// stops calling the shared set of claim keys, or calls it before the request
// lands, fails here.
//
// Draws a hook, and returns what pressing its button sent and invalidated.
function acted<T>(useHook: () => { mutate: (vars: T) => void }, vars: T, status = 200) {
  return shared(mount.render, mount.host, "POST", useHook, vars, status);
}

// Verified by deleting each hook's `onSuccess: done` in turn: its test fails
// with nothing invalidated.
describe("an act on a claim, once it lands", () => {
  it("approving sends the batch and the rows set aside, and moves every claim read", async () => {
    const { sent, invalidated } = await acted(useApproveClaim, {
      id: 7,
      batch: "tuesday",
      except: [3],
      because: "not this one",
    });
    expect(sent).toEqual([
      [
        "/v1/claims/{id}/approval",
        {
          params: { path: { id: 7 } },
          body: { batch: "tuesday", except: [3], because: "not this one" },
        },
      ],
    ]);
    expect(invalidated).toEqual(EVERY_CLAIM_KEY);
  });

  it("sending back carries the reason, and moves every claim read", async () => {
    const { sent, invalidated } = await acted(useRejectClaim, { id: 7, because: "too broad" });
    expect(sent).toEqual([
      [
        "/v1/claims/{id}/send-back",
        { params: { path: { id: 7 } }, body: { because: "too broad" } },
      ],
    ]);
    expect(invalidated).toEqual(EVERY_CLAIM_KEY);
  });

  it("holding rows back sends the rows, and moves every claim read", async () => {
    const { sent, invalidated } = await acted(useSplitClaim, {
      id: 7,
      rows: [11, 12],
      because: "a different argument",
    });
    expect(sent).toEqual([
      [
        "/v1/claims/{id}/split",
        {
          params: { path: { id: 7 } },
          body: { rows: [11, 12], because: "a different argument" },
        },
      ],
    ]);
    expect(invalidated).toEqual(EVERY_CLAIM_KEY);
  });

  // Verified by changing `onSuccess: done` to `onSettled: done` on each hook
  // in turn: its refused case then invalidates every claim read.
  it.each([
    ["approval", useApproveClaim, { id: 7 }],
    ["send-back", useRejectClaim, { id: 7, because: "x" }],
    ["split", useSplitClaim, { id: 7, rows: [1], because: "x" }],
  ] as const)("a refused %s moves nothing", async (_, hook, vars) => {
    const { sent, invalidated } = await acted(hook as never, vars, 409);
    expect(sent).toHaveLength(1);
    expect(invalidated).toEqual([]);
  });
});
