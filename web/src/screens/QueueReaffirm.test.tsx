// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { describe, expect, it, vi } from "vitest";
import { ToReaffirm } from "./QueueReaffirm";
import { accept, mounted, screen, settle } from "../test/mount";
import { change, only, press } from "../test/controls";

const mount = mounted();

// A decision of the reader's that lapsed when the code moved under it.
const lapsed = (id: number) => ({
  code_moved: true,
  rated_worse: false,
  source_files: false,
  decision: { id, kind: "finding", proposed_at: "2026-09-01T00:00:00Z", proposed_by: "ana" },
  decision_occurrence: {
    id: id * 10,
    outcome: "not-applicable",
    justification: "code-not-present",
  },
  issues: 1,
  occurrences: 1,
  occurrence: { occurrence: `p${id}`, product: "sonic", vulnerability: `CVE-2026-${id}` },
  reasoning: "not built",
  rows: 1,
});

const answered = { isPending: false, isError: false, error: null };

describe("reaffirming lapsed decisions", () => {
  it("sends the decisions picked and the reason they share", async () => {
    const sent = accept(() => ({
      data: {
        decisions: [
          { decision_id: 21, waiting: false },
          { decision_id: 23, waiting: true },
        ],
      },
    }));
    const done = vi.fn();
    mount.render(
      screen(
        <ToReaffirm
          rows={[lapsed(1), lapsed(2), lapsed(3)] as never}
          query={answered}
          onDone={done}
        />,
      ),
    );
    await settle();
    const boxes = Array.from(
      mount.host().querySelectorAll<HTMLInputElement>('input[aria-label="Select"]'),
    );
    act(() => boxes[0]?.click());
    act(() => boxes[2]?.click());
    await press(mount.host(), "Reaffirm 2");
    change(mount.host().querySelector("textarea"), "  Checked again; still not built.  ");
    await press(mount.host(), "Reaffirm 2");
    await settle();
    const [path, init] = only(sent);
    expect(path).toBe("/v1/reaffirmations");
    expect(init.body).toEqual({ decisions: [1, 3], reasoning: "Checked again; still not built." });
    expect(done).toHaveBeenCalledTimes(1);
    expect(mount.host().textContent).toContain(
      "Reaffirmed 2 decisions; 1 waits for a second person.",
    );
  });
});
