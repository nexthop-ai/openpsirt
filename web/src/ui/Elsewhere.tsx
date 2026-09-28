// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMutation } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "./Failed";
import { Outward } from "./Outward";

// The place a claim is being argued about or worked on outside here, and the
// control that records it.
//
// Anybody who may argue about the claim may set it: a link is a note about
// where the conversation is rather than a judgment, and needing a second
// person for it would leave it unset. Nothing is ever fetched from it. The
// claim page and the finding's claim card draw it alike; what is read again
// once it is set is the caller's.
export function Elsewhere({ id, where, onSet }: { id: number; where: string; onSet: () => void }) {
  const point = useMutation({
    mutationFn: async (to: string) =>
      unwrap(
        await api.PUT("/v1/claims/{id}/elsewhere", {
          params: { path: { id } },
          body: { elsewhere: to },
        }),
      ),
    onSuccess: onSet,
  });

  return (
    <p className="hint" style={{ margin: "10px 0 0" }}>
      {where ? (
        <>
          Being worked on at{" "}
          {/* Typed here rather than supplied by a scanner, and still a string
              that becomes somewhere to click — so it is judged the same way a
              scanner's reference is, by the one component that judges. */}
          <Outward href={where} />
          {". "}
        </>
      ) : (
        "Nothing here says where this is being worked on. "
      )}
      <button
        type="button"
        className="linkish"
        onClick={() => {
          const to = window.prompt(
            "The place this is being worked on: a ticket, a thread, a change. Nothing is ever sent to it.",
            where,
          );
          if (to !== null) point.mutate(to.trim());
        }}
      >
        {where ? "Change it" : "Link it"}
      </button>
      {point.error != null && <Failed error={point.error} what="That could not be recorded." />}
    </p>
  );
}
