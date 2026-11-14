// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState, type Dispatch, type SetStateAction } from "react";
import { useMutation } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { useAfterDecision, useApproveDecision, type Decision } from "../api/decisions";
import { actThrough, stillPicked } from "./useSelection";

// Approving the decisions ticked on the review queue, under one batch name, and
// taking that batch back.
//
// The selection is held by the screen, keyed by decision and holding the decision,
// because it survives paging: an approval acts on everything ticked, wherever
// it was ticked.
export function useQueueApproval(
  picked: Map<string, Decision>,
  setPicked: Dispatch<SetStateAction<Map<string, Decision>>>,
) {
  const [batch, setBatch] = useState("");
  // The batch just agreed to, which is the only one there is a safe control
  // for: undoing one named at some point in the past is a control nobody can
  // use without knowing what is in it.
  const [justDone, setJustDone] = useState("");
  // The rows of a batch refused, so a partial result says so rather than
  // leaving somebody to compare counts.
  const [refused, setRefused] = useState(0);
  const approveDecision = useApproveDecision();
  const afterDecision = useAfterDecision();
  const undo = useMutation({
    mutationFn: async (name: string) =>
      unwrap(
        await api.DELETE("/v1/approval-batches/{batch}", {
          params: { path: { batch: name } },
        }),
      ),
    onSuccess: () => {
      setJustDone("");
      afterDecision();
    },
  });

  async function approvePicked() {
    // Every decision is tried, the selection is left holding what was refused,
    // and the batch name is set whenever one landed, so the undo control
    // appears for those.
    const named = batch.trim();
    const { acted, refused: failed } = await actThrough(picked, (decision) =>
      approveDecision.mutateAsync({ id: decision.id, batch: named || undefined }),
    );
    const landed = acted.size - failed.length;
    setPicked((prev) => stillPicked(prev, acted, failed));
    setRefused(failed.length);
    // The agreement just made under one name, so it can be taken back
    // without remembering the name. Set whenever at least one landed, which
    // is the moment somebody notices.
    if (named && landed > 0) setJustDone(named);
  }

  return {
    batch,
    setBatch,
    justDone,
    setJustDone,
    refused,
    setRefused,
    approveDecision,
    undo,
    approvePicked,
  };
}
