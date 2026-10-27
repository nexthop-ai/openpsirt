// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState, type Dispatch, type SetStateAction } from "react";
import { useMutation } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { useAfterDecision, useApproveDecision, type Decision } from "../api/decisions";

// What stays ticked once an approval loop has run: everything it did not act
// on, as the selection now stands, and of what it acted on only what was
// refused and is still ticked.
export function stillPicked<T>(
  now: Map<string, T>,
  acted: Set<string>,
  refused: string[],
): Map<string, T> {
  const left = new Map<string, T>();
  for (const [key, decision] of now) {
    if (!acted.has(key) || refused.includes(key)) left.set(key, decision);
  }
  return left;
}

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
    // Sequential rather than parallel: each is a separate decision and a refusal
    // on one does not decide the fate of the rest. Every decision is tried, the
    // selection is left holding what was refused, and the batch name is set
    // whenever one landed, so the undo control appears for those.
    const named = batch.trim();
    const failed: string[] = [];
    let landed = 0;
    const acted = new Set(picked.keys());
    for (const [key, decision] of picked) {
      try {
        await approveDecision.mutateAsync({ id: decision.id, batch: named || undefined });
        landed++;
      } catch {
        failed.push(key);
      }
    }
    // The refused rows, and nothing else. The loop acts on the whole
    // selection, off-page entries included, so an entry it approved is
    // unticked wherever it sits.
    //
    // Kept from the current selection rather than from the snapshot this loop
    // started with, so anything ticked while it ran survives and anything
    // unticked while it ran stays unticked.
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
