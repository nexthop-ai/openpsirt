// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { PENDING_PAGE } from "./QueuePending";
import { queueNarrowing } from "./QueueFilters";
import { queueReason, type Reason } from "./queueReasons";

// A page of claims. The queue is read at the grain of a claim, and a claim
// is a card with its whole argument, so a page is what fits a sitting.
export const PAGE = 50;

// Everything the review queue reads, and what the address asks of it.
//
// Every list is asked for on every visit, so each tab carries its number
// without being opened: a page for the list being read, the total alone for a
// tab's count. The filters apply only to the list on screen, so a tab's count
// is the whole of its list.
export function useQueueReads(params: URLSearchParams, offset: number) {
  // Whose claims. The queue proper is what is waiting on the reader; their own
  // are a different question, what they proposed that nobody has agreed to,
  // and approving their own is refused.
  const mine = params.get("mine") === "1";
  // The claims of the reader's that lapsed. A tab of its own because the lapse
  // alert links here: it is work handed back, not a record of what happened.
  const reaffirm = params.get("reaffirm") === "1";
  // Either of the two tabs about the reader's own claims, where the queue
  // proper is only counted.
  const aside = mine || reaffirm;
  // Which of the three lists, where the reader is on one of them.
  const reason = queueReason(params);
  // Only the reader's own claims, on the two lists that show everybody's.
  const own = params.get("own") === "1";
  // The product, where the address names one. The figure on the home screen
  // is narrowed by the scope picker and links here with it, so the queue
  // answers the question the clicked number did.
  const product = params.get("product") ?? "";
  const within = product ? { product } : {};
  // What else the queue is narrowed by: who proposed a claim, its age, the
  // severity it covers, its outcome and the release it covers.
  const narrowing = queueNarrowing(params);

  const listing = (which: Reason) => {
    const reading = !aside && reason === which;
    const yours = reading && own && which !== "approval";
    return {
      queryKey: [
        "queue",
        which,
        reading ? offset : 0,
        reading,
        product,
        reading ? narrowing : {},
        yours,
      ],
      queryFn: async () =>
        unwrap(
          await api.GET("/v1/review-queue", {
            params: {
              query: {
                reason: which,
                limit: reading ? PAGE : 0,
                offset: reading ? offset : 0,
                ...within,
                ...(reading ? narrowing : {}),
                ...(yours ? { mine: true } : {}),
              },
            },
          }),
        ),
    };
  };
  const approvals = useQuery(listing("approval"));
  const expired = useQuery(listing("expired-deferral"));
  const missed = useQuery(listing("missed-fix-date"));
  const counted = { approval: approvals, "expired-deferral": expired, "missed-fix-date": missed };
  const queue = counted[reason];
  // The lapsed claims that are this person's to re-affirm, narrowed to the
  // product the address names like the queue beside it.
  const lapsedMine = useQuery({
    queryKey: ["to-reaffirm", reaffirm ? offset : 0, reaffirm, product],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/to-reaffirm", {
          params: {
            query: { limit: reaffirm ? PAGE : 1, offset: reaffirm ? offset : 0, ...within },
          },
        }),
      ),
  });
  // The fate of what this person proposed. The queue lists what is pending, so
  // approved, withdrawn, lapsed and undone all present there as the row
  // disappearing; this list says which.
  const became = useQuery({
    queryKey: ["my-claims", mine ? offset : 0, mine],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/my-claims", {
          params: { query: { limit: mine ? PAGE : 1, offset: mine ? offset : 0 } },
        }),
      ),
  });

  // A milder rating of an issue waits for a second person the same way a
  // dismissal does, and so does a request to keep something hidden longer.
  // Both are listed on this screen, where a request is otherwise read only on
  // the finding it belongs to.
  //
  // The queue is where somebody goes to be a second person. A separate list
  // rather than a queue card, because what is agreed to is not a claim about
  // code — it is how long something stays hidden, and nothing about a claim's
  // shape fits it.
  const [embargoAt, setEmbargoAt] = useState(0);
  const [ratingAt, setRatingAt] = useState(0);
  const embargoes = useQuery({
    queryKey: ["movements", "pending", embargoAt],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/disclosure-movements", {
          params: { query: { limit: PENDING_PAGE, offset: embargoAt } },
        }),
      ),
    // Somebody who may read nothing undisclosed gets an empty list rather than
    // a refusal, so this is quiet on their screen rather than an error on it.
    retry: false,
  });
  const ratings = useQuery({
    queryKey: ["queue", "assessments", ratingAt],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/assessments", {
          params: { query: { state: "proposed", limit: PENDING_PAGE, offset: ratingAt } },
        }),
      ),
  });

  return {
    mine,
    reaffirm,
    aside,
    reason,
    own,
    product,
    narrowing,
    counted,
    queue,
    lapsedMine,
    became,
    embargoes,
    embargoAt,
    setEmbargoAt,
    ratings,
    ratingAt,
    setRatingAt,
  };
}
