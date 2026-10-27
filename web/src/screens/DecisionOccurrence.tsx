// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// An occurrence row's address, which resolves to the decision it is one row
// of.
//
// Every act belongs to the decision — the reasoning, the agreement, the
// discussion, holding rows back — so there is nothing a page about one row
// could offer that is not the wrong grain. What there is instead is a stable
// address: notifications, the audit log, the reports and the evidence list all
// name a row by identifier, and each of those is somebody being sent to read
// what was decided.

import { Navigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { decisionAt } from "../app/routes";

export function DecisionOccurrence() {
  const { id: raw = "" } = useParams();
  const id = Number(raw);

  const row = useQuery({
    queryKey: ["decision-occurrence", id],
    queryFn: async () =>
      unwrap(await api.GET("/v1/decision-occurrences/{id}", { params: { path: { id } } })),
  });

  if (row.isPending) return <Loading />;
  if (row.isError) {
    return <Failed error={row.error} what="That decision could not be read." />;
  }
  const decision = row.data?.decision_occurrence?.decision_id;
  if (!decision) {
    return <Failed error={new Error("no decision")} what="That address names no decision." />;
  }
  // Replaced rather than pushed: the row's address is a way in, not a step
  // somebody took, and leaving it in the history sends Back through it again.
  return <Navigate to={decisionAt(decision)} replace />;
}
