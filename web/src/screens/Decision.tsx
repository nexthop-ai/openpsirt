// A decision's address, which resolves to the claim it is one row of.
//
// Every act belongs to the claim — the reasoning, the agreement, the
// discussion, holding rows back — so there is nothing a page about one row
// could offer that is not the wrong grain. What there is instead is a stable
// address: notifications, the record, the reports and the evidence list all
// name a decision by identifier, and each of those is somebody being sent to
// read what was decided.

import { Navigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";

export function Decision() {
  const { id: raw = "" } = useParams();
  const id = Number(raw);

  const decision = useQuery({
    queryKey: ["decision", id],
    queryFn: async () => unwrap(await api.GET("/v1/decisions/{id}", { params: { path: { id } } })),
  });

  if (decision.isPending) return <Loading />;
  if (decision.isError) {
    return <Failed error={decision.error} what="That decision could not be read." />;
  }
  const claim = decision.data?.decision?.claim_id;
  if (!claim) {
    return <Failed error={new Error("no claim")} what="That decision names no claim." />;
  }
  // Replaced rather than pushed: the decision's address is a way in, not a
  // step somebody took, and leaving it in the history sends Back through it
  // again.
  return <Navigate to={`/claims/${claim}`} replace />;
}
