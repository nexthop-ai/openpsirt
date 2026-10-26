// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The static analysis lead a recorded flaw was handed off from, where the
// reader reads it: what the hand-off was offered, whether it was undone, and
// the builds whose lead no run sees any more, which the flaw may be closed as
// fixed in.

import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Body } from "../api/client";
import { unwrap } from "../api/queries";
import { leadAt } from "../app/routes";
import { Markdown } from "../ui/Markdown";
import { on } from "../ui/when";
import { located, stateSaid } from "./leads";

export type FlawLead = Body<"FlawLeadBody">;

// The lead a flaw was recorded from, or null where it came from none the
// reader reads.
export function useFlawLead(product: string, vulnerability: string, enabled = true) {
  return useQuery({
    queryKey: ["finding", "lead", product, vulnerability],
    enabled: enabled && product !== "" && vulnerability !== "",
    queryFn: async () => {
      const answer = await api.GET("/v1/products/{product}/issues/{vulnerability}/lead", {
        params: { path: { product, vulnerability } },
      });
      if (answer.response.status === 404) return null;
      return unwrap(answer);
    },
  });
}

// The sentence a fix closure on this build starts from, where its lead is not
// reproduced here.
export function fixedFromLead(
  lead: FlawLead | null | undefined,
  stream: string,
  variant: string,
): string {
  const here = (lead?.fixed_in ?? []).find((b) => b.stream === stream && b.variant === variant);
  if (!here) return "";
  const run = here.fixed ?? here.not_seen;
  const commit = run.commit ? ` at ${run.commit.slice(0, 12)}` : "";
  return `Not reproduced by the analyzer since the build made ${on(run.built)}${commit}.`;
}

export function FlawLeadCard({
  product,
  vulnerability,
  stream,
  variant,
}: {
  product: string;
  vulnerability: string;
  stream: string;
  variant: string;
}) {
  const lead = useFlawLead(product, vulnerability);
  if (!lead.data) return null;
  const it = lead.data;
  const here = (it.fixed_in ?? []).find((b) => b.stream === stream && b.variant === variant);
  return (
    <div className="card">
      <h3>Static analysis lead</h3>
      <p>
        <Link
          className="mono"
          to={leadAt({ product, stream: it.stream, variant: it.variant }, it.place)}
        >
          {it.rule} · {located(it.path, it.line)}
        </Link>{" "}
        <span className="hint">
          · {stateSaid(it.state)} · handed off by {it.handed_by} {on(it.handed_at)}
        </span>
      </p>
      <p className="hint">
        Suggested: {it.suggested.component ?? "the build itself"} · Proposed for{" "}
        {(it.proposed ?? []).map((b) => `${b.stream}/${b.variant}`).join(", ") || "no build"}
      </p>
      {it.undone_at && (
        <div>
          <p className="hint">
            Hand-off undone by {it.undone_by} {on(it.undone_at)}
          </p>
          {it.because && <Markdown source={it.because} />}
        </div>
      )}
      {here && (
        <p className="hint">
          Not reproduced here since the build made {on(here.not_seen.built)}. Close it as fixed
          below.
        </p>
      )}
    </div>
  );
}
