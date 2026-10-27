// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The static analysis code finding a recorded flaw was recorded as a flaw from, where the
// reader reads it: what the flaw record was offered, whether it was undone, and
// the builds whose code finding no run sees any more, which the flaw may be closed as
// fixed in.

import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Body } from "../api/client";
import { unwrap } from "../api/queries";
import { codeFindingAt } from "../app/routes";
import { Markdown } from "../ui/Markdown";
import { on } from "../ui/when";
import { located, stateSaid } from "./codeFindings";

export type FlawCodeFinding = Body<"FlawCodeFindingBody">;

// The code finding a flaw was recorded from, or null where it came from none the
// reader reads.
export function useFlawCodeFinding(product: string, vulnerability: string, enabled = true) {
  return useQuery({
    queryKey: ["finding", "code-finding", product, vulnerability],
    enabled: enabled && product !== "" && vulnerability !== "",
    queryFn: async () => {
      const answer = await api.GET("/v1/products/{product}/issues/{issue}/code-finding", {
        params: { path: { product, issue: vulnerability } },
      });
      if (answer.response.status === 404) return null;
      return unwrap(answer);
    },
  });
}

// The sentence a fix closure on this build starts from, where its code finding is not
// reproduced here.
export function fixedFromCodeFinding(
  codeFinding: FlawCodeFinding | null | undefined,
  stream: string,
  variant: string,
): string {
  const here = (codeFinding?.fixed_in ?? []).find(
    (b) => b.stream === stream && b.variant === variant,
  );
  if (!here) return "";
  const run = here.fixed ?? here.not_seen;
  const commit = run.commit ? ` at ${run.commit.slice(0, 12)}` : "";
  return `No longer detected by the analyzer since the build made ${on(run.built)}${commit}.`;
}

export function FlawCodeFindingCard({
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
  const codeFinding = useFlawCodeFinding(product, vulnerability);
  if (!codeFinding.data) return null;
  const it = codeFinding.data;
  const here = (it.fixed_in ?? []).find((b) => b.stream === stream && b.variant === variant);
  return (
    <div className="card">
      <h3>Static analysis code finding</h3>
      <p>
        <Link
          className="mono"
          to={codeFindingAt({ product, stream: it.stream, variant: it.variant }, it.occurrence)}
        >
          {it.rule} · {located(it.path, it.line)}
        </Link>{" "}
        <span className="hint">
          · {stateSaid(it.state)} · recorded as a flaw by {it.recorded_by} {on(it.recorded_at)}
        </span>
      </p>
      <p className="hint">
        Suggested: {it.suggested.component ?? "the build itself"} · Proposed for{" "}
        {(it.proposed ?? []).map((b) => `${b.stream}/${b.variant}`).join(", ") || "no build"}
      </p>
      {it.undone_at && (
        <div>
          <p className="hint">
            Flaw record undone by {it.undone_by} {on(it.undone_at)}
          </p>
          {it.because && <Markdown source={it.because} />}
        </div>
      )}
      {here && (
        <p className="hint">
          No longer detected here since the build made {on(here.not_seen.built)}. Close it as fixed
          below.
        </p>
      )}
    </div>
  );
}
