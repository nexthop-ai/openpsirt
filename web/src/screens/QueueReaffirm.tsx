// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Link } from "react-router-dom";
import { at } from "../ui/when";
import { useMutation } from "@tanstack/react-query";

import { api, type Body } from "../api/client";
import { unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Because, Outcome } from "../ui/Outcome";
import { Wide } from "../ui/Wide";
import { pathTo } from "./list";

type Row = Body<"ToReaffirmBody">;

// What one act re-made: how many claims, and how many of those wait for a
// second person.
export type Reaffirmed = { claims: number; waiting: number };

// What to say about it once the rows it came from have left the list.
export function reaffirmedNotice(made: Reaffirmed): string {
  const claims = `Reaffirmed ${made.claims.toLocaleString()} ${made.claims === 1 ? "claim" : "claims"}`;
  if (made.waiting === 0) return `${claims}.`;
  return `${claims}; ${made.waiting.toLocaleString()} ${made.waiting === 1 ? "waits" : "wait"} for a second person.`;
}

// Why a claim lapsed, in the words a reader acts on. Both can hold.
export function whyLapsed(row: Pick<Row, "code_moved" | "rated_worse" | "was" | "now">): string[] {
  const why: string[] = [];
  if (row.code_moved) why.push("Code moved");
  if (row.rated_worse) {
    why.push(row.now ? `Rated worse: ${row.was || "unrated"} → ${row.now}` : "Rated worse");
  }
  return why;
}

// The claims of yours that lapsed and that nothing has replaced: work handed
// back, which the lapse alert links here. Each is re-made whole with its own
// outcome and justification; the reason typed here is the one they share.
//
// The selection is held by claim across pages, because re-affirming acts on
// claims and the server takes them by identifier.
export function ToReaffirm({
  rows,
  query,
  onDone,
}: {
  rows: Row[];
  query: { isPending: boolean; isError: boolean; error: unknown };
  onDone: () => void;
}) {
  const [picked, setPicked] = useState<Set<number>>(new Set());
  const [open, setOpen] = useState(false);
  const [reasoning, setReasoning] = useState("");
  const [made, setMade] = useState<Reaffirmed | null>(null);
  const again = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/reaffirmations", {
          body: { claims: [...picked], reasoning: reasoning.trim() },
        }),
      ),
    onSuccess: (answer) => {
      const claims = answer?.claims ?? [];
      setMade({ claims: claims.length, waiting: claims.filter((one) => one.waiting).length });
      setPicked(new Set());
      setReasoning("");
      setOpen(false);
      onDone();
    },
  });

  if (query.isPending) return <Loading />;
  if (query.isError) {
    return <Failed error={query.error} what="The claims to reaffirm could not be read." />;
  }

  const shown = rows.map((row) => row.claim.id);
  const allShown = shown.length > 0 && shown.every((id) => picked.has(id));
  function pick(ids: number[], on: boolean) {
    const next = new Set(picked);
    for (const id of ids) {
      if (on) next.add(id);
      else next.delete(id);
    }
    setPicked(next);
  }

  return (
    <>
      {made !== null && (
        <p className="hint" role="status">
          {reaffirmedNotice(made)}
        </p>
      )}
      {rows.length === 0 ? (
        <Empty
          title="Nothing of yours has lapsed."
          detail="A claim lands here when the code moves under it or its issue is rated worse."
        />
      ) : (
        <>
          {picked.size > 0 && (
            <div className="batchbar" style={{ marginBottom: 8 }}>
              <span>
                <b>{picked.size.toLocaleString()} selected</b>
              </span>
              <span className="spacer" />
              {!open && (
                <button type="button" className="btn" onClick={() => setOpen(true)}>
                  {`Reaffirm ${picked.size}`}
                </button>
              )}
              <button type="button" className="linkish" onClick={() => setPicked(new Set())}>
                Clear
              </button>
            </div>
          )}
          {open && picked.size > 0 && (
            <div className="card" style={{ marginBottom: 8 }}>
              <textarea
                rows={3}
                value={reasoning}
                aria-label="Reason"
                placeholder="Why every one of these still holds, having checked again"
                onChange={(event) => setReasoning(event.target.value)}
              />
              <div className="actions" style={{ marginTop: 10 }}>
                <button
                  type="button"
                  className="btn"
                  disabled={reasoning.trim() === "" || again.isPending}
                  onClick={() => again.mutate()}
                >
                  {again.isPending ? "Reaffirming…" : `Reaffirm ${picked.size}`}
                </button>
                <button type="button" className="linkish" onClick={() => setOpen(false)}>
                  Cancel
                </button>
              </div>
              {again.isError && (
                <Failed error={again.error} what="These could not be reaffirmed." />
              )}
            </div>
          )}
          <Wide>
            <table>
              <thead>
                <tr>
                  <th style={{ width: 30 }}>
                    <input
                      type="checkbox"
                      aria-label="Select every claim on this page"
                      checked={allShown}
                      onChange={(event) => pick(shown, event.target.checked)}
                    />
                  </th>
                  <th>Why</th>
                  <th>Claim</th>
                  <th>Issue</th>
                  <th>Component</th>
                  <th>Where</th>
                  <th className="num">Covers</th>
                  <th>Lapsed</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.claim.id} className="row">
                    <td>
                      <input
                        type="checkbox"
                        aria-label="Select"
                        checked={picked.has(row.claim.id)}
                        onChange={(event) => pick([row.claim.id], event.target.checked)}
                      />
                    </td>
                    <td>
                      {whyLapsed(row).map((said) => (
                        <span key={said} className="state lapsed" style={{ marginRight: 4 }}>
                          {said}
                        </span>
                      ))}
                    </td>
                    <td>
                      <Outcome outcome={row.decision.outcome} />{" "}
                      <Because code={row.decision.justification} />
                    </td>
                    <td>
                      <Link to={`/claims/${row.claim.id}`} className="id">
                        {row.place.vulnerability}
                      </Link>
                      {row.issues > 1 && <span className="hint"> and {row.issues - 1} more</span>}
                    </td>
                    <td className="id">
                      {row.finding ? (
                        <Link
                          to={pathTo(
                            {
                              product: row.finding.product ?? "",
                              stream: row.finding.stream ?? "",
                              variant: row.finding.variant ?? "",
                            },
                            {
                              vulnerability: row.finding.vulnerability ?? "",
                              component: row.finding.component ?? "",
                              version: row.finding.version ?? "",
                              ecosystem: row.finding.ecosystem,
                              namespace: row.finding.namespace,
                            },
                          )}
                        >
                          {row.finding.component}
                        </Link>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="hint">{row.place.product_name || row.place.product}</td>
                    <td className="num">
                      {row.places} {row.places === 1 ? "place" : "places"}
                    </td>
                    <td className="hint">{at(row.lapsed_at) || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Wide>
        </>
      )}
    </>
  );
}
