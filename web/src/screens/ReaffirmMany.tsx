// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";

import { api } from "../api/client";
import { unwrap, whichOf } from "../api/queries";
import { Failed } from "../ui/Failed";
import type { Row } from "./list";

// What one act re-made: how many claims, and how many of those wait for a
// second person.
export type Reaffirmed = { claims: number; waiting: number };

// What to say about it, once the selection it came from is gone.
export function reaffirmedNotice(made: Reaffirmed): string {
  const claims = `Reaffirmed ${made.claims.toLocaleString()} ${made.claims === 1 ? "claim" : "claims"}`;
  if (made.waiting === 0) return `${claims}.`;
  return `${claims}; ${made.waiting.toLocaleString()} ${made.waiting === 1 ? "waits" : "wait"} for a second person.`;
}

// Re-affirming every lapsed claim behind a selection, in one act.
//
// Offered only where every picked row is lapsed and the list is inside one
// product: the act is one transaction in one product, and a row in any other
// state has nothing to re-make. Each claim keeps its own outcome and
// justification; the reason typed here is the one they share.
export function ReaffirmMany({
  product,
  rows,
  build,
  onDone,
}: {
  product: string;
  rows: Row[];
  build: (row: Row) => { stream: string; variant: string };
  onDone: (made: Reaffirmed) => void;
}) {
  const [open, setOpen] = useState(false);
  const [reasoning, setReasoning] = useState("");
  const again = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/products/{product}/reaffirmations", {
          params: { path: { product } },
          body: {
            reasoning: reasoning.trim(),
            findings: rows.map((row) => ({
              ...build(row),
              vulnerability: row.vulnerability ?? "",
              component: row.component ?? "",
              ...whichOf(row),
            })),
          },
        }),
      ),
    onSuccess: (made) => {
      const claims = made?.claims ?? [];
      setReasoning("");
      setOpen(false);
      onDone({ claims: claims.length, waiting: claims.filter((one) => one.waiting).length });
    },
  });

  const lapsed = rows.length > 0 && rows.every((row) => row.state === "lapsed");
  if (!product || !lapsed) return null;

  return (
    <>
      {!open && (
        <button
          type="button"
          className="btn"
          title="Re-make every lapsed claim behind these rows, each with its own outcome and justification"
          onClick={() => setOpen(true)}
        >
          {`Reaffirm ${rows.length}`}
        </button>
      )}
      {open && (
        <div className="card" style={{ flexBasis: "100%", marginTop: 8 }}>
          <textarea
            rows={3}
            value={reasoning}
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
              {again.isPending ? "Reaffirming…" : `Reaffirm ${rows.length}`}
            </button>
            <button type="button" className="linkish" onClick={() => setOpen(false)}>
              Cancel
            </button>
          </div>
          {again.isError && <Failed error={again.error} what="These could not be reaffirmed." />}
        </div>
      )}
    </>
  );
}
