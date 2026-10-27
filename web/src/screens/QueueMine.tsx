// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Link } from "react-router-dom";
import { at } from "../ui/when";
import { own } from "../ui/own";

import { type Body } from "../api/client";
import { useSplitDecision } from "../api/decisions";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Because } from "../ui/Outcome";
import { Wide } from "../ui/Wide";
import { findingOf } from "../app/routes";
import { issuesIn, toggled } from "./outliers";
import { OutlierRows } from "../ui/OutlierRows";

// The fate of what you proposed.
//
// A whole tab of the review queue with its own endpoint, sharing nothing with
// the decisions waiting for a second person but the offset in the address. A
// different question asked of a different list: the cards next door exist to
// be judged from, and this exists to be read down.

// The fate of each decision this person proposed.
//
// A table rather than cards: the question here is not "should this be agreed
// to" — it has already been answered — it is "what happened to the things I
// said", which is one line each. The cards exist to be judged from; this
// exists to be read down.
export function Became({
  rows,
  query,
}: {
  rows: Body<"BecameBody">[];
  query: { isPending: boolean; isError: boolean; error: unknown };
}) {
  if (query.isPending) return <Loading />;
  if (query.isError) {
    return <Failed error={query.error} what="The decisions you proposed could not be read." />;
  }
  if (rows.length === 0) {
    return (
      <Empty
        title="You have not proposed anything."
        detail="A decision you record appears here with what became of it, whether or not anybody had to agree."
      />
    );
  }
  return (
    <Wide>
      <table>
        <thead>
          <tr>
            <th>Outcome</th>
            <th>Issue</th>
            <th>Component</th>
            <th>Where</th>
            <th className="num">Covers</th>
            <th>When</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <Mine key={row.decision?.id} row={row} />
          ))}
        </tbody>
      </table>
    </Wide>
  );
}

// One decision somebody proposed, and — where it is a bulk decision still being
// argued — what in it does not look like the rest, with a way to hold those
// rows back.
//
// The same signals an approver is shown. An approver reading a bulk decision may
// agree to most of it and set some aside, and so may its author: "this holds
// for most of them but not those four" is the person best placed to say it.
function Mine({ row }: { row: Body<"BecameBody"> }) {
  const split = useSplitDecision();
  const [holding, setHolding] = useState<Set<number>>(new Set());
  const [because, setBecause] = useState("");
  const outliers = row.outliers;
  const decisionId = row.decision?.id ?? 0;

  return (
    <>
      <tr className="row">
        <td>
          <Happened word={row.happened} by={row.by_name || row.by} />
        </td>
        <td>
          {row.finding ? (
            <Link to={findingOf(row.finding)} className="id">
              {row.occurrence?.vulnerability}
            </Link>
          ) : (
            <span className="id">{row.occurrence?.vulnerability}</span>
          )}{" "}
          <Because code={row.decision_occurrence?.justification} />
        </td>
        <td className="id">{row.finding?.component ?? "—"}</td>
        <td className="hint">
          {row.occurrence?.product_name || row.occurrence?.product}
          {row.finding?.branch_or_tag && (
            <>
              {" "}
              · {row.finding.branch_or_tag_name || row.finding.branch_or_tag} ·{" "}
              {row.finding.variant_name || row.finding.variant}
            </>
          )}
        </td>
        <td className="num">
          {/* In the units the queue card uses, said rather than left to
                    be guessed at: one decision can be one row or hundreds. */}
          {(row.issues ?? 0) > 1 ? (
            <>
              {row.issues} issues · {row.rows} rows
            </>
          ) : (
            <span
              title={`${row.occurrences} ${row.occurrences === 1 ? "occurrence" : "occurrences"} underneath`}
            >
              one decision
            </span>
          )}
        </td>
        <td className="hint">{at(row.when) || "—"}</td>
      </tr>
      {outliers && (outliers.rows ?? []).length > 0 && (
        <tr>
          <td colSpan={6}>
            <div className="outliers">
              <header>
                <h5>Rows that do not match the rest</h5>
                <span className="hint">
                  Holding them back makes them a decision of yours. Revise it to say what differs.
                </span>
              </header>
              <OutlierRows
                rows={outliers.rows ?? []}
                holding={holding}
                onToggle={(one, on) => setHolding(toggled(holding, one, on))}
              />
              {holding.size > 0 && (
                <div className="mt-2">
                  {split.error != null && (
                    <Failed error={split.error} what="Those rows could not be held back." />
                  )}
                  <label className="block text-sm" htmlFor={`hold-${decisionId}`}>
                    The reason these are different
                  </label>
                  <textarea
                    id={`hold-${decisionId}`}
                    rows={2}
                    value={because}
                    onChange={(event) => setBecause(event.target.value)}
                    className="w-full rounded border border-[var(--line)] bg-[var(--surface)] p-2 text-sm"
                  />
                  <button
                    type="button"
                    className="btn"
                    disabled={split.isPending || because.trim() === ""}
                    onClick={() =>
                      split.mutate(
                        { id: decisionId, rows: [...holding], because },
                        {
                          onSuccess: () => {
                            setHolding(new Set());
                            setBecause("");
                          },
                        },
                      )
                    }
                  >
                    Hold {issuesIn(outliers.rows ?? [], holding)} back
                  </button>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// One word for what became of a decision, and who did it where a person did.
//
// "Undone" is drawn apart from "waiting" though the decision is waiting in both:
// somebody had agreed, and the proposer is entitled to find that surprising.
export function Happened({ word, by }: { word?: string; by?: string }) {
  const how: Record<Body<"BecameBody">["happened"], { cls: string; said: string }> = {
    waiting: { cls: "waiting", said: "Waiting" },
    "sent-back": { cls: "lapsed", said: "Sent back" },
    approved: { cls: "agreed", said: "Approved" },
    withdrawn: { cls: "lapsed", said: "Withdrawn" },
    lapsed: { cls: "lapsed", said: "Lapsed" },
    undone: { cls: "lapsed", said: "Agreement undone" },
    mixed: { cls: "waiting", said: "Ended several ways" },
  };
  const shown = own(how, word) ?? { cls: "", said: word ?? "" };
  return (
    <>
      <span className={`state ${shown.cls}`}>{shown.said}</span>
      {by && <span className="hint"> by {by}</span>}
    </>
  );
}
