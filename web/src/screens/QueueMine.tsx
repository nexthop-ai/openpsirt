import { useState } from "react";
import { Link } from "react-router-dom";

import { type Body } from "../api/client";
import { useSplitClaim } from "../api/claims";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Because } from "../ui/Outcome";
import { Exploited, Severity } from "../ui/Severity";
import { Wide } from "../ui/Wide";

// The fate of what you proposed.
//
// A whole tab of the review queue with its own endpoint, sharing nothing with
// the claims waiting for a second person but the offset in the address. A
// different question asked of a different list: the cards next door exist to
// be judged from, and this exists to be read down.

// The fate of each claim this person proposed.
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
    return <Failed error={query.error} what="What you proposed could not be read." />;
  }
  if (rows.length === 0) {
    return (
      <Empty
        title="You have not proposed anything."
        detail="A judgment you record appears here with what became of it, whether or not anybody had to agree."
      />
    );
  }
  return (
    <Wide>
      <table>
        <thead>
          <tr>
            <th>What became of it</th>
            <th>Issue</th>
            <th>Component</th>
            <th>Where</th>
            <th className="num">Covers</th>
            <th>When</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <Mine key={row.claim?.id} row={row} />
          ))}
        </tbody>
      </table>
    </Wide>
  );
}

// One claim somebody proposed, and — where it is a bulk claim still being
// argued — what in it does not look like the rest, with a way to hold those
// rows back.
//
// The same signals an approver is shown. An approver reading a bulk claim may
// agree to most of it and set some aside; until this the author could only
// withdraw the whole thing and start again, so "this holds for most of them
// but not those four" was unavailable to the person best placed to say it.
function Mine({ row }: { row: Body<"BecameBody"> }) {
  const split = useSplitClaim();
  const [holding, setHolding] = useState<Set<number>>(new Set());
  const [because, setBecause] = useState("");
  const outliers = row.outliers;
  const claimId = row.claim?.id ?? 0;

  return (
    <>
      <tr className="row">
        <td>
          <Happened word={row.happened} by={row.by} />
        </td>
        <td>
          {row.finding ? (
            <Link
              to={
                `/products/${encodeURIComponent(row.finding.product ?? "")}` +
                `/streams/${encodeURIComponent(row.finding.stream ?? "")}` +
                `/variants/${encodeURIComponent(row.finding.variant ?? "")}` +
                `/findings/${encodeURIComponent(row.finding.vulnerability ?? "")}` +
                `/components/${encodeURIComponent(row.finding.component ?? "")}`
              }
              className="id"
            >
              {row.place?.vulnerability}
            </Link>
          ) : (
            <span className="id">{row.place?.vulnerability}</span>
          )}{" "}
          <Because code={row.decision?.justification} />
        </td>
        <td className="id">{row.finding?.component ?? "—"}</td>
        <td className="hint">
          {row.place?.product}
          {row.finding?.stream && (
            <>
              {" "}
              · {row.finding.stream} · {row.finding.variant}
            </>
          )}
        </td>
        <td className="num">
          {/* In the units the queue card uses, said rather than left to
                    be guessed at: one judgment can be one row or hundreds. */}
          {(row.issues ?? 0) > 1 ? (
            <>
              {row.issues} issues · {row.decisions} rows
            </>
          ) : (
            <span title={`${row.places} ${row.places === 1 ? "place" : "places"} underneath`}>
              one judgment
            </span>
          )}
        </td>
        <td className="hint">{row.when ? row.when.replace("T", " ").slice(0, 16) : "—"}</td>
      </tr>
      {outliers && (outliers.rows ?? []).length > 0 && (
        <tr>
          <td colSpan={6}>
            <div className="outliers">
              <header>
                <h5>Rows that do not match the rest</h5>
                <span className="hint">
                  Holding them back makes them a claim of yours. Revise it to say what differs.
                </span>
              </header>
              <Wide style={{ boxShadow: "none" }}>
                <table>
                  <thead>
                    <tr>
                      <th style={{ width: 30 }} />
                      <th>Severity</th>
                      <th>Issue</th>
                      <th>Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(outliers.rows ?? []).map((one) => (
                      <tr key={one.decision_id}>
                        <td>
                          <input
                            type="checkbox"
                            aria-label="Hold back"
                            checked={holding.has(one.decision_id)}
                            onChange={(event) => {
                              const next = new Set(holding);
                              if (event.target.checked) next.add(one.decision_id);
                              else next.delete(one.decision_id);
                              setHolding(next);
                            }}
                          />
                        </td>
                        <td>
                          <Severity word={one.severity} />
                        </td>
                        <td>
                          <span className="id">{one.vulnerability}</span>{" "}
                          <Exploited when={one.exploited} />
                        </td>
                        <td className="hint">{(one.why ?? []).join(", ")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Wide>
              {holding.size > 0 && (
                <div className="mt-2">
                  {split.error != null && (
                    <Failed error={split.error} what="Those rows could not be held back." />
                  )}
                  <label className="block text-sm" htmlFor={`hold-${claimId}`}>
                    Why these are different
                  </label>
                  <textarea
                    id={`hold-${claimId}`}
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
                        { id: claimId, rows: [...holding], because },
                        {
                          onSuccess: () => {
                            setHolding(new Set());
                            setBecause("");
                          },
                        },
                      )
                    }
                  >
                    Hold {holding.size} back
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

// One word for what became of a claim, and who did it where a person did.
//
// "Undone" is drawn apart from "waiting" though the claim is waiting in both:
// somebody had agreed, and the proposer is entitled to find that surprising.
export function Happened({ word, by }: { word?: string; by?: string }) {
  const how: Record<string, { cls: string; said: string }> = {
    waiting: { cls: "waiting", said: "Waiting" },
    "sent-back": { cls: "lapsed", said: "Sent back" },
    approved: { cls: "agreed", said: "Approved" },
    withdrawn: { cls: "lapsed", said: "Withdrawn" },
    lapsed: { cls: "lapsed", said: "Lapsed" },
    undone: { cls: "lapsed", said: "Agreement undone" },
    mixed: { cls: "waiting", said: "Ended several ways" },
  };
  const shown = how[word ?? ""] ?? { cls: "", said: word ?? "" };
  return (
    <>
      <span className={`state ${shown.cls}`}>{shown.said}</span>
      {by && <span className="hint"> by {by}</span>}
    </>
  );
}
