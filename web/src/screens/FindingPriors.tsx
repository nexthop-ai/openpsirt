// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { Body } from "../api/client";
import { Markdown } from "../ui/Markdown";
import { Because } from "../ui/Outcome";
import { UpstreamSaid } from "../ui/UpstreamSaid";
import { on } from "../ui/when";
import type { useDecisionPrefill } from "./findingPrefill";

// What others have said about an undecided finding, offered as words to start
// a decision from: what publishers state in received VEX, approved decisions
// at this component, and another product's decision at this occurrence.
// Evidence and a prefill, never an outcome.
export function Priors({
  publishers,
  similar,
  elsewhere,
  extending,
  setExtending,
  startFrom,
  mayTriage,
}: {
  publishers: Body<"SaidBody">[];
  similar: Body<"SimilarBody">[];
  elsewhere: Body<"ElsewhereBody">[];
  // Whether an approved decision is being applied here, which hides the
  // decisions to apply.
  extending: boolean;
  setExtending: (to: { decisionId: number; decisionOccurrenceId: number }) => void;
  startFrom: ReturnType<typeof useDecisionPrefill>["startFrom"];
  mayTriage: boolean;
}) {
  return (
    <>
      {/* Said when there is nothing, because the difference matters:
        an empty panel reads as "nobody has an opinion about this",
        and what it actually means is that no document saying so has
        been received here. The layer is fed only by uploads and
        supplier advisory feeds — nothing derives it, and a distribution's
        will-not-fix arrives through the scanner as an upstream fix
        status instead. */}
      {publishers.length === 0 && (
        <div className="card">
          <h3 title="What suppliers and other publishers state about this">Received VEX</h3>
          <p className="reading" title="Uploaded, or fetched from a supplier advisory feed">
            Nothing received
          </p>
        </div>
      )}

      {publishers.length > 0 && (
        <div className="card">
          <h3 title="What suppliers and other publishers state about this">Received VEX</h3>
          <p className="reading" style={{ marginBottom: 8 }}>
            Evidence. Only what is marked as applying here closes anything.
          </p>
          {publishers.map((one, i) => (
            <div key={`${one.publisher} ${i}`} className="prior">
              <header>
                <span className="id">{one.publisher}</span>{" "}
                <span className="hint">
                  says <b>{(one.status ?? "").replace("_", " ")}</b>
                  {/* The version they spoke about. A supplier names the
                  version that carries the fix, which is not the
                  version shipped here, so the status alone reads as
                  the opposite of what it says. */}
                  {one.about && <> of {one.about}</>}
                  {one.justification && <> · {one.justification.replaceAll("_", " ")}</>}
                  {one.identifier && <> · {one.identifier}</>}
                  {one.at && <> · {on(one.at)}</>}
                </span>{" "}
                {one.source === "upstream" && (
                  <UpstreamSaid
                    statement={one.id ?? 0}
                    forAnybody={!!one.for_anybody}
                    declined={!!one.declined}
                    document={one.document ?? ""}
                    mayTriage={mayTriage}
                  />
                )}
              </header>
              {/* The publisher's own prose, arriving in a document they
              published: a third party's text reaching the people who
              hold the most access here, exactly as a scan file's
              description is. Shown and never rendered —
              rendered, the author chooses headings, tables and the
              text of arbitrary links on the screen a triager decides
              from, and can name one of this deployment's own
              attachments to draw beside their argument. */}
              {one.statement && (
                <div className="why">
                  <p style={{ whiteSpace: "pre-wrap" }}>{one.statement}</p>
                </div>
              )}
              {one.notes && (
                <div className="why">
                  <span className="hint" title="What they say about this status">
                    Notes
                  </span>
                  <p style={{ whiteSpace: "pre-wrap" }}>{one.notes}</p>
                </div>
              )}
              {one.offers && (
                <div className="actions">
                  <button
                    type="button"
                    className="btn ghost"
                    onClick={() =>
                      startFrom({
                        fromStatement: one.id,
                        outcome: one.offers as string,
                        justification:
                          one.offers === "not-applicable" ? (one.justification ?? "") : "",
                        // The version goes into the record too: an
                        // approver reads this months later, and "says
                        // fixed" with nothing saying fixed in what is
                        // the same sentence about a different decision.
                        reasoning:
                          `${one.publisher} says ${(one.status ?? "").replace("_", " ")}` +
                          (one.about ? ` of ${one.about}` : "") +
                          (one.statement ? `: ${one.statement}` : "") +
                          (one.notes ? `\n${one.notes}` : "") +
                          "\n\n",
                      })
                    }
                  >
                    Start from this
                  </button>
                  <span className="hint">Fills in the form. The decision is still yours.</span>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {similar.length > 0 && !extending && (
        <div className="card">
          <h3>Approved decisions at this component</h3>
          <p className="reading" style={{ marginBottom: 8 }}>
            Same component, same justification. Still needs a second person.
          </p>
          {similar.map((s) => (
            <div key={s.decision_occurrence_id} className="prior">
              <header>
                <span className="id">#{s.decision_id}</span> <Because code={s.justification} />
                <span className="hint">
                  approved by {s.approved_by_name || s.approved_by}
                  {s.approved_at && <> on {on(s.approved_at)}</>}
                  {s.issues ? <> · {s.issues} issues rest on it</> : null}
                </span>
              </header>
              <div className="why">
                <Markdown source={s.reasoning ?? ""} />
              </div>
              <div className="actions">
                <button
                  type="button"
                  className="btn ghost"
                  onClick={() => {
                    setExtending({
                      decisionId: s.decision_id,
                      decisionOccurrenceId: s.decision_occurrence_id,
                    });
                    startFrom({
                      outcome: "not-applicable",
                      justification: s.justification,
                      reasoning: s.reasoning,
                    });
                  }}
                >
                  Apply decision #{s.decision_id} to this issue →
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
      {elsewhere.length > 0 && !extending && (
        <div className="card">
          <h3>Decided elsewhere</h3>
          {/* Never an outcome and never a default. Another team's
            decision about their product is not a decision about this
            one — what is shipped around the component differs — so
            this offers words to start from and decides nothing. */}
          <p className="reading" style={{ marginBottom: 8 }}>
            Same issue, same occurrence, another product. Their decision, for reference.
          </p>
          {elsewhere.map((e) => (
            <div key={`${e.product} ${e.decision_occurrence_id}`} className="prior">
              <header>
                <span className="id">{e.product}</span>{" "}
                {e.justification && <Because code={e.justification} />}
                <span className="hint">
                  {e.outcome}
                  {e.approved_by && <> · approved by {e.approved_by_name || e.approved_by}</>}
                  {e.approved_at && <> on {on(e.approved_at)}</>}
                </span>
              </header>
              <div className="why">
                <Markdown source={e.reasoning ?? ""} />
              </div>
              <div className="actions">
                {/* The reasoning alone. Carrying the outcome across
                  would be this screen deciding, and the point of
                  reading somebody else's argument is to judge whether
                  it holds here. */}
                <button
                  type="button"
                  className="btn ghost"
                  onClick={() =>
                    startFrom({
                      reasoning: `${e.reasoning ?? ""}\n\n_Quoted from ${e.product}; checked here._`,
                    })
                  }
                >
                  Start from these words →
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </>
  );
}
