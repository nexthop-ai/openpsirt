// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { useAfterClaim, useApproveClaim, useRejectClaim, type Claim } from "../api/claims";
import { claimAt, decisionAt, findingOf, issueAt } from "../app/routes";
import { notACredential } from "../ui/noautofill";
import { Failed } from "../ui/Failed";
import { Markdown } from "../ui/Markdown";
import { Editor, forget } from "../ui/Editor";
import { Severity, Exploited, ExploitedHere } from "../ui/Severity";
import { called, labeled } from "../ui/Outcome";
import { Wide } from "../ui/Wide";
import { issuesIn, toggled } from "./outliers";
import { promised, wordsFor, type Reason } from "./queueReasons";

// The cards the review queue is drawn in: one per claim, carrying its whole
// argument and the acts that answer it.

// Who proposed a claim and how long it has stood, which every card says first.
function Proposal({ claim }: { claim: Claim }) {
  return (
    <>
      {claim.proposedBy && (
        <span>
          Proposed by <b>{claim.proposedBy}</b>
        </span>
      )}
      <span>
        Standing <b>{claim.ageDays === 0 ? "today" : `${claim.ageDays} days`}</b>
      </span>
    </>
  );
}

// A claim waiting for a new decision rather than an agreement: a deferral
// whose date passed, or a promise whose date passed with the finding open.
//
// It says which promise it was and offers the acts that answer it. Both lists
// are anybody's in the product to act on, the proposer included, so there is
// no approving here. A missed promise can be moved to a new version or date,
// which puts it in front of a second person again where the new date needs
// one; either can be decided again on the finding.
export function Dated({
  claim,
  reason,
  marked,
}: {
  claim: Claim;
  reason: Reason;
  marked: boolean;
}) {
  const f = claim.finding;
  const [moving, setMoving] = useState(false);
  const upgrade = claim.outcome === "upgrade-needed";
  const [to, setTo] = useState(claim.upgradeTo);
  const [by, setBy] = useState("");
  const [because, setBecause] = useState("");
  const [moved, setMoved] = useState(false);
  const after = useAfterClaim();
  // The queue is read again only once the confirmation is put away. The
  // promise leaves this list when its date moves, and the card carrying the
  // answer would leave with it.
  const repromise = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PUT("/v1/claims/{id}/promise", {
          params: { path: { id: claim.id } },
          body: { ...(upgrade ? { to: to.trim() } : {}), by, reasoning: because },
        }),
      ),
    onSuccess: () => {
      setMoving(false);
      setMoved(true);
      after();
    },
  });
  const decideAgain = f ? findingOf(f) : claimAt(claim.id);
  const words = wordsFor(reason);

  return (
    <article
      id={`claim-${claim.id}`}
      className="qcard lapsedcard"
      style={marked ? { outline: "2px solid var(--accent)", outlineOffset: 2 } : undefined}
    >
      <header>
        {f?.severity && <Severity word={f.severity} />}
        {f?.exploited && <Exploited when />}
        <Link to={decideAgain} className="linkish id">
          {claim.title}
        </Link>
        <span className={`claimed ${claim.outcome}`}>
          <b>{promised(claim) || labeled(claim.outcome)}</b>
        </span>
        <span style={{ color: "var(--muted)" }}>
          {f
            ? `${f.product_name || f.product} · ${f.stream_name || f.stream} · ${f.variant_name || f.variant}`
            : claim.product}
          {claim.issues > 1 && <> · {claim.issues.toLocaleString()} issues</>}
        </span>
        <span className="state lapsed" style={{ marginLeft: "auto" }}>
          {words.stated}
        </span>
      </header>
      {claim.reasoning && (
        <div className="why">
          <Markdown source={claim.reasoning} />
        </div>
      )}
      <div className="qmeta">
        <Proposal claim={claim} />
        {claim.builds.length > 0 && (
          <span>
            Covers <b>{claim.builds.join(", ")}</b>
          </span>
        )}
      </div>

      {repromise.error != null && (
        <Failed error={repromise.error} what="The promise could not be changed." />
      )}
      {moved ? (
        <div className="alert info" role="status" style={{ margin: 0 }}>
          <strong>Promise changed</strong>
          <span>
            Any earlier approval was withdrawn.{" "}
            <Link to={claimAt(claim.id)} className="linkish">
              Open the decision →
            </Link>
          </span>
          <button type="button" className="linkish" style={{ marginLeft: "auto" }} onClick={after}>
            Done
          </button>
        </div>
      ) : moving ? (
        <div>
          <div className="filters" style={{ marginBottom: 8 }}>
            {upgrade && (
              <label className="field">
                <span>Version</span>
                <input
                  {...notACredential}
                  type="text"
                  value={to}
                  onChange={(event) => setTo(event.target.value)}
                  style={{ width: 130 }}
                />
              </label>
            )}
            <label className="field">
              <span>By</span>
              <input type="date" value={by} onChange={(event) => setBy(event.target.value)} />
            </label>
          </div>
          <Editor
            value={because}
            onChange={setBecause}
            draftKey={`repromise:${claim.key}`}
            rows={3}
            label="Reason for the change"
            placeholder="Why the date or the version is moving."
          />
          <div className="actions" style={{ marginTop: 8 }}>
            <button
              type="button"
              className="btn"
              disabled={!by || !because.trim() || (upgrade && !to.trim()) || repromise.isPending}
              onClick={() => repromise.mutate()}
            >
              Change the promise
            </button>
            <button type="button" className="btn quiet" onClick={() => setMoving(false)}>
              Cancel
            </button>
            <span className="consequence">Withdraws any approval it had</span>
          </div>
        </div>
      ) : (
        <div className="actions">
          {reason === "missed-fix-date" && (
            <button type="button" className="btn" onClick={() => setMoving(true)}>
              {upgrade ? "Change the version or date" : "Change the date"}
            </button>
          )}
          <Link to={decideAgain} className="btn ghost">
            Decide again →
          </Link>
        </div>
      )}
    </article>
  );
}

// A claim waiting for a second person's agreement, with what an approver needs
// to judge it: the issue and where it sits, the argument, what it covers and
// what would make somebody disagree.
export function Card({
  claim,
  marked,
  picked,
  onPick,
}: {
  claim: Claim;
  // An arrival sent to this claim in particular.
  marked: boolean;
  picked: boolean;
  onPick: (on: boolean) => void;
}) {
  const approveClaim = useApproveClaim();
  const rejectClaim = useRejectClaim();
  const [asking, setAsking] = useState(false);
  const [more, setMore] = useState(false);
  const f = claim.finding;
  const [because, setBecause] = useState("");
  const [aside, setAside] = useState<Set<number>>(new Set());
  // Issues, which is what the claim counts: the set aside holds a decision per
  // place, and one issue can sit at many.
  const rejecting = issuesIn(claim.outliers?.rows ?? [], aside);
  const draftKey = `send-back:${claim.key}`;
  const bulk = claim.kind === "together";
  const extension = claim.kind === "extension";
  const busy = approveClaim.isPending || rejectClaim.isPending;
  const error = approveClaim.error ?? rejectClaim.error;

  function doApprove() {
    approveClaim.mutate({
      id: claim.id,
      ...(aside.size > 0
        ? {
            except: [...aside],
            because: "Set aside at approval: these do not match the shape of the claim.",
          }
        : {}),
    });
  }

  function doReject() {
    rejectClaim.mutate(
      { id: claim.id, because },
      {
        onSuccess: () => {
          forget(draftKey);
          setBecause("");
          setAsking(false);
        },
      },
    );
  }

  return (
    <article
      id={`claim-${claim.id}`}
      className={`qcard${claim.previouslyApproved ? " returning" : ""}${bulk ? " bulkclaim" : ""}${extension ? " extension" : ""}`}
      style={marked ? { outline: "2px solid var(--accent)", outlineOffset: 2 } : undefined}
    >
      <header>
        <input
          type="checkbox"
          className="qpick"
          checked={picked}
          onChange={(event) => onPick(event.target.checked)}
          aria-label="Select this claim"
        />
        {bulk && <span className="bulkmark">Bulk claim</span>}
        {f?.severity && <Severity word={f.severity} />}
        {f?.exploited && <Exploited when />}
        {/* The issue opens its finding, which carries everything an approver
            could want; the decision record is one link further, from there. */}
        <Link to={f ? findingOf(f) : decisionAt(claim.decisionId)} className="linkish id">
          {claim.title}
        </Link>
        {/* What is being claimed, in a mark of its own ahead of where the
            finding lives, because it is what an approver agrees to. */}
        <Outcome
          outcome={claim.outcome}
          justification={claim.justification}
          until={claim.deferredUntil}
          scope={claim.scope}
        />
        <span style={{ color: "var(--muted)" }}>
          {f?.component && (
            <>
              in <span className="id">{f.component}</span>
              {f.version && (
                <span className="id" style={{ color: "var(--faint)" }}>
                  {" "}
                  {f.version}
                </span>
              )}{" "}
              ·{" "}
            </>
          )}
          {f
            ? `${f.product_name || f.product} · ${f.stream_name || f.stream} · ${f.variant_name || f.variant}`
            : claim.product}
          {bulk && claim.issues > 1 && <> · {claim.issues.toLocaleString()} issues</>}
          {extension && claim.derivedFrom && (
            <>
              {" "}
              · extends <b>#{claim.derivedFrom}</b>
            </>
          )}
        </span>
        <span className="state waiting" style={{ marginLeft: "auto" }}>
          {extension ? "Extension" : claim.previouslyApproved ? "Approved before" : "Pending"}
        </span>
      </header>

      {/* What the issue is and where it sits, before the argument about it:
          an approver judging a claim without these is judging the prose.
          Shown from the scan's own text, escaped, never rendered. */}
      {f && (f.description || f.owner || f.parent) && (
        <div className="about">
          {f.description && (
            <p className={more ? "" : "clamp"} style={{ margin: 0 }}>
              {f.description}
              {f.description.length >= 400 && !more && "…"}
            </p>
          )}
          <p
            className="hint"
            style={{ margin: "4px 0 0", display: "flex", flexWrap: "wrap", gap: "4px 12px" }}
          >
            {(f.owner || f.parent) && (
              <span>
                <span className="id">{f.owner}</span>
                {f.parent && f.parent !== f.owner && (
                  <>
                    {" "}
                    › <span className="id">{f.parent}</span>
                  </>
                )}
              </span>
            )}
            {typeof f.places === "number" && (
              <span title={`${f.places} ${f.places === 1 ? "place" : "places"} underneath`}>
                {f.places} {f.places === 1 ? "consumer" : "consumers"}
                {typeof f.decided === "number" && f.decided > 0 && (
                  <> · {f.decided} covered by this claim</>
                )}
              </span>
            )}
            {f.fixed_in ? (
              <span>
                fixed in <span className="id">{f.fixed_in}</span>
              </span>
            ) : f.fix_state === "wont-fix" ? (
              <span>upstream declined</span>
            ) : f.fix_state === "mixed" ? (
              <span>upstream fix differs by build</span>
            ) : null}
            {/* The scheme beside the number. Two are scorable and their
                numbers are not comparable, so a bare score invites a reader to
                rank one against another. */}
            {typeof f.score === "number" && (
              <span>
                CVSS{f.score_version ? ` ${f.score_version}` : ""} {f.score.toFixed(1)}
              </span>
            )}
            {f.description && f.description.length >= 200 && (
              <button
                type="button"
                className="linkish"
                style={{ fontWeight: 500 }}
                onClick={() => setMore(!more)}
              >
                {more ? "less" : "more"}
              </button>
            )}
          </p>
        </div>
      )}

      {claim.reasoning && (
        <div className="why">
          <Markdown source={claim.reasoning} />
        </div>
      )}

      <div className="qmeta">
        <Proposal claim={claim} />
        {claim.deferredDays > 0 && (
          <span>
            Put off <b>{claim.deferredDays} days</b> in total
          </span>
        )}
        {claim.selectedBy && (
          <span>
            Narrowed by <b className="mono">{claim.selectedBy}</b>
          </span>
        )}
        {extension && claim.derivedFrom && (
          <span>
            Rests on <b>#{claim.derivedFrom}</b>
          </span>
        )}
        <span>
          Writes{" "}
          <b>
            {claim.records.toLocaleString()} {claim.records === 1 ? "record" : "records"}
          </b>
        </span>
      </div>

      {!bulk && (
        <div className="reachrow">
          {/* What the claim covers, in the unit it was made in: one judgment
              at one fold, however many places sit underneath. The place count
              is a title rather than a headline — it is what the bulk cap is
              measured against, not a figure an approver reconciles with
              anything else on the card. */}
          <span
            className="r auto"
            title={`${claim.places} ${claim.places === 1 ? "place" : "places"} underneath`}
          >
            <b>one judgment</b> in this build
          </span>
          {claim.builds.length > 0 && (
            <span className="r ask">
              {/* Every build it covers, this one included, which is what the
                  server sends and what the number means. */}
              <b>{claim.builds.length}</b> {claim.builds.length === 1 ? "build" : "builds"} covered:{" "}
              {claim.builds.join(", ")}
            </span>
          )}
          <span className="hint">One approval covers every record; undo reverts them all</span>
        </div>
      )}

      {/* What would make an approver disagree. Two counts and no
          argument: nothing here can know a claim is wrong, and what it says is
          what a careful reader would go and look up — so that not looking is a
          choice rather than an omission. */}
      {claim.counter && (
        <div className="counter">
          <h5>Before approving</h5>
          <ul>
            {Object.entries(claim.counter.elsewhere ?? {}).map(([outcome, places]) => (
              <li key={outcome}>
                The same issue is <b>{called(outcome)}</b> at {places}{" "}
                {places === 1 ? "other place" : "other places"} you can see, already agreed to.
                {outcome !== claim.outcome && (
                  <>
                    {" "}
                    This claim says <b>{called(claim.outcome)}</b>.
                  </>
                )}{" "}
                <Link to={issueAt(claim.title)} className="linkish">
                  Everywhere it sits →
                </Link>
              </li>
            ))}
            {(claim.counter.undecided ?? 0) > 0 && (
              <li>
                <b>{claim.counter.undecided}</b> other{" "}
                {claim.counter.undecided === 1 ? "issue sits" : "issues sit"} undecided at the same
                place. A claim in a run is usually right, and a run is also how one gets waved
                through.
              </li>
            )}
          </ul>
        </div>
      )}

      {/* Every act over many issues carries this, including rows set aside
          from one and one re-made after it lapsed: agreeing to any of them is
          refused over an issue this product was attacked through, and this
          table is where that issue is set aside. */}
      {claim.outliers && (
        <div className="outliers">
          <header>
            <h5>Outliers</h5>
            <span className="hint">Rows that do not match the shape of the claim.</span>
          </header>
          <div className="ostats">
            {claim.outliers.exploited_here > 0 && (
              <span className="o bad">
                <b>{claim.outliers.exploited_here}</b> attacked here
              </span>
            )}
            <span className={`o${claim.outliers.exploited ? " bad" : ""}`}>
              <b>{claim.outliers.exploited}</b> known exploited
            </span>
            <span className={`o${claim.outliers.severe ? " hot" : ""}`}>
              <b>{claim.outliers.severe}</b> critical or high
            </span>
            <span className="o">
              <b>{claim.outliers.fixable}</b> have a fix available
            </span>
            <span className={`o${claim.outliers.unmatched ? " hot" : ""}`}>
              <b>{claim.outliers.unmatched}</b> do not match the narrowing
            </span>
          </div>
          {(claim.outliers.rows ?? []).length > 0 && (
            <Wide style={{ boxShadow: "none" }}>
              <table>
                <thead>
                  <tr>
                    <th style={{ width: 30 }} />
                    <th>Severity</th>
                    <th>Issue</th>
                    <th>Description</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {(claim.outliers.rows ?? []).map((row) => (
                    <tr key={row.decision_id}>
                      <td>
                        {/* Every place of the issue, not one: agreeing to any
                            of them is agreeing to the issue. */}
                        <input
                          type="checkbox"
                          aria-label="Set aside"
                          checked={aside.has(row.decision_id)}
                          onChange={(event) => setAside(toggled(aside, row, event.target.checked))}
                        />
                      </td>
                      <td>
                        <Severity word={row.severity} />
                      </td>
                      <td>
                        <span className="id">{row.vulnerability}</span>{" "}
                        <ExploitedHere when={row.exploited_here} />{" "}
                        <Exploited when={row.exploited} />
                      </td>
                      <td className="hint">{(row.description ?? "").slice(0, 120)}</td>
                      <td className="hint">{(row.why ?? []).join(", ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Wide>
          )}
          <p className="hint" style={{ margin: "8px 0 0" }}>
            Selected rows go back to {claim.proposedBy} as a separate item.
          </p>
        </div>
      )}
      {bulk && !claim.outliers && (
        <p className="hint" style={{ margin: 0 }}>
          One claim over {claim.issues.toLocaleString()} issues, read once and approved once.
        </p>
      )}

      {claim.deferredDays > 0 && claim.previouslyApproved && (
        <p style={{ margin: 0, fontSize: "var(--step--1)", color: "var(--sev-high)" }}>
          Measured against the total already deferred, not the days being asked.
        </p>
      )}

      {error != null && <Failed error={error} what="That could not be recorded." />}

      {asking ? (
        <div>
          {/* No attach control: a rejection is about what is missing from the
              reasoning, and a claim may cover many issues, so there is not one
              a file would hang off. */}
          <Editor
            value={because}
            onChange={setBecause}
            draftKey={draftKey}
            rows={4}
            label="Reason for rejection"
            placeholder="The part that is missing or wrong."
          />
          <div className="actions" style={{ marginTop: 8 }}>
            <button
              type="button"
              className="btn"
              disabled={!because.trim() || busy}
              onClick={doReject}
            >
              Reject
            </button>
            <button type="button" className="btn quiet" onClick={() => setAsking(false)}>
              Cancel
            </button>
            <span className="consequence">
              Rejected, back to <b>{claim.proposedBy}</b>
            </span>
          </div>
        </div>
      ) : (
        <div className="actions">
          <button type="button" className="btn" disabled={busy} onClick={doApprove}>
            {bulk && aside.size > 0
              ? `Approve ${(claim.issues - rejecting).toLocaleString()}, reject ${rejecting}`
              : bulk
                ? `Approve all ${claim.issues.toLocaleString()}`
                : "Approve"}
          </button>
          <button type="button" className="btn ghost" onClick={() => setAsking(true)}>
            {bulk ? "Reject all" : "Reject"}
          </button>
          {bulk && (
            <span className="consequence">
              <b>{claim.records.toLocaleString()}</b> records, each expiring independently
            </span>
          )}
        </div>
      )}
    </article>
  );
}

// The claim itself, said as its own thing: the outcome an approver agrees to,
// in its own mark, with the recognized reason beneath it in the vocabulary the
// record stores.
function Outcome({
  outcome,
  justification,
  until,
  scope,
}: {
  outcome: string;
  justification?: string;
  until?: string;
  scope?: string;
}) {
  return (
    <span className={`claimed ${outcome}`}>
      <b>{labeled(outcome)}</b>
      {justification && <span className="why mono">{justification}</span>}
      {until && <span className="why">until {until}</span>}
      {scope && (
        <span className="why">
          {scope === "portable" ? "for anyone shipping this version" : "for this build only"}
        </span>
      )}
    </span>
  );
}
