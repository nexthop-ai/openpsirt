// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The decisions made about this finding, and their fate.
//
// The state the head reads, the timeline, the revisions a decision went through,
// the comments on it, and the decisions made at this occurrence before — whose
// reasoning is offered back rather than thrown away. Together they answer one
// question, which is why they are one file: what does the record say, and how
// did it come to say that.

import { useAfterDecision, useDecisionApprovals, useDecisionRevisions } from "../api/decisions";
import { happenedOf, stripeOf } from "../ui/stripe";
import { FLOORS } from "../ui/severities";
import { useState, type ReactNode } from "react";
import { at, on } from "../ui/when";
import { initials } from "../ui/initials";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Body } from "../api/client";
import { notYours, Refused, unwrap } from "../api/queries";
import { Elsewhere } from "../ui/Elsewhere";
import { useComment, useEditComment } from "../api/mutations";
import { Failed } from "../ui/Failed";
import { ReasonEditor } from "../ui/ReasonEditor";
import { Markdown } from "../ui/Markdown";
import { EditPiece, Thread } from "../ui/Thread";
import { Because, labeled } from "../ui/Outcome";
import { UNPLACED, type Sitting } from "../ui/Covering";
import { decisionAt } from "../app/routes";

type Detail = Body<"DecisionOccurrenceDetail">;

export type Previous = {
  // The row reaffirming names, and the decision it belongs to, which is the
  // number a reader is shown.
  id: number;
  decisionId: number;
  outcome: string;
  justification: string;
  deferredUntil: string;
  proposedBy: string;
  proposedAt: string;
  state: string;
  endedAt: string;
  about: string;
  approvedBy: string;
  reasoning: string;
  occurrence: string;
};

// The head's pill reads each decision's state as a whole where the finding
// reports it, not the representative row's: one row approved and forty
// returned is pending, not approved.
//
// A proposed decision that needs nobody is in force, the same as an approved one:
// an "affected" answer or a short deferral waits for no second person.
export function stateOf(
  decisions: Detail[],
  decided: number,
  total: number,
  overall: string[],
): { label: string; cls: string } {
  if (decisions.length === 0)
    return decided > 0 && total > 0
      ? { label: "Decided", cls: "agreed" }
      : { label: "Undecided", cls: "open" };
  const states =
    overall.length === decisions.length
      ? overall
      : decisions.map((c) => c.decision_occurrence?.state ?? "");
  const waits = (i: number) => !!decisions[i]?.decision_occurrence?.needs_approval;
  if (states.some((s, i) => s === "proposed" && waits(i)))
    return { label: "Pending approval", cls: "waiting" };
  if (states.every((s) => s === "approved" || s === "proposed")) {
    const outcome = decisions[0]?.decision_occurrence?.outcome ?? "";
    const word = states.every((s) => s === "approved") ? "approved" : "in force";
    return { label: `${labeled(outcome)} · ${word}`, cls: "agreed" };
  }
  if (states.some((s) => s === "lapsed")) return { label: "Lapsed", cls: "lapsed" };
  return { label: "Decided", cls: "agreed" };
}

// The decision that stands, in its state, with outcome, justification, scope,
// approval, the reasoning rendered, and what may be done to it.
export function Standing({
  decision,
  summary,
  occurrences,
  mine,
  mayApprove,
  onRevised,
  about,
  undisclosed,
  children,
}: {
  decision: Detail;
  summary?: Body<"StandingDecisionBody">;
  occurrences: Sitting[];
  mine: boolean;
  mayApprove: boolean;
  onRevised: () => void;
  about: { product: string; vulnerability: string };
  undisclosed?: boolean;
  // Drawn at the foot of the card: what belongs to this decision and is not
  // its argument, such as the conversation about it.
  children?: ReactNode;
}) {
  // The decision, not the row. What a decision says — its reasoning, the
  // agreement given for it, the conversation about it — belongs to the action
  // that made it, so revising, withdrawing and commenting all name the decision.
  //
  // Taken from the decision rather than from the summary beside it, so that every
  // write on this card names the decision the card is drawing. The two hold the
  // same number; one call here used the decision's and the rest used the
  // summary's, which is a disagreement waiting for the day the pair is wrong.
  const id = decision.decision_occurrence?.decision_id ?? summary?.decision_id ?? 0;
  // The occurrences this decision covers, named rather than counted. A count says
  // how big the decision was and not which code it was about, and on a finding
  // that is only partly decided that is the question somebody has.
  const covers = occurrences
    .filter((occurrence) => id !== 0 && occurrence.decision === id)
    .map((occurrence) => occurrence.consumer || UNPLACED);
  // The decision's state as a whole, not its representative row's: a decision with
  // one row approved and forty sent back is not approved.
  const state = summary?.state ?? decision.decision_occurrence?.state ?? "";
  // Proposed and needing nobody is in force: nothing waits on a second person.
  const waiting = state === "proposed" && !!decision.decision_occurrence?.needs_approval;
  const rows = summary?.rows;
  const mixed =
    !!rows &&
    [rows.proposed ?? 0, rows.sent_back ?? 0, rows.approved ?? 0].filter((n) => n > 0).length > 1;
  const sentBackAt = summary?.sent_back_at ?? decision.decision_occurrence?.sent_back_at;
  const queries = useQueryClient();
  const approvals = useDecisionApprovals(id);
  const live = (approvals.data?.items ?? []).filter((a) => !a.withdrawn_at);
  const last = live[live.length - 1];
  const stripe = stripeOf(
    happenedOf(state, !!sentBackAt),
    !!decision.decision_occurrence?.needs_approval,
  );

  return (
    <div className={`card standing ${stripe}`}>
      <header className="dhead">
        <h3>
          Decision <span className="id">#{id}</span>
        </h3>
        <span className="hint">
          proposed by <b>{decision.proposed_by_name || decision.proposed_by}</b>
          {decision.proposed_at && <> · {at(decision.proposed_at)}</>}
          {typeof decision.age_days === "number" && decision.age_days > 365 && (
            <>
              {" "}
              ·{" "}
              <span style={{ color: "var(--sev-medium)" }}>
                a decision this old is worth re-reading
              </span>
            </>
          )}
        </span>
      </header>
      {sentBackAt && (
        <div className="alert" style={{ marginBottom: 12 }}>
          <strong>
            Rejected on {on(sentBackAt)}
            {rows &&
            (rows.sent_back ?? 0) > 0 &&
            (rows.sent_back ?? 0) <
              (rows.proposed ?? 0) + (rows.sent_back ?? 0) + (rows.approved ?? 0)
              ? ` — ${rows.sent_back} of ${(rows.proposed ?? 0) + (rows.sent_back ?? 0) + (rows.approved ?? 0)} records`
              : ""}
          </strong>
          <span>
            {summary?.sent_back_because ? <>{summary.sent_back_because} — </> : null}
            back with whoever wrote it, and out of the review queue until it is revised.
          </span>
        </div>
      )}
      <div className="dgrid">
        <div>
          <span className="l">Outcome</span>
          <span className="v">
            {labeled(decision.decision_occurrence?.outcome ?? "")}
            {decision.decision_occurrence?.deferred_until && (
              <> until {decision.decision_occurrence.deferred_until}</>
            )}
          </span>
        </div>
        {decision.decision_occurrence?.justification && (
          <div>
            <span className="l">Justification</span>
            <span className="v">
              <Because code={decision.decision_occurrence.justification} />
            </span>
            {decision.decision_occurrence.mitigation && (
              <span className="hint">stopped by: {decision.decision_occurrence.mitigation}</span>
            )}
          </div>
        )}
        {/* The evidence for a decision that the fix is already here, on the
            screen the decision is read from. It is the one outcome that states
            a fact somebody can check, and it is checked from here. */}
        {decision.decision_occurrence?.fixed_version && (
          <div>
            <span className="l">Fixed in</span>
            <span className="v mono">{decision.decision_occurrence.fixed_version}</span>
            <span className="hint">as the packager states it; not compared against what ships</span>
          </div>
        )}
        <div>
          <span className="l">Scope</span>
          <span className="v">
            {summary?.occurrences ?? decision.decision_occurrence?.occurrences ?? 1}{" "}
            {(summary?.occurrences ?? decision.decision_occurrence?.occurrences ?? 1) === 1
              ? "occurrence"
              : "occurrences"}{" "}
            here
            {/* Named, not just counted — an occurrence is what pulls the
                component in, which is what the decision is keyed on. Three at
                most: a kernel sits at sixty and the list would be the card. */}
            {covers.length > 0 && (
              <>
                {" ("}
                <span className="id">{covers.slice(0, 3).join(", ")}</span>
                {covers.length > 3 && <> and {covers.length - 3} more</>}
                {")"}
              </>
            )}
            {(summary?.builds ?? []).length > 0 && <> · also {summary?.builds?.join(", ")}</>}
            {summary?.kind === "extension" && <> · extends an approved decision</>}
            {decision.decision_occurrence?.selected_by && (
              <> · narrowed by: {decision.decision_occurrence.selected_by}</>
            )}
          </span>
        </div>
        <div>
          <span className="l">Approval</span>
          <span className="v">
            {state === "proposed" && !waiting ? (
              <>
                <span className="state agreed">In force</span> needs no second person
              </>
            ) : state === "proposed" ? (
              <>
                <span className="state waiting">Pending</span> waiting for a second person
                {mixed && rows && (
                  <>
                    {" "}
                    · {rows.approved ?? 0} approved · {rows.proposed ?? 0} pending ·{" "}
                    {rows.sent_back ?? 0} returned
                  </>
                )}
                {mine && " — you proposed this, so you cannot approve it"}
                {!mine && mayApprove && " — you may approve or reject it from the review queue"}
              </>
            ) : state === "approved" && last ? (
              <>
                <span className="state agreed">Approved</span> by{" "}
                <b>{last.approved_by_name || last.approved_by}</b>
                {last.approved_at && <>, {at(last.approved_at)}</>}
                {/* Carried onto this decision from the one it re-affirms: they
                    agreed to those words rather than to the reasoning shown
                    here. */}
                {last.carried_from && <span className="hint"> · carried forward</span>}
                {typeof last.covered === "number" && (
                  <> · covered {last.covered} records at the time</>
                )}
              </>
            ) : state === "approved" && approvals.isError ? (
              <>
                <span className="state agreed">Approved</span>
                <span className="hint"> · who approved it could not be read</span>
              </>
            ) : state === "approved" ? (
              <>
                <span className="state agreed">Approved</span>
                {decision.decision_occurrence?.needs_approval === false &&
                  " — needed nobody: under the deferral threshold"}
              </>
            ) : (
              <span className={`state ${state === "lapsed" ? "lapsed" : "open"}`}>{state}</span>
            )}
          </span>
        </div>
      </div>

      <ReasonEditor
        decisionId={id}
        reasoning={decision.reasoning ?? ""}
        state={state}
        approved={state === "approved"}
        about={about}
        undisclosed={undisclosed}
        onDone={onRevised}
        spaced
      />
      <Elsewhere
        id={id}
        where={summary?.elsewhere ?? ""}
        onSet={() => void queries.invalidateQueries({ queryKey: ["finding"] })}
      />
      {children}
    </div>
  );
}

type Event = { when: string; who: string; what: string; earlier?: boolean };

// One timeline: what happened to the decision that stands, and what happened at
// this occurrence before it.
export function Activity({
  decisionId,
  decision,
  occurrences,
  previous,
}: {
  decisionId: number;
  decision: Detail;
  occurrences?: number;
  previous: Previous[];
}) {
  const approvals = useDecisionApprovals(decisionId);
  const revisions = useDecisionRevisions(decisionId);
  const comments = useQuery({
    queryKey: ["comments", decisionId],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/decisions/{id}/comments", { params: { path: { id: decisionId } } }),
      ),
  });

  const now: Event[] = [];
  now.push({
    when: decision.proposed_at ?? "",
    who: decision.proposed_by_name || decision.proposed_by || "",
    what: `proposed #${decisionId} — ${labeled(decision.decision_occurrence?.outcome ?? "")} · ${occurrences ?? decision.decision_occurrence?.occurrences ?? 1} ${(occurrences ?? decision.decision_occurrence?.occurrences ?? 1) === 1 ? "occurrence" : "occurrences"}`,
  });
  for (const r of revisions.data?.items ?? []) {
    if ((r.ordinal ?? 1) > 1)
      now.push({
        when: r.written_at ?? "",
        who: r.written_by_name || r.written_by || "",
        what: `revised the reasoning (revision ${r.ordinal})`,
      });
  }
  for (const a of approvals.data?.items ?? []) {
    now.push({
      when: a.approved_at ?? "",
      who: a.approved_by_name || a.approved_by || "",
      what: a.carried_from
        ? `agreement carried forward onto revision ${a.revision_id}`
        : `approved revision ${a.revision_id}${a.batch ? ` (batch ${a.batch})` : ""}`,
    });
    if (a.withdrawn_at)
      now.push({
        when: a.withdrawn_at,
        who: a.approved_by_name || a.approved_by || "",
        what: "approval withdrawn",
      });
  }
  for (const c of comments.data?.items ?? []) {
    now.push({
      when: c.written_at ?? "",
      who: c.written_by_name || c.written_by || "",
      what: "commented",
    });
  }
  if (decision.decision_occurrence?.sent_back_at)
    now.push({
      when: decision.decision_occurrence.sent_back_at,
      who: "",
      what: "rejected — returned for revision",
    });
  now.sort((a, b) => b.when.localeCompare(a.when));

  const earlier: Event[] = previous.map((p) => ({
    when: p.proposedAt,
    who: p.proposedBy,
    what: `proposed #${p.decisionId} — ${labeled(p.outcome)}${p.state ? ` · ${p.state}` : ""}`,
    earlier: true,
  }));
  earlier.sort((a, b) => b.when.localeCompare(a.when));

  const line = (e: Event, i: number) => (
    <li key={`${e.when} ${e.what} ${i}`}>
      <span className="when">{at(e.when) || "—"}</span>
      <span className={`avatar${e.who ? "" : " none"}`}>{initials(e.who)}</span>
      <span className="what">
        {e.who && <b>{e.who} </b>}
        {e.what}
      </span>
    </li>
  );

  // A timeline assembled from three reads is only whole when all three
  // answered. One that failed takes its events out silently — and what is
  // missing from a record is the thing a reader cannot see is missing.
  const unread = [revisions, approvals, comments].find(
    (each) => each.isError && !notYours(each.error),
  );

  return (
    <div className="card">
      <h3>Activity</h3>
      {unread && (
        <Failed error={unread.error} what="Part of this decision's history could not be read." />
      )}
      <ul className="timeline">{now.map(line)}</ul>
      {earlier.length > 0 && (
        <>
          <p className="eyebrow" style={{ margin: "12px 0 6px" }}>
            Earlier at this occurrence
          </p>
          <ul className="timeline past">{earlier.map(line)}</ul>
        </>
      )}
    </div>
  );
}

// Every revision is kept. An approval names the revision it was given for,
// and revising withdraws it.
export function Revisions({ decisionId }: { decisionId: number }) {
  const revisions = useDecisionRevisions(decisionId);
  const approvals = useDecisionApprovals(decisionId);
  const items = revisions.data?.items ?? [];
  if (revisions.isError && !notYours(revisions.error)) {
    return (
      <div className="card">
        <h3>Revision history</h3>
        <Failed error={revisions.error} what="The revision history could not be read." />
      </div>
    );
  }
  if (items.length === 0) return null;
  // Who approved each revision is unknown, not "never", where that read failed.
  const unagreed = approvals.isError && !notYours(approvals.error);
  const agreed = new Map<number, { by: string; at: string; withdrawn: boolean }>();
  for (const a of approvals.data?.items ?? []) {
    if (a.revision_id)
      agreed.set(a.revision_id, {
        by: a.approved_by_name || a.approved_by || "",
        at: a.approved_at ?? "",
        withdrawn: !!a.withdrawn_at,
      });
  }

  return (
    <div className="card">
      <h3>Revision history</h3>
      <div className="history">
        {items.map((r) => {
          const a = r.id ? agreed.get(r.id) : undefined;
          return (
            <div key={r.id} className={`version${a && !a.withdrawn ? " agreed" : ""}`}>
              <span className="stamp">
                <b>Revision {r.ordinal}</b>
                {at(r.written_at)} · {r.written_by_name || r.written_by}
              </span>
              <div>
                <div className="tagline">
                  {a ? (
                    <span className={a.withdrawn ? "state open" : "state agreed"}>
                      {a.withdrawn ? "Approval withdrawn" : "Approved"} by {a.by}
                      {a.at && <>, {on(a.at)}</>}
                    </span>
                  ) : unagreed ? (
                    <span
                      className="hint"
                      title={
                        approvals.error instanceof Refused ? approvals.error.message : undefined
                      }
                    >
                      Approvals could not be read
                    </span>
                  ) : (
                    <span className="state waiting">Never approved</span>
                  )}
                </div>
                <div className="words">
                  <Markdown source={r.body ?? ""} />
                </div>
              </div>
            </div>
          );
        })}
      </div>
      <p className="hint" style={{ margin: "10px 0 0" }}>
        Approvals name a revision. Revising withdraws the approval.
      </p>
    </div>
  );
}

// Comments are separate from the reasoning and never affect an approval.
export function Comments({
  decisionId,
  mine,
  about,
  undisclosed,
  internal,
  within,
  writes = true,
}: {
  decisionId: number;
  // Drawn inside the decision's own card rather than as a card of its own.
  within?: boolean;
  mine: (who: string) => boolean;
  // The issue a file would be attached to. Comments are written about one, so
  // the control can say what it is attaching to rather than guessing.
  about: { product: string; vulnerability: string };
  // The disclosure of the thing being discussed, which is what decides
  // who may be offered after an @: naming somebody who cannot open the finding
  // calls them to something they will be refused, and on an undisclosed one
  // the mention itself says a finding exists.
  undisclosed?: boolean;
  // Whether it is internal material: a code finding's, until its flaw is disclosed.
  internal?: boolean;
  // Whether the reader may comment, which reading the decision does not imply.
  writes?: boolean;
}) {
  const comment = useComment();
  const comments = useQuery({
    queryKey: ["comments", decisionId],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/decisions/{id}/comments", { params: { path: { id: decisionId } } }),
      ),
  });

  return (
    <div className={within ? "within" : "card"}>
      {within ? <h4>Comments on this decision</h4> : <h3>Comments</h3>}
      <Thread
        items={comments.data?.items ?? []}
        mine={mine}
        about={about}
        undisclosed={undisclosed}
        internal={internal}
        word="Comment"
        consequence="Does not affect the approval"
        placeholder="A question, a note, something worth knowing later."
        draftKey={`comment:${decisionId}`}
        // silent-read: a write's answer, whose failure the thread draws from `adding`.
        notNotified={comment.data?.not_notified ?? []}
        // Said, as the note thread says it: an empty thread with a live
        // composer above it reads as a decision nobody has objected to.
        unread={
          comments.isError && !notYours(comments.error) ? (
            <Failed
              error={comments.error}
              what="The comments on this decision could not be read."
            />
          ) : null
        }
        adding={comment}
        onAdd={(body, done) => comment.mutate({ id: decisionId, body }, { onSuccess: done })}
        edit={(piece, done) => (
          <EditPiece
            id={piece.id ?? 0}
            was={piece.body ?? ""}
            label="Comment"
            useEdit={useEditComment}
            about={about}
            undisclosed={undisclosed}
            internal={internal}
            onDone={done}
          />
        )}
        useHistory={useCommentHistory}
        writes={writes}
      />
    </div>
  );
}

// One comment's earlier versions, as the thread asks for them. A hook rather
// than a component, because the thread decides when to draw them and this
// decides where they come from — which is the only thing a comment thread and
// a note thread do not share.
function useCommentHistory(id: number) {
  return useQuery({
    queryKey: ["comment", id, "history"],
    queryFn: async () =>
      unwrap(await api.GET("/v1/comments/{id}/history", { params: { path: { id } } })),
  });
}

// The decisions made here before — lapsed, withdrawn — with their reasoning
// offered back rather than thrown away, and a lapsed one reaffirmed in place.
export function PreviousCard({
  items,
  at,
  undecided,
  onReuse,
}: {
  items: Previous[];
  at: { product: string; branch_or_tag: string; variant: string; vulnerability: string };
  undecided: boolean;
  onReuse: (reasoning: string, outcome: string, justification: string) => void;
}) {
  return (
    <div className="card">
      <h3>Previous decisions at this occurrence</h3>
      <p className="hint" style={{ margin: "0 0 10px" }}>
        Lapsed and withdrawn decisions cover nothing. Kept so you can reuse the reasoning.
      </p>
      <div className="priors">
        {items.map((d) => (
          <Prior key={d.id} item={d} at={at} undecided={undecided} onReuse={onReuse} />
        ))}
      </div>
    </div>
  );
}

function Prior({
  item,
  at,
  undecided,
  onReuse,
}: {
  item: Previous;
  at: { product: string; branch_or_tag: string; variant: string; vulnerability: string };
  undecided: boolean;
  onReuse: (reasoning: string, outcome: string, justification: string) => void;
}) {
  const after = useAfterDecision();
  const [note, setNote] = useState("");
  const [asking, setAsking] = useState(false);
  // What reaffirming answered, said on the card it was done from.
  const [done, setDone] = useState<{ decisionId: number; waiting: boolean } | null>(null);
  const reaffirm = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST(
          "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/findings/{issue}/occurrences/{occurrence}/decision/reaffirmation",
          {
            params: {
              path: {
                product: at.product,
                branch_or_tag: at.branch_or_tag,
                variant: at.variant,
                issue: at.vulnerability,
                occurrence: item.occurrence,
              },
            },
            body: { previous: item.id, reasoning: `${item.reasoning}\n\n${note}`.trim() },
          },
        ),
      ),
    onSuccess: (made) => {
      setAsking(false);
      setDone({ decisionId: made.decision_id ?? 0, waiting: !!made.needs_approval });
      after();
    },
  });
  const lapsed = item.state === "lapsed";

  return (
    <article className="prior">
      <header>
        <span className="id">#{item.decisionId}</span> <b>{labeled(item.outcome)}</b>
        {item.justification && (
          <>
            {" "}
            · <Because code={item.justification} />
          </>
        )}
        {item.deferredUntil && <> to {item.deferredUntil}</>}
        <span className={`state ${lapsed ? "lapsed" : "open"}`} style={{ marginLeft: "auto" }}>
          {item.state}
        </span>
      </header>
      <p className="hint" style={{ margin: "4px 0 6px" }}>
        {item.about && (
          <>
            About <span className="id">{item.about}</span> ·{" "}
          </>
        )}
        Proposed by {item.proposedBy}
        {item.proposedAt && <> on {on(item.proposedAt)}</>}
        {item.approvedBy && <> · approved by {item.approvedBy}</>}
        {item.endedAt && (
          <>
            {" "}
            · {item.state} {on(item.endedAt)}
          </>
        )}
      </p>
      {item.reasoning && (
        <div className="why">
          <Markdown source={item.reasoning} />
        </div>
      )}
      {reaffirm.error != null && (
        <Failed error={reaffirm.error} what="That could not be reaffirmed." />
      )}
      {done && (
        <div className="alert info" role="status" style={{ margin: "8px 0 0" }}>
          <strong>Reaffirmed</strong>
          <span>
            {done.waiting
              ? "It takes effect once a second person agrees. "
              : "In force now, with the earlier agreement carried onto it."}
            {done.waiting && done.decisionId > 0 && (
              <Link to={decisionAt(done.decisionId)} className="linkish">
                Open the decision →
              </Link>
            )}
          </span>
        </div>
      )}
      {asking && (
        <div className="field" style={{ margin: "8px 0 0", maxWidth: "78ch" }}>
          <label>Reaffirmation note</label>
          <textarea
            value={note}
            style={{ minHeight: 64 }}
            placeholder="What you checked against the version that ships now — the earlier reasoning stays above; this is the addendum."
            onChange={(event) => setNote(event.target.value)}
          />
        </div>
      )}
      <div className="actions">
        {lapsed && undecided && item.occurrence && !asking && (
          <button type="button" className="btn" onClick={() => setAsking(true)}>
            Reaffirm
          </button>
        )}
        {asking && (
          <>
            <button
              type="button"
              className="btn"
              disabled={!note.trim() || reaffirm.isPending}
              onClick={() => reaffirm.mutate()}
            >
              Reaffirm
            </button>
            <button type="button" className="btn quiet" onClick={() => setAsking(false)}>
              Cancel
            </button>
            <span className="consequence">
              Keeps the earlier approval, unless it was never agreed or the issue is rated worse
            </span>
          </>
        )}
        {undecided && item.reasoning && !asking && (
          <button
            type="button"
            className="btn ghost"
            onClick={() => onReuse(item.reasoning, item.outcome, item.justification)}
          >
            Reuse this reasoning
          </button>
        )}
        <Link to={decisionAt(item.decisionId)} className="linkish">
          Open #{item.decisionId} →
        </Link>
      </div>
    </article>
  );
}

export const RATINGS = FLOORS;
