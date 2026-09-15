// What has been claimed about this finding, and what happened to it.
//
// The state the head reads, the timeline, the revisions a claim went through,
// the comments on it, and the judgments made at this place before — whose
// reasoning is offered back rather than thrown away. Together they answer one
// question, which is why they are one file: what does the record say, and how
// did it come to say that.

import { FLOORS } from "../ui/severities";
import { useState } from "react";
import { on } from "../ui/when";
import { initials } from "../ui/initials";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Body } from "../api/client";
import { notYours, unwrap } from "../api/queries";
import { Outward } from "../ui/Outward";
import { useComment, useEditComment } from "../api/mutations";
import { Failed } from "../ui/Failed";
import { ReasonEditor } from "../ui/ReasonEditor";
import { Markdown } from "../ui/Markdown";
import { Thread } from "../ui/Thread";
import { Editor, mentioning } from "../ui/Editor";
import { Because, labeled } from "../ui/Outcome";
import { UNPLACED, type Sitting } from "../ui/Covering";

type Detail = Body<"DecisionDetail">;

export type Previous = {
  id: number;
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
  place: string;
};

// The head's pill reads each claim's state as a whole where the finding
// reports it, not the representative row's: one row approved and forty
// returned is pending, not approved.
export function stateOf(
  claims: Detail[],
  decided: number,
  total: number,
  overall: string[],
): { label: string; cls: string } {
  if (claims.length === 0)
    return decided > 0 && total > 0
      ? { label: "Decided", cls: "agreed" }
      : { label: "Undecided", cls: "open" };
  const states =
    overall.length === claims.length ? overall : claims.map((c) => c.decision?.state ?? "");
  if (states.some((s) => s === "proposed")) return { label: "Pending approval", cls: "waiting" };
  if (states.every((s) => s === "approved")) {
    const outcome = claims[0]?.decision?.outcome ?? "";
    return { label: `${labeled(outcome)} · approved`, cls: "agreed" };
  }
  if (states.some((s) => s === "lapsed")) return { label: "Lapsed", cls: "lapsed" };
  return { label: "Decided", cls: "agreed" };
}

// The claim that stands, in its state, with outcome, justification, scope,
// approval, the reasoning rendered, and what may be done to it.
export function Standing({
  claim,
  summary,
  places,
  mine,
  mayApprove,
  onRevised,
  about,
  undisclosed,
}: {
  claim: Detail;
  summary?: Body<"StandingClaimBody">;
  places: Sitting[];
  mine: boolean;
  mayApprove: boolean;
  onRevised: () => void;
  about: { product: string; vulnerability: string };
  undisclosed?: boolean;
}) {
  // The claim, not the row. What a judgment says — its reasoning, the
  // agreement given for it, the conversation about it — belongs to the action
  // that made it, so revising, withdrawing and commenting all name the claim.
  //
  // Taken from the claim rather than from the summary beside it, so that every
  // write on this card names the claim the card is drawing. The two hold the
  // same number; one call here used the claim's and the rest used the
  // summary's, which is a disagreement waiting for the day the pair is wrong.
  const id = claim.decision?.claim_id ?? summary?.claim_id ?? 0;
  // Which places this claim covers, named rather than counted. A count says
  // how big the judgment was and not which code it was about, and on a finding
  // that is only partly decided that is the question somebody has.
  const covers = places
    .filter((place) => id !== 0 && place.claim === id)
    .map((place) => place.consumer || UNPLACED);
  // The claim's state as a whole, not its representative row's: a claim with
  // one row approved and forty sent back is not approved.
  const state = summary?.state ?? claim.decision?.state ?? "";
  const rows = summary?.rows;
  const mixed =
    !!rows &&
    [rows.proposed ?? 0, rows.sent_back ?? 0, rows.approved ?? 0].filter((n) => n > 0).length > 1;
  const sentBackAt = summary?.sent_back_at ?? claim.decision?.sent_back_at;
  const queries = useQueryClient();
  // Where this claim's work is happening. Stored and never fetched.
  const point = useMutation({
    mutationFn: async (where: string) =>
      unwrap(
        await api.PUT("/v1/claims/{id}/elsewhere", {
          params: { path: { id } },
          body: { elsewhere: where },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["finding"] }),
  });
  const approvals = useQuery({
    queryKey: ["decision", id, "approvals"],
    queryFn: async () =>
      unwrap(await api.GET("/v1/claims/{id}/approvals", { params: { path: { id } } })),
  });
  const live = (approvals.data?.items ?? []).filter((a) => !a.withdrawn_at);
  const last = live[live.length - 1];
  const stripe =
    state === "proposed"
      ? "pending"
      : state === "approved"
        ? "approved"
        : state === "lapsed"
          ? "lapsed"
          : "";

  return (
    <div className={`card standing ${stripe}`}>
      <header className="dhead">
        <h3>
          Decision <span className="id">#{id}</span>
        </h3>
        <span className="hint">
          proposed by <b>{claim.proposed_by}</b>
          {claim.proposed_at && <> · {claim.proposed_at.replace("T", " ").slice(0, 16)}</>}
          {typeof claim.age_days === "number" && claim.age_days > 365 && (
            <>
              {" "}
              ·{" "}
              <span style={{ color: "var(--sev-medium)" }}>
                a judgment this old is worth re-reading
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
            {labeled(claim.decision?.outcome ?? "")}
            {claim.decision?.deferred_until && <> until {claim.decision.deferred_until}</>}
          </span>
        </div>
        {claim.decision?.justification && (
          <div>
            <span className="l">Justification</span>
            <span className="v">
              <Because code={claim.decision.justification} />
            </span>
            {claim.decision.mitigation && (
              <span className="hint">stopped by: {claim.decision.mitigation}</span>
            )}
          </div>
        )}
        {/* The evidence for a claim that the fix is already here, on the
            screen the claim is read from. It is the one outcome whose claim
            is a fact somebody can check, and it is checked from here. */}
        {claim.decision?.fixed_version && (
          <div>
            <span className="l">Fixed in</span>
            <span className="v mono">{claim.decision.fixed_version}</span>
            <span className="hint">as the packager states it; not compared against what ships</span>
          </div>
        )}
        <div>
          <span className="l">Scope</span>
          <span className="v">
            {summary?.places ?? claim.decision?.places ?? 1}{" "}
            {(summary?.places ?? claim.decision?.places ?? 1) === 1 ? "place" : "places"} here
            {/* Named, not just counted — a place is what pulls the
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
            {summary?.kind === "extension" && <> · extends an approved claim</>}
            {claim.decision?.selected_by && <> · narrowed by: {claim.decision.selected_by}</>}
          </span>
        </div>
        <div>
          <span className="l">Approval</span>
          <span className="v">
            {state === "proposed" ? (
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
                <span className="state agreed">Approved</span> by <b>{last.approved_by}</b>
                {last.approved_at && <>, {last.approved_at.replace("T", " ").slice(0, 16)}</>}
                {/* Carried onto this claim from the one it re-affirms: they
                    agreed to those words rather than to the reasoning shown
                    here. */}
                {last.carried_from && <span className="hint"> · carried forward</span>}
                {typeof last.covered === "number" && (
                  <> · covered {last.covered} records at the time</>
                )}
              </>
            ) : state === "approved" ? (
              <>
                <span className="state agreed">Approved</span>
                {claim.decision?.needs_approval === false &&
                  " — needed nobody: under the deferral threshold"}
              </>
            ) : (
              <span className={`state ${state === "lapsed" ? "lapsed" : "open"}`}>{state}</span>
            )}
          </span>
        </div>
      </div>

      <ReasonEditor
        claimId={id}
        reasoning={claim.reasoning ?? ""}
        state={state}
        approved={state === "approved"}
        about={about}
        undisclosed={undisclosed}
        onDone={onRevised}
        spaced
      />
      {/* Where this is being worked on or argued about outside here.
          Anybody who may argue about the claim may set it: a link is a note
          about where the conversation is rather than a judgment, and needing a
          second person for it would leave it unset. */}
      <p className="hint" style={{ margin: "8px 0 0" }}>
        {summary?.elsewhere ? (
          <>
            Being worked on at{" "}
            {/* Judged before it is somewhere to click, like every other
                address that was somebody's text. */}
            <Outward href={summary.elsewhere} />
            {". "}
          </>
        ) : (
          "Nothing here says where this is being worked on. "
        )}
        <button
          type="button"
          className="linkish"
          onClick={() => {
            const where = window.prompt(
              "Where is this being worked on? A ticket, a thread, a change.",
              summary?.elsewhere ?? "",
            );
            if (where !== null) point.mutate(where.trim());
          }}
        >
          {summary?.elsewhere ? "Change it" : "Link it"}
        </button>
        {point.error != null && <Failed error={point.error} what="That could not be recorded." />}
      </p>
    </div>
  );
}

type Event = { when: string; who: string; what: string; earlier?: boolean };

// One timeline: what happened to the claim that stands, and what happened at
// this place before it.
export function Activity({
  claimId,
  claim,
  places,
  previous,
}: {
  claimId: number;
  claim: Detail;
  places?: number;
  previous: Previous[];
}) {
  const approvals = useQuery({
    queryKey: ["claim", claimId, "approvals"],
    queryFn: async () =>
      unwrap(await api.GET("/v1/claims/{id}/approvals", { params: { path: { id: claimId } } })),
  });
  const revisions = useQuery({
    queryKey: ["claim", claimId, "revisions"],
    queryFn: async () =>
      unwrap(await api.GET("/v1/claims/{id}/revisions", { params: { path: { id: claimId } } })),
  });
  const comments = useQuery({
    queryKey: ["comments", claimId],
    queryFn: async () =>
      unwrap(await api.GET("/v1/claims/{id}/comments", { params: { path: { id: claimId } } })),
  });

  const now: Event[] = [];
  now.push({
    when: claim.proposed_at ?? "",
    who: claim.proposed_by ?? "",
    what: `proposed #${claimId} — ${labeled(claim.decision?.outcome ?? "")} · ${places ?? claim.decision?.places ?? 1} ${(places ?? claim.decision?.places ?? 1) === 1 ? "place" : "places"}`,
  });
  for (const r of revisions.data?.items ?? []) {
    if ((r.ordinal ?? 1) > 1)
      now.push({
        when: r.written_at ?? "",
        who: r.written_by ?? "",
        what: `revised the reasoning (revision ${r.ordinal})`,
      });
  }
  for (const a of approvals.data?.items ?? []) {
    now.push({
      when: a.approved_at ?? "",
      who: a.approved_by ?? "",
      what: a.carried_from
        ? `agreement carried forward onto revision ${a.revision_id}`
        : `approved revision ${a.revision_id}${a.batch ? ` (batch ${a.batch})` : ""}`,
    });
    if (a.withdrawn_at)
      now.push({ when: a.withdrawn_at, who: a.approved_by ?? "", what: "approval withdrawn" });
  }
  for (const c of comments.data?.items ?? []) {
    now.push({ when: c.written_at ?? "", who: c.written_by ?? "", what: "commented" });
  }
  if (claim.decision?.sent_back_at)
    now.push({
      when: claim.decision.sent_back_at,
      who: "",
      what: "rejected — returned for revision",
    });
  now.sort((a, b) => b.when.localeCompare(a.when));

  const earlier: Event[] = previous.map((p) => ({
    when: p.proposedAt,
    who: p.proposedBy,
    what: `proposed #${p.id} — ${labeled(p.outcome)}${p.state ? ` · ${p.state}` : ""}`,
    earlier: true,
  }));
  earlier.sort((a, b) => b.when.localeCompare(a.when));

  const line = (e: Event, i: number) => (
    <li key={`${e.when} ${e.what} ${i}`}>
      <span className="when">{e.when.replace("T", " ").slice(0, 16) || "—"}</span>
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
        <Failed error={unread.error} what="Part of this claim's history could not be read." />
      )}
      <ul className="timeline">{now.map(line)}</ul>
      {earlier.length > 0 && (
        <>
          <p className="eyebrow" style={{ margin: "12px 0 6px" }}>
            Earlier at this place
          </p>
          <ul className="timeline earlier">{earlier.map(line)}</ul>
        </>
      )}
    </div>
  );
}

// Every revision is kept. An approval names the revision it was given for,
// and revising withdraws it.
export function Revisions({ claimId }: { claimId: number }) {
  const revisions = useQuery({
    queryKey: ["claim", claimId, "revisions"],
    queryFn: async () =>
      unwrap(await api.GET("/v1/claims/{id}/revisions", { params: { path: { id: claimId } } })),
  });
  const approvals = useQuery({
    queryKey: ["claim", claimId, "approvals"],
    queryFn: async () =>
      unwrap(await api.GET("/v1/claims/{id}/approvals", { params: { path: { id: claimId } } })),
  });
  const items = revisions.data?.items ?? [];
  if (items.length === 0) return null;
  const agreed = new Map<number, { by: string; at: string; withdrawn: boolean }>();
  for (const a of approvals.data?.items ?? []) {
    if (a.revision_id)
      agreed.set(a.revision_id, {
        by: a.approved_by ?? "",
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
                {r.written_at?.replace("T", " ").slice(0, 16)} · {r.written_by}
              </span>
              <div>
                <div className="tagline">
                  {a ? (
                    <span className={a.withdrawn ? "state open" : "state agreed"}>
                      {a.withdrawn ? "Approval withdrawn" : "Approved"} by {a.by}
                      {a.at && <>, {on(a.at)}</>}
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
  claimId,
  mine,
  about,
  undisclosed,
}: {
  claimId: number;
  mine: (who: string) => boolean;
  // The issue a file would be attached to. Comments are written about one, so
  // the control can say what it is attaching to rather than guessing.
  about: { product: string; vulnerability: string };
  // Whether what is being discussed has been announced, which is what decides
  // who may be offered after an @: naming somebody who cannot open the finding
  // calls them to something they will be refused, and on an undisclosed one
  // the mention itself says a finding exists.
  undisclosed?: boolean;
}) {
  const comment = useComment();
  const comments = useQuery({
    queryKey: ["comments", claimId],
    queryFn: async () =>
      unwrap(await api.GET("/v1/claims/{id}/comments", { params: { path: { id: claimId } } })),
  });

  return (
    <div className="card">
      <h3>Comments</h3>
      <Thread
        items={comments.data?.items ?? []}
        mine={mine}
        about={about}
        undisclosed={undisclosed}
        word="Comment"
        consequence="Does not affect the approval"
        placeholder="A question, a note, something worth knowing later."
        draftKey={`comment:${claimId}`}
        notNotified={comment.data?.not_notified ?? []}
        // A failed read drew an empty thread with a live composer above it, so
        // a claim waiting on a second approver read as one nobody had objected
        // to. The note thread one file over already said this; this is the
        // half the extraction left behind.
        unread={
          comments.isError && !notYours(comments.error) ? (
            <Failed error={comments.error} what="The comments on this claim could not be read." />
          ) : null
        }
        adding={comment}
        onAdd={(body, done) => comment.mutate({ id: claimId, body }, { onSuccess: done })}
        edit={(piece, done) => (
          <Edit
            id={piece.id ?? 0}
            was={piece.body ?? ""}
            about={about}
            undisclosed={undisclosed}
            onDone={done}
          />
        )}
        history={useCommentHistory}
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

// Rewriting a comment in place.
//
// Only its author can, which the server enforces; the button is offered only
// to them so that nobody is invited into a refusal. What it said before is
// kept and readable behind the "edited" mark.
//
// No draft is saved. A draft exists so a half-written thought survives a
// sign-out; this one starts as text that is already stored, so keeping a copy
// of it would offer somebody their own comment back as an unsent draft.
export function Edit({
  id,
  was,
  onDone,
  about,
  undisclosed,
}: {
  id: number;
  was: string;
  onDone: () => void;
  about: { product: string; vulnerability: string };
  undisclosed?: boolean;
}) {
  const [text, setText] = useState(was);
  const edit = useEditComment();
  return (
    <div className="field" style={{ margin: 0, maxWidth: "78ch" }}>
      <Editor
        value={text}
        onChange={setText}
        rows={4}
        label="Comment"
        attachTo={about}
        mentions={mentioning(about.product, undisclosed)}
      />
      {edit.error != null && <Failed error={edit.error} what="That could not be changed." />}
      <div className="actions">
        <button
          type="button"
          className="btn"
          disabled={!text.trim() || text === was || edit.isPending}
          onClick={() => edit.mutate({ id, body: text }, { onSuccess: onDone })}
        >
          Save
        </button>
        <button type="button" className="btn quiet" onClick={onDone}>
          Cancel
        </button>
      </div>
    </div>
  );
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
  at: { product: string; stream: string; variant: string; vulnerability: string };
  undecided: boolean;
  onReuse: (reasoning: string, outcome: string, justification: string) => void;
}) {
  return (
    <div className="card">
      <h3>Previous decisions at this place</h3>
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

export function Prior({
  item,
  at,
  undecided,
  onReuse,
}: {
  item: Previous;
  at: { product: string; stream: string; variant: string; vulnerability: string };
  undecided: boolean;
  onReuse: (reasoning: string, outcome: string, justification: string) => void;
}) {
  const queries = useQueryClient();
  const [note, setNote] = useState("");
  const [asking, setAsking] = useState(false);
  const reaffirm = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/findings/{vulnerability}/places/{place}/decision/reaffirmation",
          {
            params: { path: { ...at, place: item.place } },
            body: { previous: item.id, reasoning: `${item.reasoning}\n\n${note}`.trim() },
          },
        ),
      ),
    onSuccess: () => {
      setAsking(false);
      void queries.invalidateQueries({ queryKey: ["finding"] });
      void queries.invalidateQueries({ queryKey: ["decided"] });
      void queries.invalidateQueries({ queryKey: ["queue"] });
    },
  });
  const lapsed = item.state === "lapsed";

  return (
    <article className="prior">
      <header>
        <span className="id">#{item.id}</span> <b>{labeled(item.outcome)}</b>
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
        {lapsed && undecided && item.place && !asking && (
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
              No approval needed: same justification, severity unchanged
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
        <Link to={`/decisions/${item.id}`} className="linkish">
          Open #{item.id} →
        </Link>
      </div>
    </article>
  );
}

export const RATINGS = FLOORS;
