// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// One decision, whole, and every act at that grain.
//
// A decision is one argument however many occurrences it covers, so this is the page
// the acts live on: revise, withdraw, comment, agree, send back, hold rows
// back, and say where the work is happening. Nothing here offers an act on one
// row, and nothing here counts occurrences — an occurrence is a unit nobody acted in.

import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Body } from "../api/client";
import { unwrap } from "../api/queries";
import { Elsewhere } from "../ui/Elsewhere";
import {
  useAfterDecision,
  useApproveDecision,
  useRejectDecision,
  useSplitDecision,
} from "../api/decisions";
import { Comments, Revisions } from "./FindingDecision";
import { Happened } from "./QueueMine";
import { Editor } from "../ui/Editor";
import { ReasonEditor } from "../ui/ReasonEditor";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Because, labeled } from "../ui/Outcome";
import { Exploited, Severity } from "../ui/Severity";
import { on } from "../ui/when";
import { mayOf, useWho } from "../app/session";
import type { Who } from "../app/session";
import { allFindingsAt, decisionAt, findingOf } from "../app/routes";
import { issuesIn, toggled } from "./outliers";
import { stripeOf } from "../ui/stripe";
import { OutlierRows } from "../ui/OutlierRows";

// One decision as the server answers it.
type Detail = Body<"DecisionDetail">;

// The three words the decision is still being argued in. Everything else has
// finished with it, and offering an act on a finished decision is offering a
// refusal.
function live(happened?: string): boolean {
  return happened === "waiting" || happened === "sent-back" || happened === "undone";
}

export function Decision({ who }: { who: Who }) {
  const { id: raw = "" } = useParams();
  const id = Number(raw);
  const queries = useQueryClient();

  const decision = useQuery({
    queryKey: ["decision", id],
    queryFn: async () => unwrap(await api.GET("/v1/decisions/{id}", { params: { path: { id } } })),
  });

  if (decision.isPending) return <Loading />;
  if (decision.isError)
    return <Failed error={decision.error} what="That decision could not be read." />;
  const it = decision.data;
  if (!it) return null;

  // The identity alone. A decision records who proposed it by the name they sign
  // in under, and matching a display name as well made ownership turn on a
  // label anybody can be given — which hid the Agree panel from somebody
  // entitled to approve and showed Hold back to somebody who did not propose.
  const mine = it.decision.proposed_by === who.identity;
  // The thing a file is attached to. Both halves have to be known: the issue
  // says which, and the product says whose, because the same identifier in two
  // products is two pieces of work with two sets of readers.
  const about = { product: it.occurrence.product, vulnerability: it.occurrence.vulnerability };
  const again = () => void queries.invalidateQueries({ queryKey: ["decision", id] });
  // Reading a decision about internal material is not arguing it: the flaw's
  // readers read an included code finding's decisions and take no part in them. A comment
  // takes triage or approval there, and a link, a revision and a withdrawal
  // take triage.
  const here = mayOf(who, it.occurrence.product ?? "");
  const comments = !it.internal || !!(here?.triages_internal || here?.agrees_internal);
  const links = !it.internal || !!here?.triages_internal;

  return (
    <>
      <div className="screen-head">
        {/* A decision over many issues is named by what it is about — the
            component — because heading it with one of the twelve reads as a
            decision about that one. */}
        <h2>
          <span className="id">
            {it.issues > 1
              ? (it.finding?.component ?? it.occurrence.vulnerability)
              : it.occurrence.vulnerability}
          </span>{" "}
          · {labeled(it.argument.outcome)}{" "}
          {it.issues > 1 && <span className="n">{it.issues} issues</span>}
        </h2>
        <p className="hint">
          Decision <span className="id">#{it.decision.id}</span> · proposed by{" "}
          <b>{it.decision.proposed_by_name || it.decision.proposed_by}</b>
          {it.decision.proposed_at && <> on {on(it.decision.proposed_at)}</>}
          {it.age_days > 365 && (
            <>
              {" "}
              ·{" "}
              <span style={{ color: "var(--sev-medium)" }}>
                a decision this old is worth re-reading
              </span>
            </>
          )}
        </p>
      </div>

      <Argument decision={it} id={id} links={links} onChanged={again} />
      <Reasoning decision={it} about={about} onChanged={again} writes={links} />
      <Reaffirm decision={it} id={id} mine={mine} />
      <Answer decision={it} mine={mine} onAnswered={again} />
      <HoldBack decision={it} mine={mine} onHeld={again} />
      <Revisions decisionId={id} />
      <Comments
        decisionId={id}
        mine={(wrote) => wrote === who.identity}
        about={about}
        undisclosed={!!it.undisclosed}
        internal={!!it.internal}
        writes={comments}
      />
    </>
  );
}

// The decision's argument, where the work on it happens, and its present reach.
function Argument({
  decision,
  id,
  links,
  onChanged,
}: {
  decision: Detail;
  id: number;
  links: boolean;
  onChanged: () => void;
}) {
  const bulk = decision.issues > 1;
  return (
    <div
      className={`card standing ${stripeOf(decision.happened, !!decision.argument.needs_approval)}`}
    >
      <header className="dhead">
        <h3>The decision</h3>
        <Happened word={decision.happened} by={decision.by_name || decision.by} />
      </header>
      {decision.happened === "sent-back" && (
        <div className="alert" style={{ marginBottom: 12 }}>
          <strong>Sent back{decision.when && <> on {on(decision.when)}</>}</strong>
          <span>
            Returned to the author, out of the queue until revised. The reason is in the comments.
          </span>
        </div>
      )}
      {decision.previously_approved && (
        <p className="hint" style={{ margin: "0 0 10px" }}>
          Agreed to before: revised under the approval, or the code moved.
        </p>
      )}
      <div className="dgrid">
        <div>
          <span className="l">Outcome</span>
          <span className="v">
            {labeled(decision.argument.outcome)}
            {decision.argument.deferred_until && <> until {decision.argument.deferred_until}</>}
            {decision.argument.committed_to && <> by {decision.argument.committed_to}</>}
          </span>
        </div>
        {decision.argument.justification && (
          <div>
            <span className="l">Justification</span>
            <span className="v">
              <Because code={decision.argument.justification} />
            </span>
            {decision.argument.mitigation && (
              <span className="hint">stopped by: {decision.argument.mitigation}</span>
            )}
          </div>
        )}
        {decision.argument.holds_for && decision.argument.outcome !== "deferred" && (
          <div>
            <span className="l">Published as holding for</span>
            <span className="v">
              {decision.argument.holds_for === "portable"
                ? "anyone shipping this version"
                : "this build only"}
            </span>
            {!decision.argument.scope && <span className="hint">from the reason</span>}
          </div>
        )}
        {decision.argument.fixed_version && (
          <div>
            <span className="l">Fixed in</span>
            <span className="v mono">{decision.argument.fixed_version}</span>
            <span className="hint">as the packager states it; not compared against what ships</span>
          </div>
        )}
        {decision.argument.upgrade_to && (
          <div>
            <span className="l">Upgrade to</span>
            <span className="v mono">{decision.argument.upgrade_to}</span>
          </div>
        )}
        <div>
          {/* In the units somebody acted in. One decision at one fold, over
              the binaries that fold holds and the things that pull them in —
              never an occurrence count, which is a unit nobody acts in and a reader
              cannot reconcile with anything else on the screen. */}
          <span className="l">Present reach</span>
          <span
            className="v"
            title={`${decision.occurrences} written at, ${decision.findings} findings`}
          >
            {decision.findings === 0 ? (
              <b>none</b>
            ) : bulk ? (
              <>
                {decision.issues} issues · {decision.folds}{" "}
                {decision.folds === 1 ? "fold" : "folds"}
              </>
            ) : (
              <b>one decision</b>
            )}
            {decision.findings > 0 && decision.packages > 0 && (
              <>
                {" · "}
                {decision.packages} {decision.packages === 1 ? "package" : "packages"} ·{" "}
                {decision.consumers} {decision.consumers === 1 ? "consumer" : "consumers"}
              </>
            )}
          </span>
          {(decision.builds ?? []).length > 0 && (
            <span className="hint">in {(decision.builds ?? []).join(", ")}</span>
          )}
          {decision.decision.kind === "extension" && (
            <span className="hint">extends an approved decision</span>
          )}
          {decision.decision.kind === "returned" && (
            <span className="hint">rows set aside from a larger decision</span>
          )}
          {decision.decision.selected_by && (
            <span className="hint">narrowed by: {decision.decision.selected_by}</span>
          )}
          {/* The same question answered by something the approver can check.
              A sentence cannot be re-run: "drivers this image does not build"
              over a set chosen by ticking everything reads the same as an
              honest decision. Equal counts mean the decision is exactly what the
              narrowing returns. */}
          {decision.decision.selection && (
            <span
              className="hint"
              title="Re-run when the decision was written, not taken from whoever made it"
            >
              {decision.decision.selection.contains
                ? `contains "${decision.decision.selection.contains}" reaches `
                : "no narrowing, which reaches "}
              {decision.decision.selection.matched.toLocaleString()} · decided about{" "}
              {decision.decision.selection.named.toLocaleString()}
            </span>
          )}
        </div>
        {(decision.ended ?? []).map((part) => (
          <Ended key={part.state} decisionId={decision.decision.id} part={part} />
        ))}
      </div>
      {decision.finding && (
        <p className="hint" style={{ margin: "10px 0 0" }}>
          {decision.finding.severity && <Severity word={decision.finding.severity} />}{" "}
          <Exploited when={decision.finding.exploited} /> in{" "}
          <span className="id">{decision.finding.component}</span>{" "}
          {decision.finding.version && <span className="id">{decision.finding.version}</span>}
          {" · "}
          <Link className="linkish" to={findingOf(decision.finding)}>
            Open the finding →
          </Link>
        </p>
      )}
      <Elsewhere
        id={id}
        where={decision.decision.elsewhere ?? ""}
        onSet={onChanged}
        writes={links}
      />
    </div>
  );
}

// What the rows that stopped one way reached when they stopped, beside the
// present reach rather than in it. Counted in occurrences, because that is what a
// row is keyed on. The link opens what sits at those occurrences now, across every
// release, since the list's own defaults would hide a tag or an ended branch
// the decision covered.
function Ended({ decisionId, part }: { decisionId: number; part: Body<"EndedReachBody"> }) {
  const builds = part.builds ?? [];
  const query = new URLSearchParams([
    ["decision", String(decisionId)],
    ["decision_state", part.state],
    ["planned", "either"],
    ["on", "branch"],
    ["on", "tag"],
    ["support", "in-support"],
    ["support", "past-eol"],
  ]);
  return (
    <div>
      <span className="l">
        {part.state === "withdrawn" ? "Reach when withdrawn" : "Reach when it lapsed"}
      </span>
      <span className="v">
        {part.occurrences} {part.occurrences === 1 ? "occurrence" : "occurrences"} · {builds.length}{" "}
        {builds.length === 1 ? "build" : "builds"}
      </span>
      <span className="hint">
        {part.at && <>on {on(part.at)}</>}
        {builds.length > 0 && <> in {builds.join(", ")}</>}
      </span>
      <Link className="linkish" to={allFindingsAt(query)}>
        Findings there now →
      </Link>
    </div>
  );
}

// Re-making everything one action decided, after the code moved under it.
//
// Offered on the decision rather than on each row, because that is the unit the
// decision was made at: a team answering one kernel issue writes a row at each
// of its occurrences in one action, and restoring them one at a time is that
// many separately typed justifications for one argument.
//
// The proposer's, and nobody else's. An approver doing this would become the
// proposer of the new decision while their own earlier agreement is carried onto
// it, which is one person on both sides of the control.
function Reaffirm({ decision, id, mine }: { decision: Detail; id: number; mine: boolean }) {
  // The decision's own blocks are among what every act on a decision invalidates,
  // with the lists the re-made decision joins.
  const after = useAfterDecision();
  const [reasoning, setReasoning] = useState("");
  const [waiting, setWaiting] = useState<boolean | null>(null);
  // The decision the act re-made, which is where the decision now stands.
  const [remade, setRemade] = useState(0);
  const again = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/decisions/{id}/reaffirmation", {
          params: { path: { id } },
          body: { reasoning: reasoning.trim() },
        }),
      ),
    onSuccess: (made) => {
      setWaiting(!!made?.waiting);
      setRemade(made?.decision_id ?? 0);
      setReasoning("");
      after();
    },
  });

  // The answer outlives the card: once re-made, this decision is no longer one
  // to re-affirm, and the confirmation stays where the button was.
  if (waiting !== null) {
    return (
      <div className="alert info" role="status">
        <strong>Re-affirmed</strong>
        <span>
          {waiting
            ? "Waiting for a second person: it is rated worse now, or was never agreed. "
            : "Standing, with the earlier agreement carried onto it. "}
          {remade > 0 && (
            <Link to={decisionAt(remade)} className="linkish">
              Open the re-made decision →
            </Link>
          )}
        </span>
      </div>
    );
  }
  if (!mine || !decision.reaffirmable) return null;
  return (
    <div className="card">
      <header className="dhead">
        <h3>Re-affirm</h3>
      </header>
      <p className="reading" style={{ marginTop: 0 }}>
        It lapsed. Reaffirming re-makes every occurrence at today's versions.
      </p>
      <textarea
        rows={3}
        value={reasoning}
        placeholder="The reason it still holds, having checked again"
        onChange={(event) => setReasoning(event.target.value)}
      />
      <div className="actions" style={{ marginTop: 10 }}>
        <button
          type="button"
          className="btn"
          disabled={reasoning.trim() === "" || again.isPending}
          onClick={() => again.mutate()}
        >
          Re-affirm all {decision.occurrences > 1 ? `${decision.occurrences} occurrences` : ""}
        </button>
      </div>
      {again.isError && <Failed error={again.error} what="It could not be re-affirmed." />}
    </div>
  );
}

// The reasoning as it stands, and the two acts anybody who may argue about it
// has.
//
// Not the author's alone. The server asks whether the subject may decide
// about each row of the decision and nothing about who wrote it, which is what
// the act-and-needs table says: propose, revise and withdraw all ask for
// triage on the product at the finding's visibility. Gated on authorship,
// this screen would refuse a triager what the finding allows them: the same
// person, the same decision, two answers.
//
// Revising keeps the old words readable, takes back the approval given for
// them, and returns the decision to the queue. Withdrawing needs nobody.
function Reasoning({
  decision,
  about,
  onChanged,
  writes,
}: {
  decision: Detail;
  about: { product: string; vulnerability: string };
  onChanged: () => void;
  writes: boolean;
}) {
  const id = decision.decision.id;
  // The card names the screen so the reasoning block is styled as something
  // read rather than as the editor it toggles into on the finding.
  return (
    <div className="card decision">
      <h3>Reasoning</h3>
      <ReasonEditor
        decisionId={id}
        reasoning={decision.argument.reasoning}
        state={decision.happened ?? ""}
        approved={decision.happened === "approved"}
        about={about}
        undisclosed={!!decision.undisclosed}
        internal={!!decision.internal}
        onDone={onChanged}
        writes={writes}
      />
    </div>
  );
}

// The acts a second person may perform on this decision.
//
// Absent for the proposer, whatever they hold: the control this rests on is
// that a second person agrees, and offering somebody a button that would
// refuse them is worse than offering nothing.
function Answer({
  decision,
  mine,
  onAnswered,
}: {
  decision: Detail;
  mine: boolean;
  onAnswered: () => void;
}) {
  const who = useWho();
  const approve = useApproveDecision();
  const reject = useRejectDecision();
  const [asking, setAsking] = useState(false);
  const [because, setBecause] = useState("");

  // The decision names its product by the name that addresses it, which is what
  // somebody's reach is keyed on.
  const here = mayOf(who.data, decision.occurrence.product ?? "");
  // Asked at the decision's most careful row: a code finding decision is internal, and
  // agreeing there takes the approver capability.
  const mayAgree = !!(decision.internal
    ? here?.agrees_internal
    : decision.undisclosed
      ? here?.agrees_private
      : here?.agrees_public);
  if (mine || !mayAgree || !live(decision.happened)) return null;
  const busy = approve.isPending || reject.isPending;
  const failed = approve.error ?? reject.error;

  return (
    <div className="card">
      <h3>Your answer</h3>
      {failed != null && <Failed error={failed} what="That could not be recorded." />}
      {!asking ? (
        <div className="actions">
          <button
            type="button"
            className="btn"
            disabled={busy}
            onClick={() => approve.mutate({ id: decision.decision.id }, { onSuccess: onAnswered })}
          >
            {approve.isPending ? "Agreeing…" : "Agree"}
          </button>
          <button
            type="button"
            className="btn quiet"
            disabled={busy}
            onClick={() => setAsking(true)}
          >
            Send it back
          </button>
          <span className="consequence">
            Agreeing puts this in force everywhere it reaches. Sending it back returns it to the
            author.
          </span>
        </div>
      ) : (
        <>
          {/* A reason is required, because sending a decision back without one
              tells the author nothing they can act on and the round trip
              starts again. */}
          <Editor
            value={because}
            onChange={setBecause}
            placeholder="The evidence you need before you would agree."
          />
          <div className="actions" style={{ marginTop: 8 }}>
            <button
              type="button"
              className="btn"
              disabled={busy || because.trim() === ""}
              onClick={() =>
                reject.mutate(
                  { id: decision.decision.id, because },
                  {
                    onSuccess: () => {
                      setBecause("");
                      setAsking(false);
                      onAnswered();
                    },
                  },
                )
              }
            >
              {reject.isPending ? "Sending…" : "Send it back"}
            </button>
            <button type="button" className="linkish" onClick={() => setAsking(false)}>
              Cancel
            </button>
          </div>
        </>
      )}
    </div>
  );
}

// The proposer's side of setting rows aside: hold back the ones that do not
// look like the rest, and they become a decision of their own carrying the
// argument they were made under.
//
// The same signals an approver is shown, for the same reason: whoever wrote a
// bulk decision faces the same choice.
function HoldBack({
  decision,
  mine,
  onHeld,
}: {
  decision: Detail;
  mine: boolean;
  onHeld: () => void;
}) {
  const split = useSplitDecision();
  const [holding, setHolding] = useState<Set<number>>(new Set());
  const [because, setBecause] = useState("");
  const rows = decision.outliers?.rows ?? [];
  if (!mine || !live(decision.happened) || rows.length === 0) return null;

  return (
    <div className="card">
      <header className="dhead">
        <h3>Rows that do not match the rest</h3>
        <span className="hint">
          {(decision.outliers?.incidents ?? 0) > 0 &&
            `${decision.outliers?.incidents} with an incident · `}
          {decision.outliers?.exploited ?? 0} known exploited · {decision.outliers?.severe ?? 0}{" "}
          severe · {decision.outliers?.fixable ?? 0} fixable · {decision.outliers?.unmatched ?? 0}{" "}
          off the term
        </span>
      </header>
      <p className="hint" style={{ margin: "0 0 10px" }}>
        Holding them back makes them a decision of yours. Revise it to say what differs.
      </p>
      <OutlierRows
        rows={rows}
        holding={holding}
        onToggle={(one, on) => setHolding(toggled(holding, one, on))}
      />
      {holding.size > 0 && (
        <div style={{ marginTop: 10 }}>
          {split.error != null && (
            <Failed error={split.error} what="Those rows could not be held back." />
          )}
          <Editor
            value={because}
            onChange={setBecause}
            label="The reason these are different"
            rows={2}
          />
          <div className="actions" style={{ marginTop: 8 }}>
            <button
              type="button"
              className="btn"
              disabled={split.isPending || because.trim() === ""}
              onClick={() =>
                split.mutate(
                  { id: decision.decision.id, rows: [...holding], because },
                  {
                    onSuccess: () => {
                      setHolding(new Set());
                      setBecause("");
                      onHeld();
                    },
                  },
                )
              }
            >
              Hold {issuesIn(rows, holding)} back
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
