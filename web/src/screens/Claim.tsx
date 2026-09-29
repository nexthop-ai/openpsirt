// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// One claim, whole, and every act at that grain.
//
// A claim is one argument however many decisions it wrote, so this is the page
// the acts live on: revise, withdraw, comment, agree, send back, hold rows
// back, and say where the work is happening. Nothing here offers an act on one
// row, and nothing here counts places — a place is a unit nobody acted in.

import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Body } from "../api/client";
import { unwrap } from "../api/queries";
import { Elsewhere } from "../ui/Elsewhere";
import { useApproveClaim, useRejectClaim, useSplitClaim } from "../api/claims";
import { Comments, Revisions } from "./FindingClaim";
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
import { allFindingsAt, claimAt, findingAt } from "../app/routes";
import { issuesIn, toggled } from "./outliers";
import { OutlierRows } from "../ui/OutlierRows";

// The stripe down the card, which says the claim's state before anybody reads
// a word of it. Three colors and no fourth: waiting, in force, and finished
// with — the same three the finding screen draws.
function stripe(happened?: string): string {
  if (happened === "approved") return "approved";
  if (happened === "withdrawn" || happened === "lapsed") return "lapsed";
  return "pending";
}

// One claim as the server answers it.
type Claimed = Body<"ClaimDetail">;

// The three words the claim is still being argued in. Everything else has
// finished with it, and offering an act on a finished claim is offering a
// refusal.
function live(happened?: string): boolean {
  return happened === "waiting" || happened === "sent-back" || happened === "undone";
}

export function Claim({ who }: { who: Who }) {
  const { id: raw = "" } = useParams();
  const id = Number(raw);
  const queries = useQueryClient();

  const claim = useQuery({
    queryKey: ["claim", id],
    queryFn: async () => unwrap(await api.GET("/v1/claims/{id}", { params: { path: { id } } })),
  });

  if (claim.isPending) return <Loading />;
  if (claim.isError) return <Failed error={claim.error} what="That claim could not be read." />;
  const it = claim.data;
  if (!it) return null;

  // The identity alone. A claim records who proposed it by the name they sign
  // in under, and matching a display name as well made ownership turn on a
  // label anybody can be given — which hid the Agree panel from somebody
  // entitled to approve and showed Hold back to somebody who did not propose.
  const mine = it.claim.proposed_by === who.identity;
  // The thing a file is attached to. Both halves have to be known: the issue
  // says which, and the product says whose, because the same identifier in two
  // products is two pieces of work with two sets of readers.
  const about = { product: it.place.product, vulnerability: it.place.vulnerability };
  const again = () => void queries.invalidateQueries({ queryKey: ["claim", id] });

  return (
    <>
      <div className="screen-head">
        {/* A claim over many issues is named by what it is about — the
            component — because heading it with one of the twelve reads as a
            claim about that one. */}
        <h2>
          <span className="id">
            {it.issues > 1
              ? (it.finding?.component ?? it.place.vulnerability)
              : it.place.vulnerability}
          </span>{" "}
          · {labeled(it.argument.outcome)}{" "}
          {it.issues > 1 && <span className="n">{it.issues} issues</span>}
        </h2>
        <p className="hint">
          Claim <span className="id">#{it.claim.id}</span> · proposed by{" "}
          <b>{it.claim.proposed_by_name || it.claim.proposed_by}</b>
          {it.claim.proposed_at && <> on {on(it.claim.proposed_at)}</>}
          {it.age_days > 365 && (
            <>
              {" "}
              ·{" "}
              <span style={{ color: "var(--sev-medium)" }}>
                a judgment this old is worth re-reading
              </span>
            </>
          )}
        </p>
      </div>

      <Argument claim={it} id={id} onChanged={again} />
      <Reasoning claim={it} about={about} onChanged={again} />
      <Reaffirm claim={it} id={id} mine={mine} onDone={again} />
      <Answer claim={it} mine={mine} onAnswered={again} />
      <HoldBack claim={it} mine={mine} onHeld={again} />
      <Revisions claimId={id} />
      <Comments
        claimId={id}
        mine={(wrote) => wrote === who.identity}
        about={about}
        undisclosed={!!it.undisclosed}
      />
    </>
  );
}

// The claim's argument, its landing place, and its present reach.
function Argument({ claim, id, onChanged }: { claim: Claimed; id: number; onChanged: () => void }) {
  const bulk = claim.issues > 1;
  return (
    <div className={`card standing ${stripe(claim.happened)}`}>
      <header className="dhead">
        <h3>The decision</h3>
        <Happened word={claim.happened} by={claim.by_name || claim.by} />
      </header>
      {claim.happened === "sent-back" && (
        <div className="alert" style={{ marginBottom: 12 }}>
          <strong>Sent back{claim.when && <> on {on(claim.when)}</>}</strong>
          <span>
            Returned to the author, out of the queue until revised. The reason is in the comments.
          </span>
        </div>
      )}
      {claim.previously_approved && (
        <p className="hint" style={{ margin: "0 0 10px" }}>
          Agreed to before: revised under the approval, or the code moved.
        </p>
      )}
      <div className="dgrid">
        <div>
          <span className="l">Outcome</span>
          <span className="v">
            {labeled(claim.argument.outcome)}
            {claim.argument.deferred_until && <> until {claim.argument.deferred_until}</>}
            {claim.argument.committed_to && <> by {claim.argument.committed_to}</>}
          </span>
        </div>
        {claim.argument.justification && (
          <div>
            <span className="l">Justification</span>
            <span className="v">
              <Because code={claim.argument.justification} />
            </span>
            {claim.argument.mitigation && (
              <span className="hint">stopped by: {claim.argument.mitigation}</span>
            )}
          </div>
        )}
        {claim.argument.fixed_version && (
          <div>
            <span className="l">Fixed in</span>
            <span className="v mono">{claim.argument.fixed_version}</span>
            <span className="hint">as the packager states it; not compared against what ships</span>
          </div>
        )}
        {claim.argument.upgrade_to && (
          <div>
            <span className="l">Upgrade to</span>
            <span className="v mono">{claim.argument.upgrade_to}</span>
          </div>
        )}
        <div>
          {/* In the units somebody acted in. One judgment at one fold, over
              the binaries that fold holds and the things that pull them in —
              never a place count, which is a unit nobody acts in and a reader
              cannot reconcile with anything else on the screen. */}
          <span className="l">Present reach</span>
          <span className="v" title={`${claim.places} written at, ${claim.findings} findings`}>
            {claim.findings === 0 ? (
              <b>none</b>
            ) : bulk ? (
              <>
                {claim.issues} issues · {claim.folds} {claim.folds === 1 ? "fold" : "folds"}
              </>
            ) : (
              <b>one judgment</b>
            )}
            {claim.findings > 0 && claim.packages > 0 && (
              <>
                {" · "}
                {claim.packages} {claim.packages === 1 ? "package" : "packages"} · {claim.consumers}{" "}
                {claim.consumers === 1 ? "consumer" : "consumers"}
              </>
            )}
          </span>
          {(claim.builds ?? []).length > 0 && (
            <span className="hint">in {(claim.builds ?? []).join(", ")}</span>
          )}
          {claim.claim.kind === "extension" && (
            <span className="hint">extends an approved claim</span>
          )}
          {claim.claim.kind === "returned" && (
            <span className="hint">rows set aside from a larger claim</span>
          )}
          {claim.claim.selected_by && (
            <span className="hint">narrowed by: {claim.claim.selected_by}</span>
          )}
          {/* The same question answered by something the approver can check.
              A sentence cannot be re-run: "drivers this image does not build"
              over a set chosen by ticking everything reads the same as an
              honest claim. Equal counts mean the claim is exactly what the
              narrowing returns. */}
          {claim.claim.selection && (
            <span
              className="hint"
              title="Re-run when the claim was written, not taken from whoever made it"
            >
              {claim.claim.selection.contains
                ? `contains "${claim.claim.selection.contains}" reaches `
                : "no narrowing, which reaches "}
              {claim.claim.selection.matched.toLocaleString()} · claimed about{" "}
              {claim.claim.selection.named.toLocaleString()}
            </span>
          )}
        </div>
        {(claim.ended ?? []).map((part) => (
          <Ended key={part.state} claimId={claim.claim.id} part={part} />
        ))}
      </div>
      {claim.finding && (
        <p className="hint" style={{ margin: "10px 0 0" }}>
          {claim.finding.severity && <Severity word={claim.finding.severity} />}{" "}
          <Exploited when={claim.finding.exploited} /> in{" "}
          <span className="id">{claim.finding.component}</span>{" "}
          {claim.finding.version && <span className="id">{claim.finding.version}</span>}
          {" · "}
          <Link
            className="linkish"
            to={findingAt(
              {
                product: claim.finding.product,
                stream: claim.finding.stream,
                variant: claim.finding.variant,
              },
              {
                vulnerability: claim.finding.vulnerability,
                component: claim.finding.component,
                version: claim.finding.version ?? "",
                ecosystem: claim.finding.ecosystem,
                namespace: claim.finding.namespace,
              },
            )}
          >
            Open the finding →
          </Link>
        </p>
      )}
      <Elsewhere id={id} where={claim.claim.elsewhere ?? ""} onSet={onChanged} />
    </div>
  );
}

// What the rows that stopped one way reached when they stopped, beside the
// present reach rather than in it. Counted in places, because that is what a
// row is keyed on. The link opens what sits at those places now, across every
// release, since the list's own defaults would hide a tag or an ended branch
// the claim covered.
function Ended({ claimId, part }: { claimId: number; part: Body<"EndedReachBody"> }) {
  const builds = part.builds ?? [];
  const query = new URLSearchParams([
    ["claim", String(claimId)],
    ["claim_state", part.state],
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
        {part.places} {part.places === 1 ? "place" : "places"} · {builds.length}{" "}
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

// Re-making everything one action claimed, after the code moved under it.
//
// Offered on the claim rather than on each row, because that is the unit the
// judgment was made at: a team answering one kernel issue writes a decision at
// each of its places in one action, and restoring them one at a time is that
// many separately typed justifications for one argument.
//
// The claimant's, and nobody else's. An approver doing this would become the
// proposer of the new claim while their own earlier agreement is carried onto
// it, which is one person on both sides of the control.
function Reaffirm({
  claim,
  id,
  mine,
  onDone,
}: {
  claim: Claimed;
  id: number;
  mine: boolean;
  onDone: () => void;
}) {
  const [reasoning, setReasoning] = useState("");
  const [waiting, setWaiting] = useState<boolean | null>(null);
  // The claim the act re-made, which is where the decision now stands.
  const [remade, setRemade] = useState(0);
  const again = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/claims/{id}/reaffirmation", {
          params: { path: { id } },
          body: { reasoning: reasoning.trim() },
        }),
      ),
    onSuccess: (made) => {
      setWaiting(!!made?.waiting);
      setRemade(made?.claim_id ?? 0);
      setReasoning("");
      onDone();
    },
  });

  // The answer outlives the card: once re-made, this claim is no longer one
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
            <Link to={claimAt(remade)} className="linkish">
              Open the re-made claim →
            </Link>
          )}
        </span>
      </div>
    );
  }
  if (!mine || !claim.reaffirmable) return null;
  return (
    <div className="card">
      <header className="dhead">
        <h3>Re-affirm</h3>
      </header>
      <p className="reading" style={{ marginTop: 0 }}>
        It lapsed. Reaffirming re-makes every place at today's versions.
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
          Re-affirm all {claim.places > 1 ? `${claim.places} places` : ""}
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
// about each row of the claim and nothing about who wrote it, which is what
// the act-and-needs table says: propose, revise and withdraw all ask for
// triage on the product at the finding's visibility. Gated on authorship,
// this screen would refuse a triager what the finding allows them: the same
// person, the same claim, two answers.
//
// Revising keeps the old words readable, takes back the approval given for
// them, and returns the claim to the queue. Withdrawing needs nobody.
function Reasoning({
  claim,
  about,
  onChanged,
}: {
  claim: Claimed;
  about: { product: string; vulnerability: string };
  onChanged: () => void;
}) {
  const id = claim.claim.id;
  // The card names the screen so the reasoning block is styled as something
  // read rather than as the editor it toggles into on the finding.
  return (
    <div className="card claim">
      <h3>Reasoning</h3>
      <ReasonEditor
        claimId={id}
        reasoning={claim.argument.reasoning}
        state={claim.happened ?? ""}
        approved={claim.happened === "approved"}
        about={about}
        undisclosed={!!claim.undisclosed}
        onDone={onChanged}
      />
    </div>
  );
}

// The acts a second person may perform on this claim.
//
// Absent for the proposer, whatever they hold: the control this rests on is
// that a second person agrees, and offering somebody a button that would
// refuse them is worse than offering nothing.
function Answer({
  claim,
  mine,
  onAnswered,
}: {
  claim: Claimed;
  mine: boolean;
  onAnswered: () => void;
}) {
  const who = useWho();
  const approve = useApproveClaim();
  const reject = useRejectClaim();
  const [asking, setAsking] = useState(false);
  const [because, setBecause] = useState("");

  // The claim names its product by the name that addresses it, which is what
  // somebody's reach is keyed on.
  const here = mayOf(who.data, claim.place.product ?? "");
  const mayAgree = !!(claim.undisclosed ? here?.agrees_private : here?.agrees_public);
  if (mine || !mayAgree || !live(claim.happened)) return null;
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
            onClick={() => approve.mutate({ id: claim.claim.id }, { onSuccess: onAnswered })}
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
          {/* A reason is required, because sending a claim back without one
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
                  { id: claim.claim.id, because },
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
// look like the rest, and they become a claim of their own carrying the
// argument they were made under.
//
// The same signals an approver is shown, for the same reason: whoever wrote a
// bulk claim faces the same choice.
function HoldBack({ claim, mine, onHeld }: { claim: Claimed; mine: boolean; onHeld: () => void }) {
  const split = useSplitClaim();
  const [holding, setHolding] = useState<Set<number>>(new Set());
  const [because, setBecause] = useState("");
  const rows = claim.outliers?.rows ?? [];
  if (!mine || !live(claim.happened) || rows.length === 0) return null;

  return (
    <div className="card">
      <header className="dhead">
        <h3>Rows that do not match the rest</h3>
        <span className="hint">
          {claim.outliers?.exploited ?? 0} exploited · {claim.outliers?.severe ?? 0} severe ·{" "}
          {claim.outliers?.fixable ?? 0} fixable · {claim.outliers?.unmatched ?? 0} off the term
        </span>
      </header>
      <p className="hint" style={{ margin: "0 0 10px" }}>
        Holding them back makes them a claim of yours. Revise it to say what differs.
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
                  { id: claim.claim.id, rows: [...holding], because },
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
