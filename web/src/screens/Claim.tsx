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
import { linkable } from "../ui/addressable";
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
import { useWho } from "../app/session";
import type { Who } from "../app/session";

// How a product's two spellings are compared: a name people type is matched
// without regard to capitals, which is the rule the server applies to the
// identifier and the displayed name alike.
function same(name?: string): string {
  return (name ?? "").toLowerCase();
}

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

  const mine = it.claim.proposed_by === who.identity || it.claim.proposed_by === who.name;
  // What a file is attached to. Both halves have to be known: the issue says
  // which, and the product says whose, because the same identifier in two
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
          <b>{it.claim.proposed_by}</b>
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
      <Answer claim={it} mine={mine} onAnswered={again} />
      <HoldBack claim={it} mine={mine} onHeld={again} />
      <Revisions claimId={id} />
      <Comments
        claimId={id}
        mine={(wrote) => wrote === who.identity || wrote === who.name}
        about={about}
      />
    </>
  );
}

// What the claim says, where it lands, and what it covers now.
function Argument({ claim, id, onChanged }: { claim: Claimed; id: number; onChanged: () => void }) {
  const bulk = claim.issues > 1;
  return (
    <div className={`card standing ${stripe(claim.happened)}`}>
      <header className="dhead">
        <h3>What was decided</h3>
        <Happened word={claim.happened} by={claim.by} />
      </header>
      {claim.happened === "sent-back" && (
        <div className="alert" style={{ marginBottom: 12 }}>
          <strong>Sent back{claim.when && <> on {on(claim.when)}</>}</strong>
          <span>
            Back with whoever wrote it, and out of the review queue until it is revised. The reason
            given is in the comments.
          </span>
        </div>
      )}
      {claim.previously_approved && (
        <p className="hint" style={{ margin: "0 0 10px" }}>
          Agreed to before and back again — revised under the approval, or the code moved. Whoever
          reads it next is re-reading rather than meeting it.
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
          <span className="l">What it covers now</span>
          <span className="v" title={`${claim.places} written at, ${claim.findings} findings`}>
            {bulk ? (
              <>
                {claim.issues} issues · {claim.folds} {claim.folds === 1 ? "fold" : "folds"}
              </>
            ) : (
              <b>one judgment</b>
            )}
            {claim.packages > 0 && (
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
            <span className="hint">
              rows set aside from a larger claim, carrying the argument they were made under
            </span>
          )}
          {claim.claim.selected_by && (
            <span className="hint">narrowed by: {claim.claim.selected_by}</span>
          )}
        </div>
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
            to={
              `/products/${encodeURIComponent(claim.finding.product)}` +
              `/streams/${encodeURIComponent(claim.finding.stream)}` +
              `/variants/${encodeURIComponent(claim.finding.variant)}` +
              `/findings/${encodeURIComponent(claim.finding.vulnerability)}` +
              `/components/${encodeURIComponent(claim.finding.component)}` +
              (claim.finding.version ? `?version=${encodeURIComponent(claim.finding.version)}` : "")
            }
          >
            Open the finding →
          </Link>
        </p>
      )}
      <Elsewhere id={id} where={claim.claim.elsewhere ?? ""} onSet={onChanged} />
    </div>
  );
}

// Where this is being argued about or worked on outside here.
//
// Anybody who may argue about the claim may set it: a link is a note about
// where the conversation is rather than a judgment, and needing a second
// person for it would leave it unset. Nothing is ever fetched from it.
function Elsewhere({ id, where, onSet }: { id: number; where: string; onSet: () => void }) {
  const point = useMutation({
    mutationFn: async (to: string) =>
      unwrap(
        await api.PUT("/v1/claims/{id}/elsewhere", {
          params: { path: { id } },
          body: { elsewhere: to },
        }),
      ),
    onSuccess: onSet,
  });

  return (
    <p className="hint" style={{ margin: "10px 0 0" }}>
      {where ? (
        <>
          Being worked on at{" "}
          {/* Typed here rather than supplied by a scanner, and still a string
              that becomes somewhere to click — so it is judged the same way a
              scanner's reference is. What fails is shown and not linked. */}
          {linkable(where) ? (
            <a
              href={linkable(where)!}
              target="_blank"
              rel="noreferrer noopener"
              className="linkish"
            >
              {where}
            </a>
          ) : (
            <span className="id">{where}</span>
          )}
          {". "}
        </>
      ) : (
        "Nothing here says where this is being worked on. "
      )}
      <button
        type="button"
        className="linkish"
        onClick={() => {
          const to = window.prompt(
            "Where is this being worked on? A ticket, a thread, a change. Nothing is ever sent to it.",
            where,
          );
          if (to !== null) point.mutate(to.trim());
        }}
      >
        {where ? "Change it" : "Link it"}
      </button>
      {point.error != null && <Failed error={point.error} what="That could not be recorded." />}
    </p>
  );
}

// The reasoning as it stands, and the two acts anybody who may argue about it
// has.
//
// **Not the author's alone.** The server asks whether the subject may decide
// about each row of the claim and nothing about who wrote it, which is what
// the act-and-needs table says: propose, revise and withdraw all ask for
// triage on the product at the finding's visibility. Gated on authorship
// here, a triager reading a colleague's stale claim had no way to revise or
// withdraw it on this screen and every way to do it from the finding — the
// same person, the same claim, two answers.
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
  const standing = live(claim.happened) || claim.happened === "approved";

  // The card names the screen so the reasoning block is styled as something
  // read rather than as the editor it toggles into on the finding.
  return (
    <div className="card claim">
      <h3>Reasoning</h3>
      <ReasonEditor
        claimId={id}
        reasoning={claim.argument.reasoning}
        offered={standing}
        approved={claim.happened === "approved"}
        about={about}
        onDone={onChanged}
      />
    </div>
  );
}

// What a second person may do about this claim.
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

  // The claim names its product the way a person reads it, and what somebody
  // reaches is keyed on the identifier — so the two are compared the way the
  // server compares a name somebody typed: on either spelling, ignoring
  // capitals. Comparing the identifier against the displayed name drew this
  // panel for nobody.
  const named = same(claim.place.product);
  const mayAgree = (who.data?.reach ?? []).some(
    (each) => (same(each.product) === named || same(each.name) === named) && each.may_agree,
  );
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
            Agreeing puts this in force everywhere it reaches. Sending it back returns it to whoever
            wrote it, out of the queue until they revise it.
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
            placeholder="What you need before you would agree."
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
// The same signals an approver is shown, for the same reason — whoever wrote a
// bulk claim faces the same choice, and had nothing to choose with.
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
        Hold them back and they become a claim of yours, with the argument they were made under.
        Revise it to say what is different about them.
      </p>
      <div className="tablewrap" style={{ boxShadow: "none" }}>
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
            {rows.map((one) => (
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
                  <span className="id">{one.vulnerability}</span> <Exploited when={one.exploited} />
                </td>
                <td className="hint">{(one.why ?? []).join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {holding.size > 0 && (
        <div style={{ marginTop: 10 }}>
          {split.error != null && (
            <Failed error={split.error} what="Those rows could not be held back." />
          )}
          <Editor value={because} onChange={setBecause} label="Why these are different" rows={2} />
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
              Hold {holding.size} back
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
