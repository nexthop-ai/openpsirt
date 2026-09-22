import { notACredential } from "../ui/noautofill";
import { WaitingRulings } from "./InboxRuling";
import { overCapNotice, useBulkCap } from "../ui/bulk";
import { useEffect, useState } from "react";
import { Loading } from "../ui/Loading";
import { Became } from "./QueueMine";
import { Embargoes, PENDING_PAGE, Ratings } from "./QueuePending";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { api, type Body } from "../api/client";
import { UNOWNED_LIST, usePaging } from "./list";
import { unwrap } from "../api/queries";
import { claimOf, useApproveClaim, useRejectClaim, type Claim } from "../api/claims";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Markdown } from "../ui/Markdown";
import { Editor, forget } from "../ui/Editor";
import { Severity, Exploited, ExploitedHere } from "../ui/Severity";
import { Paged } from "../ui/Paged";
import { Because, called, labeled } from "../ui/Outcome";
import { Wide } from "../ui/Wide";

// A page of claims. The queue is read at the grain of a claim, and a claim
// is a card with its whole argument, so a page is what fits a sitting.
const PAGE = 50;

// The review queue at the grain of a claim: one card per proposer's action,
// however many records it wrote. The approver reads one argument and its
// reach, and approving, rejecting and undoing all work at that size. A bulk
// claim carries its outliers; an extension says what it rests on. Lapsed
// decisions and deferrals that ran out sit underneath: nobody has to agree to
// those again, but each needs a fresh reason.
export function Queue() {
  const [params, setParams] = useSearchParams();
  const { offset, go } = usePaging();
  // A claim somebody was sent to, by a notice or a link. Found on the page
  // and shown, or said to be missing — a link that lands on the queue with
  // nothing marked leaves somebody hunting through cards for the one meant.
  const wanted = Number(params.get("claim") ?? 0);
  // The claim beside its key, not the key alone. A selection deliberately
  // survives paging — a row is selected by what it is rather than by where it
  // sits — and the loop that acted on it filtered the current page, so
  // everything ticked on an earlier page was counted in the button and
  // silently never approved.
  const [picked, setPicked] = useState<Map<string, Claim>>(new Map());
  const { cap, over } = useBulkCap(picked.size);
  const [batch, setBatch] = useState("");
  // The batch just agreed to, which is the only one there is a safe control
  // for: undoing one named at some point in the past is a control nobody can
  // use without knowing what is in it.
  const [justDone, setJustDone] = useState("");
  // The rows of a batch refused, so a partial result says so rather than
  // leaving somebody to compare counts.
  const [refused, setRefused] = useState(0);
  const approveClaim = useApproveClaim();
  const queries = useQueryClient();
  const undo = useMutation({
    mutationFn: async (name: string) =>
      unwrap(
        await api.DELETE("/v1/approval-batches/{batch}", {
          params: { path: { batch: name } },
        }),
      ),
    onSuccess: () => {
      setJustDone("");
      void queries.invalidateQueries({ queryKey: ["queue"] });
    },
  });

  // Whose claims. The queue proper is what is waiting on you; your own are a
  // different question — what did I propose that nobody has agreed to — and
  // they were mixed in, which made the queue a list containing work the reader
  // cannot do, because approving your own is refused.
  const mine = params.get("mine") === "1";
  // The product, where the address names one. The figure on the home screen
  // is narrowed by the scope picker and links here with it, so a queue that
  // ignored it answered a different question from the number that was clicked.
  const product = params.get("product") ?? "";
  const within = product ? { product } : {};
  const queue = useQuery({
    queryKey: ["queue", mine ? 0 : offset, mine, product],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/review-queue", {
          // A page when it is the list being read, one row when it is only
          // the tab's count: both sides are asked for on every visit so a tab
          // carries its number without being opened.
          params: { query: { limit: mine ? 1 : PAGE, offset: mine ? 0 : offset, ...within } },
        }),
      ),
  });
  // The fate of what this person proposed. A different question from the
  // queue's, and a different statement: the queue lists what is pending, so
  // approved, withdrawn, lapsed and undone all present there as the row
  // disappearing, and the proposer finds out by reopening the finding.
  const became = useQuery({
    queryKey: ["my-claims", mine ? offset : 0, mine],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/my-claims", {
          params: { query: { limit: mine ? PAGE : 1, offset: mine ? offset : 0 } },
        }),
      ),
  });

  const found = wanted > 0 && (queue.data?.items ?? []).some((row) => claimOf(row).id === wanted);
  useEffect(() => {
    if (!found) return;
    document.getElementById(`claim-${wanted}`)?.scrollIntoView({ block: "center" });
  }, [found, wanted]);
  // Lapsed and expired asked as one list. They overlap — a deferral that ran
  // out on code that then moved is both — so two lists had to be merged and
  // deduplicated here while the figure over them added the two totals and
  // counted the overlap twice. One question answers both, and the number it
  // comes back with is the number of rows.
  const stopped = useQuery({
    queryKey: ["queue", "stopped"],
    queryFn: async () =>
      unwrap(await api.GET("/v1/decisions", { params: { query: { stopped: true, limit: 50 } } })),
  });
  // A milder rating of an issue waits for a second person the same way a
  // dismissal does, and there was nowhere to be that second person: the route
  // existed and no screen reached it. Requests to keep something hidden longer
  // that nobody has agreed to . Until now there was nowhere to be that second
  // person: a request could be read on the finding it belongs to and nowhere
  // else, so the only way to find one was to already know it existed.
  //
  // It is on this screen because this is where somebody goes to be a second
  // person, and it is a separate list rather than a queue card because what is
  // agreed to is not a claim about code — it is how long something stays
  // hidden, and nothing about a claim's shape fits it.
  const [embargoAt, setEmbargoAt] = useState(0);
  const [ratingAt, setRatingAt] = useState(0);
  const embargoes = useQuery({
    queryKey: ["movements", "pending", embargoAt],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/disclosure-movements", {
          params: { query: { limit: PENDING_PAGE, offset: embargoAt } },
        }),
      ),
    // Somebody who may read nothing undisclosed gets an empty list rather than
    // a refusal, so this is quiet on their screen rather than an error on it.
    retry: false,
  });
  const ratings = useQuery({
    queryKey: ["queue", "assessments", ratingAt],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/assessments", {
          params: { query: { state: "proposed", limit: PENDING_PAGE, offset: ratingAt } },
        }),
      ),
  });

  if (queue.isPending) return <Loading />;
  if (queue.isError) {
    return <Failed error={queue.error} what="The review queue could not be read." />;
  }

  // The request the export links make, so a file matches the screen it was
  // taken from rather than being the whole backlog under a narrowed heading.
  const exporting = new URLSearchParams();
  if (mine) exporting.set("mine", "true");
  if (product) exporting.set("product", product);
  const asked = [...exporting].length > 0 ? "?" + exporting.toString() : "";
  const claims = (queue.data?.items ?? []).map(claimOf);
  const records = claims.reduce((sum, c) => sum + c.records, 0);
  const rows = stopped.data?.items ?? [];

  async function approvePicked() {
    // Sequential rather than parallel: each is a separate claim and a refusal
    // on one should not decide the fate of the rest — which is what the loop
    // said and did not do. An unguarded await abandoned every claim after the
    // first refusal, left the selection reading its original size, and never
    // set the batch name, so the undo control for the approvals that did land
    // never appeared.
    const named = batch.trim();
    const failed: string[] = [];
    let landed = 0;
    for (const [key, claim] of picked) {
      try {
        await approveClaim.mutateAsync({ id: claim.id, batch: named || undefined });
        landed++;
      } catch {
        failed.push(key);
      }
    }
    // The refused rows, and nothing else.
    //
    // The selection spans pages and the loop above acts on all of it, so an
    // entry that is not on the page in front of somebody was approved like the
    // rest — keeping it ticked because it is off-page left the count standing
    // and made a second press report every one of them as refused.
    //
    // Kept from the current selection rather than from the snapshot this loop
    // started with, so anything ticked while it ran survives.
    setPicked((prev) => {
      const left = new Map<string, Claim>();
      for (const [key, claim] of prev) {
        if (failed.includes(key)) left.set(key, claim);
      }
      for (const key of failed) {
        const held = picked.get(key);
        if (held) left.set(key, held);
      }
      return left;
    });
    setRefused(failed.length);
    // The agreement just made under one name, so it can be taken back
    // without remembering the name. The control the queue already promised:
    // "approvals under one batch name can be undone together" said so and
    // there was nowhere to do it.
    // Whenever at least one landed, which is the moment somebody notices —
    // not only when every one of them did.
    if (named && landed > 0) setJustDone(named);
  }

  return (
    <>
      <div className="screen-head">
        <h2>Review queue</h2>
        <p>
          {mine ? (
            <>
              {(became.data?.total ?? 0).toLocaleString()} proposed by you · what became of each,
              newest first
            </>
          ) : (
            <>
              {(queue.data?.total ?? claims.length).toLocaleString()} pending
              {records > claims.length && (
                <> · {records.toLocaleString()} records between those shown</>
              )}{" "}
              {product ? (
                <>
                  {" "}
                  · in <b>{product}</b>
                </>
              ) : (
                <> · across every product you may approve on</>
              )}
            </>
          )}
        </p>
        {/* The backlog as a file. One row per claim, the way this
            screen counts them, because that is the unit somebody works
            through — and reporting a backlog was copying this out by hand. */}
        <span style={{ marginLeft: "auto" }}>
          <a className="btn quiet" href={`/v1/review-queue.csv${asked}`}>
            CSV
          </a>{" "}
          <a className="btn quiet" href={`/v1/review-queue.json${asked}`}>
            JSON
          </a>
        </span>
      </div>

      <div className="tabs2">
        <button
          type="button"
          className="tab2"
          aria-selected={!mine}
          onClick={() => {
            const now = new URLSearchParams(params);
            now.delete("mine");
            now.delete("offset");
            setParams(now);
          }}
        >
          Waiting on me <span className="n">{(queue.data?.total ?? 0).toLocaleString()}</span>
        </button>
        <button
          type="button"
          className="tab2"
          aria-selected={mine}
          onClick={() => {
            const now = new URLSearchParams(params);
            now.set("mine", "1");
            now.delete("offset");
            setParams(now);
          }}
        >
          Mine, recent <span className="n">{(became.data?.total ?? 0).toLocaleString()}</span>
        </button>
      </div>

      {wanted > 0 && !found && (
        <div className="alert" style={{ marginBottom: 10 }}>
          <strong>Claim {wanted} is not waiting here.</strong>
          <span>
            It may have been decided, or it may sit on another page.{" "}
            <Link to={UNOWNED_LIST} className="linkish">
              Unassigned →
            </Link>
          </span>
        </div>
      )}

      {!mine && claims.length > 0 && (
        <div className="batchbar">
          <label style={{ display: "flex", gap: 7, alignItems: "center" }}>
            <input
              type="checkbox"
              checked={claims.length > 0 && claims.every((c) => picked.has(c.key))}
              onChange={(event) => {
                // This page either way, so ticking and unticking are
                // inverses. Unticking cleared every page's selection where
                // ticking added only this one's.
                const next = new Map(picked);
                for (const claim of claims) {
                  if (event.target.checked) next.set(claim.key, claim);
                  else next.delete(claim.key);
                }
                setPicked(next);
              }}
              aria-label="Select every claim shown"
            />
            <b>{picked.size === 0 ? "Nothing selected" : `${picked.size} selected`}</b>
          </label>
          <span className="hint">Approvals under one batch name can be undone together.</span>
          <span className="spacer" />
          <input
            {...notACredential}
            type="text"
            value={batch}
            onChange={(event) => setBatch(event.target.value)}
            placeholder="batch name"
            aria-label="Batch name"
            style={{ width: 150 }}
          />
          {/* Bounded by what this deployment allows in one act, and said
              rather than met one refusal at a time: approving is a request
              per claim, and this selection deliberately survives paging, so
              it can be arbitrarily large. */}
          {over && (
            <span className="alert" role="status">
              {overCapNotice(cap)}
            </span>
          )}
          <button
            type="button"
            className="btn"
            disabled={picked.size === 0 || approveClaim.isPending || over}
            onClick={() => void approvePicked()}
          >
            {picked.size === 0 ? "Approve selected" : `Approve ${picked.size} selected`}
          </button>
        </div>
      )}

      {refused > 0 && (
        <p className="alert" role="status">
          {refused === 1
            ? "One claim could not be agreed to and is still selected."
            : `${refused.toLocaleString()} claims could not be agreed to and are still selected.`}
        </p>
      )}
      {approveClaim.error != null && (
        <Failed error={approveClaim.error} what="That could not be approved." />
      )}
      {undo.error != null && (
        <Failed error={undo.error} what="That agreement could not be taken back." />
      )}

      {/* Taking a batch back. Offered only just after one was made, because
          this is the moment somebody notices — a permanent control for
          undoing something named at some point in the past is a control
          nobody can use safely. The decisions themselves stand; only the
          agreements are undone, and each proposer is told. */}
      {justDone && (
        <div className="alert info" style={{ marginBottom: 12 }}>
          <strong>Agreed to under &ldquo;{justDone}&rdquo;</strong>
          <span>Returns those claims to this queue. Each proposer is notified.</span>
          <button
            type="button"
            className="linkish"
            disabled={undo.isPending}
            onClick={() => undo.mutate(justDone)}
          >
            Undo the batch
          </button>
          <button type="button" className="linkish" onClick={() => setJustDone("")}>
            Dismiss
          </button>
        </div>
      )}

      {mine ? (
        <Became rows={became.data?.items ?? []} query={became} />
      ) : claims.length === 0 ? (
        <Empty
          title="Nothing is pending."
          detail="A claim needing a second person would appear here."
        />
      ) : (
        <div className="queue">
          {claims.map((claim) => (
            <Card
              key={claim.key}
              claim={claim}
              marked={claim.id === wanted}
              picked={picked.has(claim.key)}
              onPick={(on) => {
                const next = new Map(picked);
                if (on) next.set(claim.key, claim);
                else next.delete(claim.key);
                setPicked(next);
              }}
            />
          ))}
        </div>
      )}
      <Paged
        shown={mine ? (became.data?.items?.length ?? 0) : claims.length}
        total={mine ? became.data?.total : queue.data?.total}
        offset={offset}
        limit={PAGE}
        onGo={go}
      />

      <Ratings
        waiting={(ratings.data?.items ?? []).filter((each) => each.needs_approval)}
        total={ratings.data?.total}
        offset={ratingAt}
        onGo={setRatingAt}
        error={ratings.isError ? ratings.error : undefined}
      />

      {/* The movement read is deliberately quiet for somebody who may read
          nothing undisclosed — an empty list rather than a refusal — so only a
          real failure is handed on. */}
      <Embargoes
        waiting={embargoes.data?.items ?? []}
        total={embargoes.data?.total}
        offset={embargoAt}
        onGo={setEmbargoAt}
      />

      {/* A ruling setting reports aside waits for a second person the way a
          dismissal does, and this is where somebody goes to be one. Narrowed
          to the products the reader may work reports in. */}
      <WaitingRulings product={product || undefined} />

      <div className="screen-head" id="lapsed" style={{ marginTop: 22 }}>
        <h2>Lapsed decisions</h2>
        <p>
          {stopped.isError ? "—" : (stopped.data?.total ?? 0).toLocaleString()} · nobody has to
          agree to these again — two people already did — but each needs a fresh reason, because
          what it was a claim about has moved.
        </p>
      </div>
      {/* A read that did not happen is not a list of nothing. Without this the
          section drew "0 ·" over "Nothing has lapsed." on a failed read, which
          is the defect this whole change is about, one screen along from where
          it was fixed. */}
      <Paged shown={rows.length} total={stopped.data?.total} limit={50} />
      {stopped.isError ? (
        <Failed error={stopped.error} what="Lapsed decisions could not be read." />
      ) : rows.length === 0 ? (
        <Empty
          title="Nothing has lapsed."
          detail="A decision the code moved out from under, or a deferral whose date has passed, would appear here."
        />
      ) : (
        <div className="queue">
          {rows.map((row) => (
            <Stopped key={row.decision?.id} row={row} />
          ))}
        </div>
      )}
    </>
  );
}

type Standing = NonNullable<Body<"DecisionsOutputBody">["items"]>[number];

// A decision the code moved out from under, or a deferral whose date passed.
//
// A lapsed row points at the claim it belonged to, because re-affirming is an
// act on the claim: one act re-makes every place it covered. Pointed at the
// finding, a claim over forty five places drew forty five cards each offering
// the one-place-at-a-time workflow the whole-claim act exists to replace.
function Stopped({ row }: { row: Standing }) {
  const it = row.decision;
  const lapsed = it?.state === "lapsed";
  return (
    <article className="qcard lapsedcard">
      <header>
        <Link to={`/decisions/${it?.id}`} className="id linkish">
          {row.place?.vulnerability}
        </Link>
        <span style={{ color: "var(--muted)" }}>
          {row.place?.product} · {labeled(it?.outcome ?? "")}
          {it?.justification && (
            <>
              {" "}
              · <Because code={it.justification} />
            </>
          )}
        </span>
        <span className="state lapsed" style={{ marginLeft: "auto" }}>
          {lapsed ? "Lapsed" : "Deferral ran out"}
        </span>
      </header>
      {row.reasoning && (
        <div className="why">
          <Markdown source={row.reasoning} />
        </div>
      )}
      <div className="qmeta">
        <span>
          Proposed by <b>{row.proposed_by}</b>
        </span>
        <span>
          Stood <b>{row.age_days} days</b>
        </span>
        {it?.deferred_until && (
          <span>
            Put off until <b>{it.deferred_until}</b>
          </span>
        )}
      </div>
      <p className="hint" style={{ margin: 0 }}>
        {lapsed
          ? "The code moved. Re-affirm the whole claim, with a fresh reason."
          : "The deferral has expired."}
      </p>
      <div className="actions">
        {/* The claim, where the whole-act control is, rather than the row.
            A lapsed claim is re-made once however many places it covered. */}
        <Link
          to={lapsed && it?.claim_id ? `/claims/${it.claim_id}` : `/decisions/${it?.id}`}
          className="btn ghost"
        >
          {lapsed && it?.claim_id ? "Open the claim →" : "Open the decision →"}
        </Link>
      </div>
    </article>
  );
}

function Card({
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
        <Link to={f ? findingPath(f) : `/decisions/${claim.decisionId}`} className="linkish id">
          {claim.title}
        </Link>
        {/* What is being claimed, in its own right rather than as the fifth
            clause of a sentence about where the finding lives. It is the thing
            an approver is agreeing to, and it was reading as an afterthought
            behind the component, the version, the product, the branch and the
            variant. */}
        <Outcome
          outcome={claim.outcome}
          justification={claim.justification}
          until={claim.deferredUntil}
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
          {f ? `${f.product} · ${f.stream} · ${f.variant}` : claim.product}
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

      {/* What the issue is and where it sits, before the argument about it
: an approver judging a claim without these is judging the
          prose. Shown from the scan's own text, escaped, never rendered. */}
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
        {claim.proposedBy && (
          <span>
            Proposed by <b>{claim.proposedBy}</b>
          </span>
        )}
        <span>
          Standing <b>{claim.ageDays === 0 ? "today" : `${claim.ageDays} days`}</b>
        </span>
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
              {/* Every build it covers, this one included — which is what the
                  server sends and what the number means. It said "other" and
                  counted its own, so a claim covering one build read as
                  reaching a second one somewhere. */}
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
                <Link to={`/issues/${encodeURIComponent(claim.title)}`} className="linkish">
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
                          onChange={(event) => {
                            const next = new Set(aside);
                            for (const id of row.decision_ids ?? [row.decision_id]) {
                              if (event.target.checked) next.add(id);
                              else next.delete(id);
                            }
                            setAside(next);
                          }}
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
            Selected rows are excluded from the approval and rejected back to {claim.proposedBy} as
            a separate item, with this table as the reason.
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
              ? `Approve ${(claim.issues - aside.size).toLocaleString()}, reject ${aside.size}`
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

// The address of a claim's finding, with the version the build ships it at.
function findingPath(f: {
  product?: string;
  stream?: string;
  variant?: string;
  vulnerability?: string;
  component?: string;
  version?: string;
}): string {
  return (
    `/products/${encodeURIComponent(f.product ?? "")}` +
    `/streams/${encodeURIComponent(f.stream ?? "")}` +
    `/variants/${encodeURIComponent(f.variant ?? "")}` +
    `/findings/${encodeURIComponent(f.vulnerability ?? "")}` +
    `/components/${encodeURIComponent(f.component ?? "")}` +
    (f.version ? `?version=${encodeURIComponent(f.version)}` : "")
  );
}

// The claim itself, said as its own thing.
//
// The outcome is what an approver is agreeing to, and it was the fifth clause
// of a line that led with the component, the version, the product, the branch
// and the variant — so the most important fact on the card read as an
// afterthought. It leads now, in its own mark, with the recognized reason
// beneath it in the vocabulary the record actually stores.
function Outcome({
  outcome,
  justification,
  until,
}: {
  outcome: string;
  justification?: string;
  until?: string;
}) {
  return (
    <span className={`claimed ${outcome}`}>
      <b>{labeled(outcome)}</b>
      {justification && <span className="why mono">{justification}</span>}
      {until && <span className="why">until {until}</span>}
    </span>
  );
}
