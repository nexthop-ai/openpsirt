// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import {
  Activity,
  Comments,
  PreviousCard,
  Revisions,
  Standing,
  stateOf,
  type Previous,
} from "./FindingClaim";
import { Assess } from "./FindingAssess";
import { ExploitedHere } from "./FindingExploited";
import { Notes } from "./FindingNotes";
import { Duplicates, MatchMethod, LookItUp, Places, References, Reporter } from "./FindingEvidence";
import { Assignee, Attachments, Collaborators, Marks, Resolve } from "./FindingPeople";
import { useMemo, useRef, useState } from "react";
import { Loading } from "../ui/Loading";
import { on } from "../ui/when";
import { useQueries, useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, type Body } from "../api/client";
import { at as choicesAt, unwrap } from "../api/queries";
import { useWho } from "../app/session";
import { Failed } from "../ui/Failed";
import { Severity, Exploited, ExploitedHere as ExploitedHereBadge } from "../ui/Severity";
import { Weaknesses } from "../ui/Weakness";
import { AffectedBuilds } from "./FindingBuilds";
import { Markdown } from "../ui/Markdown";
import { Decide, said, type Recorded } from "../ui/Decide";
import { useKept } from "../ui/Saved";
import { Because } from "../ui/Outcome";
import { fromAt, listQuery, pathTo, where, windowFor, withinVariant } from "./list";

// One finding: what the issue is, how bad, what upstream has done, where it
// sits, the evidence — and the working screen for deciding it, before and
// after. When a claim stands it is shown in its state, with one activity
// timeline, the revision history, the comments, and the decisions made at this
// place before, whose reasoning is offered back.

// The score's publisher and its rank, as a reader
// can use it.
//
// A publisher that is a bare identifier is dropped. Half of what arrives here
// is a CNA's own UUID — "b0ca135-0b70-47ef-9f44-1890c2a1c46c" — which answers
// "who says 7.8" with a string nobody can look up, and putting it on screen
// beside a real name like "nvd@nist.gov" says the two are the same kind of
// answer. Whether it is primary or secondary survives either way, because that
// is the part somebody weighing two scores acts on.
const ANONYMOUS = /^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i;

function scoredBy(source: string | undefined, kind: string | undefined): string {
  const named = (source ?? "").trim();
  return [ANONYMOUS.test(named) ? "" : named, (kind ?? "").trim().toLowerCase()]
    .filter(Boolean)
    .join(" · ");
}

// A step's landing place, said in the hover rather than on the button: the
// button says which direction, and which finding is what somebody checks
// before taking it.
function neighborly(step: { row: { vulnerability?: string; component?: string } }): string {
  return `${step.row.vulnerability ?? ""} in ${step.row.component ?? ""}`;
}

type Similar = Body<"SimilarBody">;

// The places of the finding asked which decision stood there
// before. The finding carries the earlier decisions themselves; what it does
// not carry is which place each was at, and reaffirming one needs the place.
const SAMPLE = 8;

// The reason a finding carries no deadline, in words a reader can act on.
//
// Each says what to do with the row rather than naming the rule: somebody
// reading this is deciding whether to look further, and "below the line" on
// its own is a term they would have to go and learn.
function whyNone(reason: string | undefined): string {
  switch (reason) {
    case "not-rated":
      return "nobody has rated it yet. The clock starts when somebody does.";
    case "below-the-line":
      return "below what this product triages at. Recorded and counted; nothing is late.";
    case "nothing-to-take":
      return "upstream has released no fix, or has declined to, so there is no version that would close it.";
    case "out-of-support":
      return "the release is past its end of life, so nothing here will be fixed.";
    default:
      return "nothing here is late.";
  }
}

export function Finding() {
  const {
    product = "",
    stream = "",
    variant = "",
    vulnerability = "",
    component = "",
  } = useParams();
  const [params] = useSearchParams();
  const version = params.get("version") ?? "";
  // The list this was opened from, carried as one value. Working a filtered
  // list meant returning to it and finding your place after every decision;
  // with the list's own address in hand, the row before and the row after are
  // a link — under the same filters, in the same order. Present and empty is a
  // list that asked for everything, which walks like any other; absent is no
  // list at all, and then there is no order for this to be next in.
  const walking = params.has("from");
  const from = params.get("from") ?? "";
  const who = useWho();
  const at = { product, stream, variant, vulnerability, component };
  const [recorded, setRecorded] = useState<Recorded | null>(null);
  // The decision form, for the one act that has to put it in front of
  // somebody: reusing an earlier reasoning fills it in and then has to show
  // them what it filled in.
  const form = useRef<HTMLDivElement>(null);
  // The place the confirmation is drawn. It sits at the head of the screen,
  // above everything the finding says, and the button that produces it is at
  // the foot of the decision form — so somebody pressing submit was left
  // looking at the form they had just sent, with the answer a page and a half
  // above them and nothing saying anything had happened.
  const confirmation = useRef<HTMLDivElement>(null);
  // The finding the screen is on. A params-only change does not remount it,
  // so anything below that belongs to one finding has to say which.
  const oneFinding = `${vulnerability}|${component}|${version}`;
  // The decision form's starting point, and how many times it has been given
  // one. Starting from something is a fresh form rather than an edit to the one
  // on screen, so the count is what the form is mounted against — two prefills
  // carrying the same words are still two, and the second has to take.
  const [prefill, setPrefill] = useState<{
    // The finding it was started on. Walking to the next one is a fresh form:
    // without this, one decision recorded would leave the count above zero for
    // the rest of the walk and the rule would quietly stop filling anything in.
    at: string;
    n: number;
    from: {
      outcome?: string;
      justification?: string;
      reasoning?: string;
      // The length of the deferral it offers, which the form turns into a date
      // as it opens. Only a prepared rule carries one: a length is what a rule
      // means by "put this off for a quarter", and a date saved months ago is
      // not.
      deferDays?: number;
      // Cited, never applied: what a VEX document said is not this claim, and
      // this is what lets a later revision to it be noticed.
      fromStatement?: number;
    } | null;
  }>({ at: oneFinding, n: 0, from: null });
  // The statement started from on the finding being read, which is nothing on
  // one the count was not raised on.
  const own = prefill.at === oneFinding ? prefill : { at: oneFinding, n: 0, from: null };
  function startFrom(from: (typeof prefill)["from"]) {
    setPrefill({ at: oneFinding, n: own.n + 1, from });
  }
  const [reclassifying, setReclassifying] = useState(false);
  const [extending, setExtending] = useState<{ claimId: number; decisionId: number } | null>(null);
  // The saved filter this was opened under, where it is one that prepares a
  // claim. The address names the filter rather than repeating what it says, so
  // what a rule prepares is decided in one place — and a link somebody sends
  // prepares nothing for the person who opens it, because the filters are
  // personal and a name they have not kept is a name that is not there.
  const rule = params.get("rule") ?? "";
  const rules = useKept(product, rule !== "");
  // The claim that filter prepares, in the words the form takes, and whether it
  // prepares something no form can be submitted from. A rule prepares a claim
  // and a person proposes it: this fills the form in and nothing else.
  const offered = useMemo(() => {
    const one = (rules.data?.items ?? []).find((each) => each.name === rule);
    if (!one?.prepares) return { from: null, lengthless: false };
    const it = one.prepares;
    // A deferral is the one outcome that needs a date, and the date is worked
    // out from the length. Kept without one — which every deferral saved
    // before there was a field for it was — it would fill a form that cannot
    // be submitted, under a banner saying the filter prepared it.
    if (it.outcome === "deferred" && !it.defer_days) return { from: null, lengthless: true };
    return {
      from: {
        outcome: it.outcome,
        justification: it.justification ?? "",
        reasoning: it.reasoning,
        ...(it.defer_days ? { deferDays: it.defer_days } : {}),
      },
      lengthless: false,
    };
  }, [rules.data, rule]);
  const prepared = offered.from;
  // The form's opening values, and the thing it is mounted against. Somebody
  // who has started from something on this finding has said which prefill they
  // want, so theirs wins and clearing it clears the rule's too — the rule fills
  // a form nobody has answered yet, not one somebody is working in.
  const opening = own.n > 0 ? own.from : prepared;
  const opened =
    own.n > 0 ? `own:${oneFinding}:${own.n}` : `rule:${prepared ? rule : ""}:${oneFinding}`;
  // Held until what the rule prepares is known, because a form that opens
  // blank and refills itself a moment later loses whatever somebody put in it
  // first — which is what a reloaded or bookmarked link does, having no
  // answer already in hand.
  const settled = rule === "" || !rules.isPending;

  const list = useMemo(() => new URLSearchParams(from), [from]);
  // Through the same guard the list applies: what is specific to a variant is
  // a question about one, and an address carrying the filter without a variant
  // is refused by the server — which would take the previous and next row with
  // it rather than the filter.
  const listed = useMemo(
    () => withinVariant(listQuery(list), Boolean(list.get("variant"))),
    [list],
  );
  // Widened by one at each end, so that stepping off a page finds the row on
  // the next one rather than stopping at a boundary the reader never chose.
  const span = useMemo(() => windowFor(listed.offset, listed.limit), [listed]);
  const neighbors = useQuery({
    enabled: walking,
    queryKey: ["walk", product, from],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/findings", {
          params: { path: { product }, query: { ...listed, ...span, ...where(list) } },
        }),
      ),
  });
  const walk = useMemo(() => {
    const items = neighbors.data?.items ?? [];
    // By what the row is rather than by where it sat: the list is read afresh
    // here, and a row may have moved or gone since it was drawn.
    const i = items.findIndex(
      (row) =>
        row.vulnerability === vulnerability &&
        row.component === component &&
        (row.version ?? "") === version,
    );
    if (i < 0) return null;
    function step(j: number) {
      const row = items[j];
      if (!row) return null;
      return {
        row,
        to: pathTo(
          {
            product,
            stream: row.stream || (list.get("stream") ?? ""),
            variant: row.variant || (list.get("variant") ?? ""),
          },
          row,
          // The neighbor is handed the list at the page it sits on, so a walk
          // that crosses a boundary leaves the list where the reader now is.
          fromAt(from, span.offset + j, listed.limit),
          // And the rule the list was opened under, or walking to the next
          // finding would quietly stop filling the form in.
          rule,
        ),
      };
    }
    return {
      at: span.offset + i,
      total: neighbors.data?.total ?? 0,
      previous: step(i - 1),
      next: step(i + 1),
    };
  }, [
    neighbors.data,
    span,
    listed.limit,
    list,
    from,
    rule,
    product,
    vulnerability,
    component,
    version,
  ]);

  const finding = useQuery({
    queryKey: ["finding", at, version],
    queryFn: async () =>
      unwrap(
        await api.GET(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/findings/{vulnerability}/components/{component}",
          { params: { path: at, query: version ? { version } : {} } },
        ),
      ),
  });

  const it = finding.data;
  // Whether this reader may argue about this finding, which is what the
  // controls about the finding turn on: triage at the finding's own
  // visibility, since each is its own role. A record of being exploited here
  // is about the product and takes triage at either visibility. Read once:
  // asked at each control, the copies drift and one of them ends up offering a
  // button that answers 403.
  const here = who.data?.reach.find((r) => r.product === product);
  const mayTriage = !!(it?.undisclosed ? here?.may_hide : here?.triages_public);
  const places = useMemo(() => it?.places ?? [], [it]);
  // A place is the component and what pulls it in; two chains reaching the
  // same pair are one place, and the head counts what a decision covers.
  const distinct = new Set(places.map((place) => place.place)).size;
  // The claims standing here, one representative decision each, read for the
  // reasoning and the approvals the claim row does not carry.
  const standingIds = useMemo(() => (it?.standing ?? []).map((c) => c.decision_id), [it]);
  const standing = useQueries({
    queries: standingIds.slice(0, SAMPLE).map((id) => ({
      queryKey: ["decision", id],
      queryFn: async () =>
        unwrap(await api.GET("/v1/decisions/{id}", { params: { path: { id } } })),
    })),
  });
  // The place each earlier decision was at, for reaffirming it.
  const openPlaces = places.filter((p) => p.decision == null).slice(0, SAMPLE);
  const history = useQueries({
    queries: ((it?.previous ?? []).some((p) => p.ended === "lapsed") ? openPlaces : []).map(
      (place) => ({
        queryKey: ["decided", at, place.place],
        queryFn: async () =>
          unwrap(
            await api.GET(
              "/v1/products/{product}/streams/{stream}/variants/{variant}/findings/{vulnerability}/places/{place}/decision",
              { params: { path: { ...at, place: place.place ?? "" } } },
            ),
          ),
      }),
    ),
  });

  if (finding.isPending) return <Loading />;
  if (finding.isError) {
    const choices = choicesAt(finding.error, "query.version");
    if (choices.length > 0) {
      return (
        <div className="card">
          <h3>Versions of {component}</h3>
          <p className="reading" style={{ marginBottom: 10 }}>
            Shipped at more than one version here.
          </p>
          <ul className="refs">
            {choices.map((choice) => (
              <li key={`${choice.version} ${choice.ecosystem ?? ""}`}>
                <Link className="linkish id" to={`?version=${encodeURIComponent(choice.version)}`}>
                  {choice.version}
                </Link>
                {choice.ecosystem && <span className="hint">{choice.ecosystem}</span>}
              </li>
            ))}
          </ul>
        </div>
      );
    }
    return <Failed error={finding.error} what="This finding could not be read." />;
  }
  if (!it) return null;

  // The rating shown: the newest generation the issue is rated under, and the
  // issue's own score where no rating is held beside it.
  const newest = it.ratings?.[0] ?? {
    score: it.score ?? 0,
    version: it.score_version ?? "",
    vector: it.vector ?? "",
    source: it.score_source,
    kind: it.score_kind,
  };

  // Each claim kept with the summary it came from, paired before anything is
  // dropped. Filtering first and indexing the summary list afterwards paired
  // a claim with another claim's summary the moment one of the parallel reads
  // was slow or failed — and the summary is where the identifier the reasoning
  // editor writes to comes from, so a revision landed on the wrong claim.
  const pairs = standingIds.slice(0, SAMPLE).flatMap((_, i) => {
    const claim = standing[i]?.data;
    return claim ? [{ claim, summary: it.standing?.[i] }] : [];
  });
  const claims = pairs.map((pair) => pair.claim);
  const placeOf = new Map<number, string>();
  history.forEach((q, i) => {
    for (const d of q.data?.previously ?? []) {
      if (d.decision?.id && !placeOf.has(d.decision.id))
        placeOf.set(d.decision.id, openPlaces[i]?.place ?? "");
    }
  });
  const previous: Previous[] = (it.previous ?? []).map((p) => ({
    id: p.decision_id,
    outcome: p.outcome,
    justification: p.justification ?? "",
    deferredUntil: p.deferred_until ?? "",
    proposedBy: p.proposed_by_name || p.proposed_by,
    proposedAt: p.proposed_at,
    state: p.ended,
    endedAt: p.ended_at ?? "",
    about: p.about ?? "",
    approvedBy: p.approved_by_name || p.approved_by || "",
    reasoning: p.reasoning,
    place: placeOf.get(p.decision_id) ?? "",
  }));
  const similar: Similar[] = it.similar ?? [];
  // Another product's decision about this same issue at this same place.
  // Evidence and a prefill, never an outcome: what is shipped around a
  // component differs between products, which is the whole reason a place is a
  // component at a position rather than a component.
  const elsewhere = it.elsewhere ?? [];
  // Anything here still to answer. One named predicate rather than
  // the same test written at four sites: the fifth was written in a different
  // unit — a count of distinct places against a count of chain rows — and
  // could never be false, which read as a second safety check and was none.
  const undecided = places.some((place) => place.decision == null);
  // What publishers have said, from VEX documents and supplier advisories: a
  // third layer beside what the build claims and what we decided. Shown,
  // offered as a prefill, never applied.
  const publishers = it.said ?? [];

  // Counted as places, the way the decision counts them, not as chain rows.
  const decided = new Set(places.filter((p) => p.decision != null).map((p) => p.place)).size;
  const state = stateOf(
    claims,
    decided,
    distinct,
    (it.standing ?? []).map((each) => each.state ?? ""),
  );
  // Back to the list as it was, where this was opened from one: the same
  // filters, the same order, the same page. The product's own list route takes
  // them, because the build travels in the address like every other filter and
  // the list may have been across several.
  const back = walking
    ? `/products/${encodeURIComponent(product)}/findings${from ? `?${from}` : ""}`
    : `/products/${encodeURIComponent(product)}` +
      `/streams/${encodeURIComponent(stream)}` +
      `/variants/${encodeURIComponent(variant)}/findings`;
  const build =
    `/products/${encodeURIComponent(product)}` +
    `/streams/${encodeURIComponent(stream)}` +
    `/variants/${encodeURIComponent(variant)}`;
  const mine = (proposedBy: string) => !!who.data && proposedBy === who.data.identity;

  return (
    <>
      <div className="screen-head">
        <span className="crumbs">
          <Link to={back} className="linkish" style={{ fontWeight: 500, color: "var(--muted)" }}>
            Findings
          </Link>{" "}
          › <b>{it.vulnerability}</b>
        </span>
        {/* Where this sits in the list it was opened from, and the way on
. Absent where it was not opened from a list, because
            there is then no order for it to be next in. */}
        {walk && (
          <div className="walking">
            {walk.previous ? (
              <Link to={walk.previous.to} className="btn quiet" title={neighborly(walk.previous)}>
                ← Previous
              </Link>
            ) : (
              <span className="btn quiet off">← Previous</span>
            )}
            <span className="hint">
              {(walk.at + 1).toLocaleString()} of {walk.total.toLocaleString()}
            </span>
            {walk.next ? (
              <Link to={walk.next.to} className="btn quiet" title={neighborly(walk.next)}>
                Next →
              </Link>
            ) : (
              <span className="btn quiet off">Next →</span>
            )}
          </div>
        )}
        <h2>
          {/* The one screen that answers "everywhere this issue sits" had
              almost no doors into it: an exact-match search, one report and
              one queue link. The identifier a reader is already looking at is
              the natural one. */}
          <Link
            to={`/issues/${encodeURIComponent(it.vulnerability ?? "")}`}
            className="id"
            title={`${it.vulnerability} everywhere it sits`}
          >
            {it.vulnerability}
          </Link>{" "}
          in <span className="id">{it.component}</span>{" "}
          <Severity word={it.assessed || it.severity} />{" "}
          <ExploitedHereBadge when={(it.exploited_here ?? []).some((each) => each.standing)} />{" "}
          {it.exploited && <Exploited when />}{" "}
          <span className={`state ${state.cls}`}>{state.label}</span>
        </h2>
        <p>
          {product} · {stream} · {variant} · {distinct} {distinct === 1 ? "place" : "places"} ·{" "}
          <b style={{ color: "var(--ink)" }}>
            {decided} of {distinct} decided
          </b>
        </p>
        {/* When it runs out, how long it has been here, and who is carrying
            it. The list carried all three and the screen somebody actually
            decides on carried none, so the one row that matters was the one
            place you had to go back to the list to read. */}
        <p className="hint">
          {it.due ? (
            <>
              Due <b style={{ color: "var(--ink)" }}>{on(it.due)}</b>
              {typeof it.days_left === "number" && (
                <>
                  {" · "}
                  {it.days_left < 0 ? (
                    <span className="state lapsed">{Math.abs(it.days_left)} days over</span>
                  ) : (
                    <span className={it.days_left <= 7 ? "state waiting" : undefined}>
                      {it.days_left} days left
                    </span>
                  )}
                </>
              )}
            </>
          ) : (
            // Said rather than left blank: every reason is deliberate, so an
            // empty cell would read as missing data on the row somebody is
            // deciding about.
            <>No deadline — {whyNone(it.no_deadline)}</>
          )}
          {it.opened && (
            <>
              {" · "}open here since <b style={{ color: "var(--ink)" }}>{on(it.opened)}</b>
            </>
          )}
          {" · "}
          {it.assigned_to ? (
            <>
              held by <b style={{ color: "var(--ink)" }}>{it.assigned_to}</b>
            </>
          ) : (
            "held by nobody"
          )}
        </p>
        {/* The words people put on this, beside what it is rather
            than filed under the evidence: a mark is ours and the evidence is
            the world's, and somebody scanning the head for what state this is
            in is the person who put the mark here. */}
        <Marks
          at={at}
          tags={it.tags ?? []}
          mayMark={mayTriage}
          onChanged={() => void finding.refetch()}
        />
      </div>

      {/* The standing notice disclosure opening the record requires: unmissable, above everything,
          and on the screen where somebody is about to write something down.
          The row's chip is the secondary signal, not this. */}
      {it.undisclosed && (
        <div className="alert" style={{ marginBottom: 14 }}>
          <strong>Not disclosed</strong>
          <span>
            Nothing about this has been announced. Anything said about it outside this deployment
            discloses it — including a ticket, a commit message or a chat.
            {it.disclose_at ? (
              <>
                {" "}
                The embargo ends <b>{on(it.disclose_at)}</b>, and reaching that date discloses
                nothing by itself.
              </>
            ) : (
              <> No end date has been set.</>
            )}
          </span>
        </div>
      )}

      {recorded && (
        <div className="alert info" style={{ marginBottom: 14 }} ref={confirmation}>
          <strong>Submitted</strong>
          <span>
            Recorded against {recorded.recorded} {recorded.recorded === 1 ? "place" : "places"} here
            {recorded.applied.length > 0 && <>, and in {recorded.applied.join(", ")}</>};{" "}
            {recorded.matching} matching {recorded.matching === 1 ? "build is" : "builds are"}{" "}
            reached by lookup.{" "}
            {recorded.needsApproval
              ? `The ${said(recorded.outcome)} takes effect once a second person approves it. ` +
                `It is now in the review queue.`
              : "In force now."}{" "}
            {/* The next finding first, where there is one: somebody working a
                list wants the next one, and the review queue is where the
                claim went rather than where they are going. */}
            {walk?.next && (
              <>
                <Link to={walk.next.to} className="linkish">
                  Next finding →
                </Link>{" "}
                ·{" "}
              </>
            )}
            <Link to="/review-queue" className="linkish">
              Go to the review queue →
            </Link>
          </span>
        </div>
      )}

      {it.arrived_from && (
        <div className="shortfall">
          <span className="icon">◭</span>
          <div>
            <h4>Short upgrades</h4>
            <p>
              <span className="id">{it.component}</span> moved{" "}
              <b>
                {it.arrived_from} → {it.version}
              </b>
              {it.fixed_in && (
                <>
                  ; this issue is fixed in <b>{it.fixed_in}</b>
                </>
              )}
              , so the upgrade could not have resolved it. The old reasoning probably still stands,
              and somebody's remediation did not land.
            </p>
            <div className="ladder">
              <span className="v was">{it.arrived_from}</span>
              <span className="arrow">→</span>
              <span className="v now">{it.version} shipped</span>
              {it.fixed_in && (
                <>
                  <span className="arrow">·</span>
                  <span className="v need">{it.fixed_in} fixes it</span>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Evidence on one side and the action on the other. The
          decision form used to sit below the description, the chains, the
          holder, the assessment and the similar decisions — about 1,550 pixels down a page running to 2,800, so
          on an ordinary screen the thing the page is for was three
          screens away. Neither is hidden to fix it: what is read in order
          to decide sits beside what decides it, which is the arrangement
          the decision form already uses inside itself. */}
      {/* What the issue is, before anything about deciding it. It sat in the
          narrow column beside the action, where a paragraph of a CVE
          description runs four words to a line — and it is the thing somebody
          reads first to work out whether the rest is worth reading. Full
          width and first; the action is immediately under it rather than
          three screens down, which is what keeping the primary action above
          the fold is for. */}
      {it.description && (
        <div className="card described">
          <h3>Description</h3>
          {/* What a **scan file** said is shown and never rendered:
              it is a third party's text reaching the people who hold the most
              access here. What somebody recorded *here* is our own prose,
              written through the same editor and the same submission policy
              as a justification, and it is rendered like one. */}
          {it.recorded ? (
            <Markdown source={it.description} />
          ) : (
            <p style={{ whiteSpace: "pre-wrap" }}>{it.description}</p>
          )}
        </div>
      )}

      {/* Evidence first and full width, then the form beneath it. The two
          stood side by side, the form wide on the left and the facts narrow
          on the right, so the facts were read in a 380-pixel column while
          the widest thing on the screen was an empty text area. What
          somebody does here is weigh the evidence and then act, and the
          layout now runs in that order. */}
      <div className="evidence">
        <div className="evblock">
          <h4>Severity</h4>
          <div className="scores">
            {/* Where the number came from. Everything else this screen shows
                carries its provenance — what found it, what it was matched
                from, what it was matched in — and the one number a deadline is
                set from carried none, so a reader asking who says 5.9 had
                nowhere to go. */}
            {/* The newest generation the issue is rated under, and the
                others beside it: a version 3 and a version 4 rating are two
                judgments. */}
            <div className="score">
              <span className="n">{newest.score ? newest.score.toFixed(1) : "—"}</span>
              <span className="l">CVSS{newest.version ? ` ${newest.version}` : ""}</span>
              {scoredBy(newest.source, newest.kind) && (
                <span className="l">{scoredBy(newest.source, newest.kind)}</span>
              )}
              {(it.ratings ?? []).slice(1).map((other) => (
                <span className="l" key={other.version} title={other.vector}>
                  also {other.score.toFixed(1)} on CVSS {other.version}
                </span>
              ))}
            </div>
            {/* The estimate, what it means, and whether it is current.
                Nobody acts on 0.00042; "higher than 91% of everything
                published" is the same number a reader can use. It is a
                thirty-day forecast recomputed daily, so the day it is about
                is part of it rather than a detail. */}
            <div className="score">
              <span className="n">
                {typeof it.likelihood === "number" ? it.likelihood.toFixed(3) : "—"}
              </span>
              <span className="l">
                EPSS
                {typeof it.likelihood_percentile === "number" && it.likelihood_percentile > 0 && (
                  <> · {(it.likelihood_percentile * 100).toFixed(0)}th percentile</>
                )}
              </span>
              {it.likelihood_on && <span className="l">as of {it.likelihood_on}</span>}
            </div>
            <div className="score">
              <span className="n">{it.exploited ? "Yes" : "No"}</span>
              <span className="l">Exploited</span>
            </div>
          </div>
          {/* What kind of flaw this is, all of it. One identifier was shown
              and the rest were dropped, and a bare number is not something a
              reader knows: the common ones are named here, every one of them
              links to where it is written up, and the two words a feed uses to
              say it has no classification are said rather than drawn as one. */}
          <Weaknesses of={it.weaknesses ?? []} />
          {newest.vector && (
            <p className="mono" style={{ fontSize: "var(--step--1)", color: "var(--muted)" }}>
              {newest.vector}
            </p>
          )}
          {/* The control sits on the line that reports the rating, so
              somebody reading a severity does not have to go and find the
              button for it. */}
          <p className="hint">
            {it.assessed ? (
              <>
                Assessed <Severity word={it.assessed} /> · published <Severity word={it.severity} />
              </>
            ) : (
              <>
                Published <Severity word={it.severity} />
              </>
            )}
            {undecided && !reclassifying && (
              <button
                type="button"
                className="linkish"
                style={{ marginLeft: 8 }}
                onClick={() => setReclassifying(true)}
              >
                Reclassify
              </button>
            )}
          </p>
          {reclassifying && (
            <Assess
              product={product}
              vulnerability={vulnerability}
              published={it.severity ?? ""}
              assessed={it.assessed ?? ""}
              onClose={() => setReclassifying(false)}
            />
          )}
          {/* Beside the rating, because the two are the pair a reader is
              weighing: what the world says this is worth, and whether it has
              already happened to us. */}
          <ExploitedHere
            product={product}
            vulnerability={vulnerability}
            records={it.exploited_here ?? undefined}
            mayTriage={!!here?.may_triage}
          />
        </div>

        <MatchMethod
          matched={it.matched}
          from={it.matched_from}
          version={it.version}
          inData={it.matched_in}
          range={it.matched_range}
        />

        <div className="evblock">
          <h4>Upstream</h4>
          <p>
            {/* The name opens the component, here as in both list views:
                what is open against it across every build, where it could
                go, and the act that moves it. */}
            <Link
              className="linkish id"
              title={`Open ${it.component}`}
              to={`/products/${encodeURIComponent(product)}/components/${encodeURIComponent(it.component ?? "")}`}
            >
              {it.component} {it.version}
            </Link>
            {it.upstream && (
              <>
                {" "}
                — cut from <span className="id">{it.upstream}</span>
              </>
            )}
            {". "}
            {it.fix_state === "fixed" && it.fixed_in ? (
              <>
                Fixed upstream in <span className="id">{it.fixed_in}</span>
                {it.fixed_at && <>, available since {on(it.fixed_at)}</>}.
              </>
            ) : it.fix_state === "wont-fix" ? (
              <>Upstream has declined to fix this.</>
            ) : it.fix_state === "mixed" ? (
              <>The places this sits at do not agree about what upstream did.</>
            ) : (
              <>No fix has been published.</>
            )}
          </p>
          {it.latest_version && (
            <p className="hint" style={{ margin: 0 }}>
              Newest upstream release is <span className="id">{it.latest_version}</span>
              {it.latest_released_at && <>, which shipped {on(it.latest_released_at)}</>}.
            </p>
          )}
          {it.nothing_since && (
            <p className="alert" style={{ margin: 0 }}>
              <span>
                Nothing has been released upstream since {it.latest_released_at ?? "well before"},
                over a year before this issue was named, and there is no fix. Replacing or patching
                the component is the response available.
              </span>
            </p>
          )}
        </div>

        {/* What produced this, and when it first appeared. The
            run that answers now is not the run that answered, so this
            cannot be worked out again later — and it is the only thing that
            can answer "which vulnerability database produced the finding
            you dismissed on 3 March" after a feed is corrected. */}
        {(it.found_by || it.opened) && (
          <div className="evblock">
            <h4>First seen</h4>
            <p>
              {it.opened && (
                <>
                  <b>{it.opened}</b>
                  {it.found_by ? ", by " : "."}
                </>
              )}
              {it.found_by && (
                <>
                  <span className="id">
                    {it.found_by.scanner}
                    {it.found_by.scanner_version ? ` ${it.found_by.scanner_version}` : ""}
                  </span>
                  {it.found_by.database_version && (
                    <>
                      {" "}
                      against the vulnerability database of{" "}
                      <span className="id">{it.found_by.database_version}</span>
                    </>
                  )}
                  .
                </>
              )}
            </p>
            {!it.found_by && (
              <p className="hint" style={{ margin: 0 }}>
                Entered by a person, not a scanner
              </p>
            )}
          </div>
        )}

        {(it.aliases ?? []).length > 0 && (
          <div className="evblock">
            <h4>Aliases</h4>
            <p className="id">{(it.aliases ?? []).join(" · ")}</p>
          </div>
        )}
      </div>

      <div className="acting">
        {pairs.map(({ claim, summary }) => (
          <Standing
            key={claim.decision?.id}
            claim={claim}
            summary={summary}
            places={places}
            mine={mine(claim.proposed_by ?? "")}
            mayApprove={!!(it.undisclosed ? here?.agrees_private : here?.agrees_public)}
            onRevised={() => void finding.refetch()}
            about={{ product, vulnerability }}
            undisclosed={!!it.undisclosed}
          />
        ))}

        {/* Above the VEX statements: a write-up is what somebody deciding
            reads first, and a third party's claim is read against it. The
            whole block of links belongs below the action, which is a different
            question from the advisory the judgment rests on. */}
        <div className="evidence">
          <References advisory={it.advisory} refs={it.references ?? []} />
          <LookItUp links={it.links ?? []} />
        </div>

        {undecided && (
          <>
            {/* Said when there is nothing, because the difference matters:
                an empty panel reads as "nobody has an opinion about this",
                and what it actually means is that no document saying so has
                been uploaded here. The layer is fed only by uploads
 — nothing derives it, and a distribution's
                will-not-fix arrives through the scanner as an upstream fix
                status instead. */}
            {publishers.length === 0 && (
              <div className="card">
                <h3>What publishers say</h3>
                <p className="reading" title="Uploaded by an administrator, never fetched">
                  Nothing uploaded
                </p>
              </div>
            )}

            {publishers.length > 0 && (
              <div className="card">
                <h3>What publishers say</h3>
                <p className="reading" style={{ marginBottom: 8 }}>
                  Evidence only. Nothing here is decided or counted from it.
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
                      </span>
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
                              // the same sentence about a different claim.
                              reasoning:
                                `${one.publisher} says ${(one.status ?? "").replace("_", " ")}` +
                                (one.about ? ` of ${one.about}` : "") +
                                (one.statement ? `: ${one.statement}` : "") +
                                "\n\n",
                            })
                          }
                        >
                          Start from this
                        </button>
                        <span className="hint">
                          Fills in the form. The decision is still yours.
                        </span>
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
                  <div key={s.decision_id} className="prior">
                    <header>
                      <span className="id">#{s.decision_id}</span>{" "}
                      <Because code={s.justification} />
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
                          setExtending({ claimId: s.claim_id, decisionId: s.decision_id });
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
                    judgment about their product is not a judgment about this
                    one — what is shipped around the component differs — so
                    this offers words to start from and decides nothing. */}
                <p className="reading" style={{ marginBottom: 8 }}>
                  The same issue at the same place in another product. Somebody else&apos;s judgment
                  about their build, to read rather than to take.
                </p>
                {elsewhere.map((e) => (
                  <div key={`${e.product} ${e.decision_id}`} className="prior">
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
            {/* Said before anything is decided, because what the form is
                filled in with is what somebody is about to put their name
                to. A rule proposes nothing by itself, and the screen it
                fills is where that has to be legible. */}
            {/* A failure to read your filters is not the same as a filter
                that prepares nothing, and the silent form looks identical.
                The absence of a rule is meant to be silent; not finding out
                is not. */}
            {rule !== "" && rules.isError && (
              <div className="alert">
                <strong>Your saved filter “{rule}” could not be read</strong>
                <span>Nothing was filled in.</span>
              </div>
            )}
            {offered.lengthless && (
              <div className="alert">
                <strong>“{rule}” prepares a deferral with no length</strong>
                <span>
                  Nothing was filled in. The filter has no deferral length; save it again to set
                  one.
                </span>
              </div>
            )}
            {own.n === 0 && prepared && (
              <div className="alert info">
                <strong>Filled in from “{rule}”</strong>
                <span>
                  Nothing is proposed until you submit. It goes out as <b>your</b> claim.
                </span>
                <button
                  type="button"
                  className="linkish"
                  style={{ marginLeft: "auto" }}
                  onClick={() => startFrom(null)}
                >
                  Empty the form
                </button>
              </div>
            )}
            {settled && (
              <div ref={form}>
                <Decide
                  at={{ ...at, version }}
                  places={places}
                  undisclosed={!!it.undisclosed}
                  assigning={
                    <Assignee
                      at={at}
                      assigned={it.assigned_to ?? ""}
                      undisclosed={!!it.undisclosed}
                      routedBy={it.routed_by ?? ""}
                    />
                  }
                  onDone={(r) => {
                    setRecorded(r);
                    startFrom(null);
                    setExtending(null);
                    // Brought to where somebody is looking. Smooth, like the
                    // form's own scroll, so the page moving is something they
                    // watch happen rather than a jump they have to re-find
                    // themselves after.
                    requestAnimationFrame(() =>
                      confirmation.current?.scrollIntoView({
                        behavior: "smooth",
                        block: "center",
                      }),
                    );
                  }}
                  extending={extending}
                  prefill={opening}
                  // Remounted when what is being decided changes, not only when
                  // a prefill arrives. Changing scope on a build-scoped screen
                  // is a parameter change rather than a navigation, so the form
                  // stayed mounted and kept the previous build's answers in its
                  // fields — an outcome and a justification about one variant,
                  // offered against another.
                  key={`${opened}:${product}:${stream}:${variant}:${vulnerability}:${component}:${version}`}
                />
              </div>
            )}
          </>
        )}
      </div>

      <div className="deciding">
        {/* Keyed on the issue in this product, so it is here whether or not
            anybody has decided anything. It sits above the claim's own thread
            because it is the one somebody can write in before there is a
            claim — which is what it exists for. The two stay apart: a claim is
            keyed on a place and a note on an issue, so they cannot become one
            record, and merging them would put text an approval never saw into
            the record an approval points at. */}
        <Notes
          product={product}
          vulnerability={vulnerability}
          mine={mine}
          undisclosed={!!it.undisclosed}
        />

        {/* Keyed on the claim, not on the row: the reasoning, the agreement
            and the conversation belong to the action that made the judgment. */}
        {pairs[0]?.claim.decision?.claim_id && (
          <>
            <Activity
              claimId={pairs[0].claim.decision.claim_id}
              claim={pairs[0].claim}
              places={pairs[0].summary?.places}
              previous={previous}
            />
            <Revisions claimId={pairs[0].claim.decision.claim_id} />
            <Comments
              claimId={pairs[0].claim.decision.claim_id}
              mine={mine}
              about={{ product, vulnerability }}
              undisclosed={!!it.undisclosed}
            />
          </>
        )}
        <Attachments about={{ product, vulnerability }} admin={!!who.data?.admin} />

        {/* Whether it has been announced, which decides which people the
            picker is allowed to offer. It was handed `recorded` — whether a
            person entered it rather than a scanner — so an embargoed finding
            a scanner reported offered readers of disclosed work, whom the
            server then refuses, and a disclosed flaw somebody recorded asked
            for undisclosed readers and came back empty to anybody holding
            only public triage. Two fields on one object, one letter apart in
            meaning. */}
        {/* Only where the triage pane is not drawn. There it sits at the head
            of the same pane, because triage is both questions — who is on it
            and what was decided. Here there is nothing left to decide, and
            reassigning a decided finding is still ordinary. */}
        {!undecided && (
          <Assignee
            at={at}
            assigned={it.assigned_to ?? ""}
            undisclosed={!!it.undisclosed}
            routedBy={it.routed_by ?? ""}
          />
        )}

        {/* Under triage, in a pane of its own. It is the longest block on the
            screen and among the least often read: somebody deciding wants what
            the issue is and what upstream did before they want the walk down
            to it. */}
        <div className="card">
          <Places places={places} build={build} version={it.version} />
        </div>

        {/* Who has been let into this one case. Only where it is
            undisclosed: on a public finding the grant means nothing, because
            everybody who reads the product already reads it. */}
        {it.undisclosed && <Collaborators product={product} vulnerability={vulnerability} />}

        {/* Who told us, where somebody outside did, and the names
            this issue answers to. Both are about a flaw recorded
            here rather than one a scanner reported. */}
        {it.recorded && <Reporter product={product} vulnerability={vulnerability} />}
        {!it.recorded && <Duplicates product={product} vulnerability={vulnerability} card />}

        {/* And which builds it affects, which the first belief about
            a flaw is often wrong about — that is the point of being able to
            record one before the analysis is finished. */}
        {it.recorded && <AffectedBuilds product={product} vulnerability={vulnerability} />}

        {it.recorded && <Resolve at={at} vulnerability={vulnerability} />}

        {previous.length > 0 && (
          <PreviousCard
            items={previous}
            at={at}
            undecided={undecided}
            onReuse={(reasoning, outcome, justification) => {
              startFrom({ reasoning, outcome, justification });
              // The form, by identity. A CSS selector matched the first card
              // inside the acting column, which is the standing claim's
              // wherever one stands — so the act filled the form in correctly
              // and scrolled somewhere above it, and on a long finding the
              // form the person is now meant to submit was off screen.
              form.current?.scrollIntoView({ behavior: "smooth", block: "start" });
            }}
          />
        )}
      </div>
    </>
  );
}
