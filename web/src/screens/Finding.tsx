import {
  Activity,
  Comments,
  PreviousCard,
  RATINGS,
  Revisions,
  Standing,
  stateOf,
  type Previous,
} from "./FindingClaim";
import { FixingIn, HowMatched, LookItUp, Places, References, WhoTold } from "./FindingEvidence";
import { Assignee, Attachments, Collaborators, Marks, Resolve } from "./FindingPeople";
import { useMemo, useState } from "react";
import { Loading } from "../ui/Loading";
import { on } from "../ui/when";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, type Body } from "../api/client";
import { at as choicesAt, unwrap } from "../api/queries";
import { useWho } from "../app/session";
import { Failed } from "../ui/Failed";
import { Severity, Exploited } from "../ui/Severity";
import { AffectedBuilds } from "./FindingBuilds";
import { Markdown } from "../ui/Markdown";
import { Decide, said, type Recorded } from "../ui/Decide";
import { Because } from "../ui/Outcome";
import { fromAt, listQuery, pathTo, where, windowFor } from "./list";

// One finding: what the issue is, how bad, what upstream has done, where it
// sits, the evidence — and the working screen for deciding it, before and
// after. When a claim stands it is shown in its state, with one activity
// timeline, the revision history, the comments, and the decisions made at this
// place before, whose reasoning is offered back.

type Detail = Body<"DecisionDetail">;

// What a step lands on, said in the hover rather than on the button: the
// button says which direction, and which finding is what somebody checks
// before taking it.
function neighborly(step: { row: { vulnerability?: string; component?: string } }): string {
  return `${step.row.vulnerability ?? ""} in ${step.row.component ?? ""}`;
}

type Similar = Body<"SimilarBody">;

// How many of the finding's places are asked which decision stood there
// before. The finding carries the earlier decisions themselves; what it does
// not carry is which place each was at, and reaffirming one needs the place.
const SAMPLE = 8;

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
  const [prefill, setPrefill] = useState<{
    outcome?: string;
    justification?: string;
    reasoning?: string;
    // Cited, never applied: what a VEX document said is not this claim, and
    // this is what lets a later revision to it be noticed.
    fromStatement?: number;
  } | null>(null);
  const [extending, setExtending] = useState<{ claimId: number; decisionId: number } | null>(null);

  const list = useMemo(() => new URLSearchParams(from), [from]);
  const listed = useMemo(() => listQuery(list), [list]);
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
        ),
      };
    }
    return {
      at: span.offset + i,
      total: neighbors.data?.total ?? 0,
      previous: step(i - 1),
      next: step(i + 1),
    };
  }, [neighbors.data, span, listed.limit, list, from, product, vulnerability, component, version]);

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
  // Which place each earlier decision was at, for reaffirming it.
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
          <h3>Which {component}?</h3>
          <p className="reading" style={{ marginBottom: 10 }}>
            This build ships that name at more than one version. Pick the one you mean.
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

  const claims = standing.map((q) => q.data).filter((d): d is Detail => !!d);
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
    proposedBy: p.proposed_by,
    proposedAt: p.proposed_at,
    state: p.ended,
    endedAt: p.ended_at ?? "",
    about: p.about ?? "",
    approvedBy: p.approved_by ?? "",
    reasoning: p.reasoning,
    place: placeOf.get(p.decision_id) ?? "",
  }));
  const similar: Similar[] = it.similar ?? [];
  // What VEX documents say: a third layer beside what the build claims and
  // what we decided. Shown, offered as a prefill, never applied.
  const vex = it.vex ?? [];

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
  const mine = (proposedBy: string) =>
    !!who.data && (proposedBy === who.data.identity || proposedBy === who.data.name);

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
          <span className="id">{it.vulnerability}</span> in{" "}
          <span className="id">{it.component}</span> <Severity word={it.assessed || it.severity} />{" "}
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
            // Said rather than left blank: there are exactly two reasons and
            // both are deliberate, so an empty cell would read as missing data
            // on the row somebody is deciding about.
            <>
              No deadline —{" "}
              {it.no_deadline === "below-the-line"
                ? "below what this product triages at. Recorded and counted; nothing is late."
                : "the release is past its end of life, so nothing here will be fixed."}
            </>
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
          mayMark={!!who.data?.reach.find((r) => r.product === product)?.may_triage}
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
        <div className="alert info" style={{ marginBottom: 14 }}>
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
            <h4>Short bumps</h4>
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
              , so the bump could not have resolved it. The old reasoning probably still stands, and
              somebody's remediation did not land.
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
          holder, the fix targets, the assessment and the similar
          decisions — about 1,550 pixels down a page running to 2,800, so
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
            <div className="score">
              <span className="n">{it.score ? it.score.toFixed(1) : "—"}</span>
              <span className="l">CVSS</span>
            </div>
            <div className="score">
              <span className="n">
                {typeof it.likelihood === "number" ? it.likelihood.toFixed(3) : "—"}
              </span>
              <span className="l">EPSS</span>
            </div>
            <div className="score">
              <span className="n">{(it.weaknesses ?? [])[0] ?? "—"}</span>
              <span className="l">Weakness</span>
            </div>
            <div className="score">
              <span className="n">{it.exploited ? "Yes" : "No"}</span>
              <span className="l">Exploited</span>
            </div>
          </div>
          {it.vector && (
            <p className="mono" style={{ fontSize: "var(--step--1)", color: "var(--muted)" }}>
              {it.vector}
            </p>
          )}
          <p className="hint">
            {it.assessed ? (
              <>
                Assessed <Severity word={it.assessed} /> · published <Severity word={it.severity} />
                . The assessment orders it and sets its deadline.
              </>
            ) : (
              <>
                Published <Severity word={it.severity} />. Being exploited outranks the score.
              </>
            )}
          </p>
        </div>

        <HowMatched
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
            <h4>Scanner</h4>
            <p>
              {it.opened && (
                <>
                  First seen here <b>{it.opened}</b>
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
            <p className="hint" style={{ margin: 0 }}>
              {it.found_by
                ? "The run that first said this, not the newest one — a later run finding the same thing does not reopen it. Which vulnerability database was in force is what a corrected feed makes worth having."
                : "Recorded here by a person rather than reported by a scanner, so no run found it."}
            </p>
          </div>
        )}

        <Places places={places} build={build} />

        {(it.aliases ?? []).length > 0 && (
          <div className="evblock">
            <h4>Aliases</h4>
            <p className="id">{(it.aliases ?? []).join(" · ")}</p>
          </div>
        )}
      </div>

      <div className="acting">
        {claims.map((claim, i) => (
          <Standing
            key={claim.decision?.id}
            claim={claim}
            summary={it.standing?.[i]}
            places={places}
            mine={mine(claim.proposed_by ?? "")}
            mayApprove={!!who.data?.reach.find((r) => r.product === product)?.may_agree}
            onRevised={() => void finding.refetch()}
            about={{ product, vulnerability }}
          />
        ))}

        {places.some((p) => p.decision == null) && (
          <>
            {/* Said when there is nothing, because the difference matters:
                an empty panel reads as "nobody has an opinion about this",
                and what it actually means is that no document saying so has
                been uploaded here. The layer is fed only by uploads
 — nothing derives it, and a distribution's
                will-not-fix arrives through the scanner as an upstream fix
                status instead. */}
            {vex.length === 0 && (
              <div className="card">
                <h3>VEX statements</h3>
                <p className="reading">
                  None. No VEX document uploaded here mentions this issue at this component — which
                  is not the same as nobody having published one. An administrator uploads them;
                  nothing here fetches them.
                </p>
              </div>
            )}

            {vex.length > 0 && (
              <div className="card">
                <h3>VEX statements</h3>
                <p className="reading" style={{ marginBottom: 8 }}>
                  From a VEX document somebody uploaded here, published by a distribution or an
                  upstream security team about this component. It is evidence and nothing more — it
                  decides nothing here, and it is not counted anywhere. What it adds over the scan
                  is the reasoning.
                </p>
                {vex.map((one, i) => (
                  <div key={`${one.publisher} ${i}`} className="prior">
                    <header>
                      <span className="id">{one.publisher}</span>{" "}
                      <span className="hint">
                        says <b>{(one.status ?? "").replace("_", " ")}</b>
                        {one.justification && <> · {one.justification.replaceAll("_", " ")}</>}
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
                    {one.offers && decided < places.length && (
                      <div className="actions">
                        <button
                          type="button"
                          className="btn ghost"
                          onClick={() =>
                            setPrefill({
                              fromStatement: one.id,
                              outcome: one.offers as string,
                              justification:
                                one.offers === "not-applicable" ? (one.justification ?? "") : "",
                              reasoning:
                                `${one.publisher} says ${(one.status ?? "").replace("_", " ")}` +
                                (one.statement ? `: ${one.statement}` : "") +
                                "\n\n",
                            })
                          }
                        >
                          Start from this
                        </button>
                        <span className="hint">
                          Fills the form in. The judgment is still yours, and the record says you
                          made it.
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
                  The same component under the same consumer, with the same justification. Applying
                  one extends its argument to this issue; it still needs a second person.
                </p>
                {similar.map((s) => (
                  <div key={s.decision_id} className="prior">
                    <header>
                      <span className="id">#{s.decision_id}</span>{" "}
                      <Because code={s.justification} />
                      <span className="hint">
                        approved by {s.approved_by}
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
                          setPrefill({
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
            <Decide
              at={{ ...at, version }}
              places={places}
              onDone={(r) => {
                setRecorded(r);
                setPrefill(null);
                setExtending(null);
              }}
              extending={extending}
              prefill={prefill}
            />
          </>
        )}
      </div>

      <div className="deciding">
        {/* Eleven links between the facts and the form is the defect the old
            layout was built to fix, arriving by a different route — so what
            is read elsewhere is read below the act rather than beside it. */}
        <div className="evidence">
          <References advisory={it.advisory} refs={it.references ?? []} />
          <LookItUp links={it.links ?? []} />
        </div>

        {/* Keyed on the claim, not on the row: the reasoning, the agreement
            and the conversation belong to the action that made the judgment. */}
        {claims.length > 0 && claims[0]?.decision?.claim_id && (
          <>
            <Activity
              claimId={claims[0].decision.claim_id}
              claim={claims[0]}
              places={it.standing?.[0]?.places}
              previous={previous}
            />
            <Revisions claimId={claims[0].decision.claim_id} />
            <Comments
              claimId={claims[0].decision.claim_id}
              mine={mine}
              about={{ product, vulnerability }}
            />
          </>
        )}
        <Attachments about={{ product, vulnerability }} admin={!!who.data?.admin} />

        <Assignee
          at={at}
          assigned={it.assigned_to ?? ""}
          undisclosed={!!it.recorded}
          routedBy={it.routed_by ?? ""}
        />

        {/* Who has been let into this one case. Only where it is
            undisclosed: on a public finding the grant means nothing, because
            everybody who reads the product already reads it. */}
        {it.undisclosed && <Collaborators product={product} vulnerability={vulnerability} />}

        {/* Who told us, where somebody outside did, and the names
            this issue answers to. Both are about a flaw recorded
            here rather than one a scanner reported. */}
        {it.recorded && <WhoTold product={product} vulnerability={vulnerability} />}

        {/* And which builds it affects, which the first belief about
            a flaw is often wrong about — that is the point of being able to
            record one before the analysis is finished. */}
        {it.recorded && <AffectedBuilds product={product} vulnerability={vulnerability} />}

        {it.recorded && <Resolve at={at} vulnerability={vulnerability} />}

        <FixingIn at={at} />

        {places.some((p) => p.decision == null) && (
          <Assess
            vulnerability={vulnerability}
            published={it.severity ?? ""}
            assessed={it.assessed ?? ""}
          />
        )}

        {previous.length > 0 && (
          <PreviousCard
            items={previous}
            at={at}
            undecided={places.some((p) => p.decision == null)}
            onReuse={(reasoning, outcome, justification) => {
              setPrefill({ reasoning, outcome, justification });
              document
                .querySelector(".acting .card")
                ?.scrollIntoView({ behavior: "smooth", block: "start" });
            }}
          />
        )}
      </div>
    </>
  );
}

// What we think of the issue itself, as against what was published. About the
// issue rather than where it sits, so it holds wherever the issue appears ;
// rating it milder waits for a second person.
function Assess({
  vulnerability,
  published,
  assessed,
}: {
  vulnerability: string;
  published: string;
  assessed: string;
}) {
  const queries = useQueryClient();
  const [open, setOpen] = useState(false);
  const [severity, setSeverity] = useState<string>(published || "medium");
  const [reasoning, setReasoning] = useState("");

  const assess = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/issues/{vulnerability}/assessment", {
          params: { path: { vulnerability } },
          body: { severity: severity as (typeof RATINGS)[number], reasoning },
        }),
      ),
    onSuccess: () => {
      setOpen(false);
      setReasoning("");
      void queries.invalidateQueries({ queryKey: ["finding"] });
    },
  });

  const milder =
    RATINGS.indexOf(severity as (typeof RATINGS)[number]) <
    RATINGS.indexOf((published || "medium") as (typeof RATINGS)[number]);

  if (assessed) {
    return (
      <div className="assess">
        <h3>Issue assessment</h3>
        <p className="reading" style={{ margin: 0 }}>
          Assessed <Severity word={assessed} />, published <Severity word={published} />. The
          assessment orders it and sets its deadline everywhere this issue appears.
        </p>
      </div>
    );
  }

  if (!open) {
    return (
      <div className="assess">
        <h3>Issue assessment</h3>
        <p className="reading" style={{ margin: "0 0 8px" }}>
          Published as <Severity word={published} />. A rating of ours holds wherever the issue
          appears.
        </p>
        <button type="button" className="linkish" onClick={() => setOpen(true)}>
          Rate it differently
        </button>
      </div>
    );
  }

  return (
    <div className="assess">
      <h3>Issue assessment</h3>
      {assess.error != null && <Failed error={assess.error} what="That could not be recorded." />}
      <div className="ourview">
        <div className="pair">
          <span className="l">Published</span>
          <span className="theirs">{published || "unrated"}</span>
        </div>
        <div className="field" style={{ margin: 0 }}>
          <label htmlFor="rating">Assessed</label>
          <select
            id="rating"
            value={severity}
            style={{ width: "auto" }}
            onChange={(event) => setSeverity(event.target.value)}
          >
            {RATINGS.map((each) => (
              <option key={each} value={each}>
                {each}
              </option>
            ))}
          </select>
        </div>
      </div>
      <p className="hint" style={{ margin: "0 0 8px" }}>
        {milder
          ? "Milder than published, so a second person has to agree before it takes effect."
          : "At or above what was published, so it takes effect at once."}
      </p>
      <div className="field" style={{ marginBottom: 8, maxWidth: "78ch" }}>
        <label htmlFor="why">Reasoning</label>
        <textarea
          id="why"
          style={{ minHeight: 64 }}
          value={reasoning}
          placeholder="What makes the published rating wrong for this issue, anywhere it appears?"
          onChange={(event) => setReasoning(event.target.value)}
        />
      </div>
      <div className="actions">
        <button
          type="button"
          className="btn"
          disabled={reasoning.trim() === "" || assess.isPending}
          onClick={() => assess.mutate()}
        >
          Save assessment
        </button>
        <button type="button" className="btn quiet" onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
    </div>
  );
}
