import { type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Body } from "../api/client";
import { unwrap } from "../api/queries";
import { Editor, forget, mentioning } from "./Editor";
import { Failed } from "./Failed";
import { JUSTIFICATIONS, labeled, type Justification } from "./Outcome";
import { Covering, type Sitting } from "./Covering";
import { waitingFor } from "./awaiting";
import { nothingToReview } from "./reach";
import { Review, type Other, type Plan } from "./Review";
import { useWho } from "../app/session";
import { DECIDE_KEPT, keepAnswer, restoreAnswer } from "../app/drafts";

// One judgment about this finding. Outcome, the justification where it does
// not apply, a date where it is deferred, the reasoning, which places it
// covers, and — on submit — a guided review of where it applies beyond this
// build.
//
// The finding screen carries it and so does a row opened in the findings list,
// which is the same form in both: what a claim requires and what it writes do
// not change with where it is typed.

export type At = {
  product: string;
  stream: string;
  variant: string;
  vulnerability: string;
  component: string;
  version: string;
};

// The outcomes that may carry advice for a holder, and the ones that must.
//
// Two of them carry a mitigation and they ask for it differently. A claim that
// something already stops it *is* the mitigation, so it is required there. A
// claim that something will not be fixed is a standing property of a shipped
// feature — a protocol that cannot change without breaking what it is
// compatible with — and there is often a real answer and often none, so it is
// offered and optional.
//
// The second is what puts an affected statement in the published document,
// which is the only way such a flaw ever reaches a customer: no scan closes one
// and no advisory is issued about one. Without it the field was reachable by
// posting to the API by hand and by nothing on any screen.
export function mustMitigate(outcome: string, justification: string): boolean {
  return outcome === "not-applicable" && justification === "inline_mitigations_already_exist";
}

export function mayMitigate(outcome: string, justification: string): boolean {
  return mustMitigate(outcome, justification) || outcome === "wont-fix";
}

// The place the reasoning typed about one thing is kept.
//
// Every part of what is being decided, the version included. A build ships one
// name at more than one version often enough that leaving it out shares a
// draft between two of them: a justification typed about one version came back
// pre-filled against the other, which is different code at a different number
// of places — on the text a second person has to approve.
export function draftKeyFor(at: At): string {
  return (
    `decide:${at.product}:${at.stream}:${at.variant}:` +
    `${at.vulnerability}:${at.component}:${at.version}`
  );
}

// An outcome's name in a sentence about what happens next.
//
// A deferral and a dismissal both wait for a second person and are not the
// same act: one says "later" and the other says "no", and calling both a
// dismissal in the confirmation told somebody they had done a thing they had
// not.
export function said(outcome: string): string {
  switch (outcome) {
    case "deferred":
      return "deferral";
    case "affected":
      return "claim";
    case "already-fixed":
      return "claim that it is already fixed";
    case "patch-needed":
      return "promise to backport a fix";
    case "upgrade-needed":
      return "promise to upgrade the package";
    default:
      return "dismissal";
  }
}

export type Recorded = {
  claimId: number;
  recorded: number;
  covered: number;
  left: number;
  needsApproval: boolean;
  // The other builds the same judgment covered. Named rather than reported
  // on: it is one transaction, so there is no per-build outcome to have.
  applied: string[];
  matching: number;
  // The outcome recorded, so a confirmation can name it. Without this every
  // outcome that waits for a second person was called a dismissal, and a
  // deferral is not one — it says "later", not "no".
  outcome: string;
};

// The outcomes this form offers, which are not all of them: upgrading answers a
// component and everything open on it, so it is recorded from the component's
// own screen. The words come from the one map rather than being written here —
// this list had its own name for the backport answer, and every screen that
// read one back used the other, so somebody picked one word and was shown a
// different one.
//
// "patch-needed" is the answer a version comparison cannot see: the fix is
// carried in and the version stays where it was, so unless somebody can say so
// the row sits open with nothing true to say about it.
//
// Driven off the generated request type rather than retyped: the server
// generates these words from the domain vocabulary, and a third copy here is
// the shape that change removed from eight struct tags. Written as a record so
// the check runs both ways — a word the domain gains and this does not is a
// missing key, and a word this keeps after the domain drops it is an excess
// one. Both are compile errors rather than a screen offering something the
// route refuses.
type OneAtATime = Body<"FindingDecisionBody">["outcome"];

const OFFERS: Record<OneAtATime, true> = {
  affected: true,
  "not-applicable": true,
  deferred: true,
  "wont-fix": true,
  "already-fixed": true,
  "patch-needed": true,
};

// The order they are drawn in is this object's, which is its declaration
// order: what a person reads first is a decision about the screen rather than
// about the vocabulary.
const OFFERED = Object.keys(OFFERS) as OneAtATime[];

// The last pair somebody chose, for the session they are in.
//
// Offered, never applied. Somebody deciding a hundred findings in a day
// answers the same way for runs of them, and retyping the pair is the cost the
// review measured. But a judgment prefilled with the last one made is a record
// that can say something nobody meant — and this is the one form where that
// matters, since a dismissal hides risk and carries a name. So it is a button
// saying what it will fill in, and the fill is somebody's own click.
//
// Per session rather than remembered: what somebody was doing this morning is
// not what they are doing now, and a default that survives a night is a
// default nobody chose.
// The place the tab remembers the last judgment, to offer back. Named beside
// the
// sign-out clear that takes it away, so the two cannot drift apart.
const LAST = DECIDE_KEPT;

type Same = { outcome: string; justification: string };

function lastUsed(): Same | null {
  try {
    const kept = window.sessionStorage.getItem(LAST);
    if (!kept) return null;
    const said = JSON.parse(kept) as Same;
    return said.outcome ? said : null;
  } catch {
    return null;
  }
}

function rememberUsed(said: Same) {
  try {
    window.sessionStorage.setItem(LAST, JSON.stringify(said));
  } catch {
    // A browser that refuses storage loses a shortcut and nothing else.
  }
}

// The distance out to a date, in whole days from today. Rounded up, the way a
// person reads a calendar: a date tomorrow is one day out.
function deferredDays(until: string): number {
  const then = Date.parse(until + "T00:00:00Z");
  if (Number.isNaN(then)) return 0;
  return Math.max(0, Math.ceil((then - Date.now()) / 86_400_000));
}

export function Decide({
  at,
  places,
  onDone,
  extending,
  prefill,
  undisclosed,
  assigning,
}: {
  at: At;
  places: Sitting[];
  // The person dealing with it, drawn at the head of the same pane. Triage is
  // both questions: who is on it, and what was decided.
  assigning?: ReactNode;
  // The finding's disclosure, which decides who may be offered
  // after an @ in the reasoning: naming somebody who cannot read it calls them
  // to something they will be refused.
  undisclosed?: boolean;
  // Opened inside the findings list, where the keys are live and there is a
  // next row to go to.
  onDone: (recorded: Recorded) => void;
  // An approved claim this extends, where the backend offers one.
  extending?: { claimId: number; decisionId: number } | null;
  prefill?: {
    outcome?: string;
    justification?: string;
    reasoning?: string;
    // The length of the deferral it prepares, counted from whenever somebody
    // submits it. A saved rule means "put this off for a quarter" rather than
    // "until 3 March", so a date would be wrong the week after it was saved
    // and the days are turned into one here.
    deferDays?: number;
    // The VEX statement this was started from, cited so that a later revision
    // to it raises an alert. Never what the claim rests on.
    fromStatement?: number;
  } | null;
}) {
  // Read once, as the form is built. Every prefill is a fresh start rather than
  // a value merged into what is on screen — "start from this" means this and
  // not what somebody had half written — so the screen that offers one mounts
  // the form again, and the fields below seed themselves from it.
  const queries = useQueryClient();
  const draftKey = draftKeyFor(at);
  // The draft chosen here and not sent, read once as the form is built.
  //
  // A prefill wins over it, because a prefill is somebody pressing "start
  // from this" and a draft is what they left behind — an explicit choice beats
  // an interrupted one. Read once, like the prefill beside it: a value that
  // changed under somebody mid-decision is not the one they were answering.
  const [kept] = useState(() => (prefill ? {} : restoreAnswer(draftKey)));
  // Nothing chosen until somebody chooses. A form opening on "not applicable"
  // with a justification already selected puts every finding one click from a
  // dismissal — the outcome that hides risk and needs a second person,
  // offered as the default for the ordinary case.
  const [outcome, setOutcome] = useState(prefill?.outcome ?? kept.outcome ?? "");
  const [fixedVersion, setFixedVersion] = useState(kept.fixedVersion ?? "");
  // Likewise unchosen. A justification is a claim about our build that a
  // reader is entitled to take literally, so the first one in the list is not
  // an answer — it is whichever happened to be written first.
  const [justification, setJustification] = useState<Justification | "">(
    (prefill?.justification as Justification | undefined) ??
      (kept.justification as Justification | undefined) ??
      "",
  );
  const [mitigation, setMitigation] = useState(kept.mitigation ?? "");
  // Counted from now rather than from when the rule was saved, which is the
  // whole reason a prepared deferral is kept as a number of days. Without this
  // one opened the form with the outcome chosen and no date, which cannot be
  // submitted — a prefill that half-fires.
  const [until, setUntil] = useState(() => {
    if (!prefill?.deferDays) return kept.until ?? "";
    const day = new Date();
    day.setUTCDate(day.getUTCDate() + prefill.deferDays);
    return day.toISOString().slice(0, 10);
  });
  const [lands, setLands] = useState(kept.lands ?? "");
  // The deployment's deferral threshold, so the form can say which side of it
  // a date falls on while it is being chosen.
  const days = useWho().data?.deferral_days ?? null;
  // Read once when the form opens: it is a shortcut offered, and one that
  // changed under somebody mid-decision would be a different shortcut from
  // the one they read.
  const [same] = useState(lastUsed);
  const [reasoning, setReasoning] = useState(prefill?.reasoning ?? "");
  const [excluded, setExcluded] = useState<Set<string>>(() => new Set());
  const [reviewing, setReviewing] = useState(false);

  // Written as it is chosen, beside the prose the editor is already keeping.
  // A draft that keeps three paragraphs and loses what they argued for is one
  // somebody has to read to find out what they meant.
  useEffect(() => {
    keepAnswer(draftKey, { outcome, justification, until, fixedVersion, mitigation, lands });
  }, [draftKey, outcome, justification, until, fixedVersion, mitigation, lands]);

  const open = useMemo(() => places.filter((p) => p.decision == null), [places]);
  const answered = places.length - open.length;
  const covering = open.filter((p) => !excluded.has(p.place ?? ""));
  const needsJustification = outcome === "not-applicable";
  const needsDate = outcome === "deferred";
  // A claim that the fix is already here is a fact somebody can check against
  // whoever packages the component, and it is required for that reason . The
  // server refuses it empty; asking here means the person finds out while they
  // are still looking at the tracker.
  const needsFixedVersion = outcome === "already-fixed";
  // A promise with no date is what leaving the finding alone already says, so
  // the date is what makes it a claim at all.
  const needsLanding = outcome === "patch-needed";
  // Ctrl or ⌘ with Enter, anywhere in the form. Only when it is ready, so the
  // shortcut cannot submit something the button would refuse.
  //
  // Through refs rather than by re-binding on every keystroke: the listener is
  // one, and what it reads is whatever the form says at the moment it fires.
  const readyRef = useRef(false);
  const startRef = useRef(() => {});
  useEffect(() => {
    function pressed(event: KeyboardEvent) {
      if (event.key !== "Enter" || !(event.ctrlKey || event.metaKey)) return;
      if (!readyRef.current) return;
      event.preventDefault();
      startRef.current();
    }
    document.addEventListener("keydown", pressed);
    return () => document.removeEventListener("keydown", pressed);
  }, []);

  const needsMitigation = mustMitigate(outcome, justification);
  const offerMitigation = mayMitigate(outcome, justification);

  // A judgment's reach beyond this build, answered whole by the
  // server rather than sampled here.
  //
  // Asked per place and sampled — a kernel flaw sits at sixty places, and
  // that is sixty requests from one screen — the answer is not only shown:
  // the builds at differing versions become the ones offered to include, and
  // what is offered is what gets written. A build reachable only from a place
  // past the sample is then never offered and the judgment silently does not
  // travel there, which is a cost control on the interface turned into a rule
  // about what a decision covers.
  const reach = useQuery({
    queryKey: [
      "reach",
      at.product,
      at.stream,
      at.variant,
      at.vulnerability,
      at.component,
      at.version ?? "",
    ],
    queryFn: async () =>
      unwrap(
        await api.GET(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/findings/{vulnerability}/components/{component}/reach",
          {
            params: {
              path: {
                product: at.product,
                stream: at.stream,
                variant: at.variant,
                vulnerability: at.vulnerability,
                component: at.component,
              },
              query: at.version ? { version: at.version } : {},
            },
          },
        ),
      ),
    staleTime: 60_000,
  });

  const { matching, offered } = useMemo(() => {
    const auto = new Map<string, true>();
    const diff = new Map<string, Other>();
    const differing = new Set<string>();
    {
      for (const m of reach.data?.automatic ?? []) auto.set(`${m.stream} · ${m.variant}`, true);
      for (const m of reach.data?.differing ?? []) {
        // Its place, said as an aside. The subject of the question is the
        // version — a build at matching versions never reaches this list — so
        // "this build" is the honest label for another version sitting beside
        // the one in hand, rather than the build's own name repeated back.
        const build = m.here ? "this build" : `${m.stream} · ${m.variant}`;
        // One question per version, not one per build: a build carrying the
        // component at four versions is four claims about different code, and
        // each is posted with its own version.
        const key = `${build} @ ${m.version ?? ""}`;
        const had = diff.get(key);
        differing.add(build);
        diff.set(key, {
          key,
          build,
          stream: m.stream ?? "",
          variant: m.variant ?? "",
          version: m.version ?? "",
          places: (had?.places ?? 0) + (m.places ?? 0),
          note: "The same issue at another version. Check the reasoning still holds there.",
          tone: "warn",
        });
      }
    }
    for (const build of differing) auto.delete(build);
    return {
      matching: [...auto.keys()].sort(),
      offered: [...diff.values()].sort((a, b) => a.key.localeCompare(b.key)),
    };
  }, [reach.data]);

  // The answers still missing, which are both what the form says and what
  // stops it being submitted. Two lists of the same conditions is how one of
  // them comes to hold a question the other does not.
  const waiting = waitingFor({
    outcome,
    needsJustification,
    justification,
    needsMitigation,
    mitigation,
    needsFixedVersion,
    fixedVersion,
    needsLanding,
    lands,
    needsDate,
    until,
    reasoning,
    covering: covering.length,
  });
  const ready = waiting === null;

  function body() {
    return {
      outcome: outcome as OneAtATime,
      // Narrowed rather than asserted: submit is disabled until one is
      // chosen, so the empty case cannot reach here.
      ...(needsJustification && justification !== "" ? { justification } : {}),
      ...(offerMitigation && mitigation.trim() !== "" ? { mitigation } : {}),
      ...(needsDate ? { deferred_until: until } : {}),
      ...(needsFixedVersion ? { fixed_version: fixedVersion.trim() } : {}),
      ...(needsLanding ? { committed_to: lands } : {}),
      reasoning,
      ...(excluded.size > 0 ? { places: covering.map((p) => p.place) } : {}),
      ...(extending ? { extends: extending.claimId } : {}),
      ...(prefill?.fromStatement ? { from_statement: prefill.fromStatement } : {}),
    };
  }

  const submit = useMutation({
    mutationFn: async (applied: Other[]): Promise<Recorded> => {
      // One request and one transaction, however many builds it reaches. Sent
      // a build at a time, a refusal part-way left the judgment recorded in
      // some releases and not others — an act nobody performed.
      const here = unwrap(
        await api.POST(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/findings/{vulnerability}/components/{component}/decision",
          {
            params: {
              path: {
                product: at.product,
                stream: at.stream,
                variant: at.variant,
                vulnerability: at.vulnerability,
                component: at.component,
              },
              query: at.version ? { version: at.version } : {},
            },
            body: {
              ...body(),
              // The version the reach named, because the other build may ship
              // this component at several and a name alone is a refusal there.
              ...(applied.length > 0
                ? {
                    also: applied.map((other) => ({
                      stream: other.stream,
                      variant: other.variant,
                      ...(other.version ? { version: other.version } : {}),
                    })),
                  }
                : {}),
            },
          },
        ),
      );
      return {
        claimId: here.claim_id,
        recorded: here.recorded,
        covered: here.covered,
        left: here.left,
        needsApproval: here.needs_approval,
        applied: applied.map((other) =>
          other.version ? `${other.build} at ${other.version}` : other.build,
        ),
        matching: matching.length,
        outcome,
      };
    },
    onSuccess: (recorded) => {
      // The choice, kept for the next one — offered there and never applied.
      rememberUsed({ outcome, justification });
      forget(draftKey);
      setReviewing(false);
      void queries.invalidateQueries({ queryKey: ["finding"] });
      void queries.invalidateQueries({ queryKey: ["findings"] });
      void queries.invalidateQueries({ queryKey: ["queue"] });
      void queries.invalidateQueries({ queryKey: ["home"] });
      onDone(recorded);
    },
  });

  readyRef.current = ready;
  startRef.current = start;

  function start() {
    // With the reach known and empty the sheet asks nothing, so the
    // decision goes straight through. What it would have said is still said
    // afterwards: the confirmation names the builds reached by lookup and the
    // places written.
    if (nothingToReview(reach, offered)) {
      submit.mutate([]);
      return;
    }
    setReviewing(true);
  }

  if (open.length === 0) {
    return (
      <div className="card">
        <div>
          <h3 style={{ margin: "0 0 6px" }}>Decision</h3>
          <p className="reading">Every place has been decided. Revise from the claim itself.</p>
        </div>
      </div>
    );
  }

  const form = (
    <div>
      {answered > 0 && (
        <p className="hint" style={{ margin: "-4px 0 12px" }}>
          {answered} of {places.length} places already decided. This covers what is left.
        </p>
      )}
      {extending && (
        <div className="alert info" style={{ marginBottom: 12 }}>
          <strong>Extends decision #{extending.decisionId}</strong>
          <span>The same argument, already read. Still needs a second person.</span>
        </div>
      )}

      <div className="field">
        <label>Outcome</label>
        <div className="outcomes">
          {OFFERED.map((each) => (
            <button
              key={each}
              type="button"
              className="outcome"
              aria-pressed={outcome === each}
              onClick={() => setOutcome(each)}
            >
              {labeled(each)}
            </button>
          ))}
        </div>
        {/* The pair last recorded in this session, offered as a click rather
            than filled in. Somebody deciding a hundred findings answers the
            same way for runs of them, and retyping the pair is the cost; but
            a judgment prefilled with the last one made is a record that can
            say what nobody meant, and this is the form where that matters. */}
        {same && same.outcome !== outcome && (
          <p className="hint" style={{ marginTop: 6 }}>
            <button
              type="button"
              className="linkish"
              onClick={() => {
                setOutcome(same.outcome);
                setJustification((same.justification || "") as Justification | "");
              }}
            >
              Same as last time
            </button>{" "}
            — {labeled(same.outcome)}
            {same.justification ? ` · ${same.justification.replaceAll("_", " ")}` : ""}
          </p>
        )}
      </div>

      {needsJustification && (
        <div className="field">
          <label htmlFor={`${draftKey}-just`}>Justification</label>
          <select
            id={`${draftKey}-just`}
            value={justification}
            onChange={(event) => setJustification(event.target.value as Justification)}
          >
            {/* An unchosen state, so the first justification in the list is
                not offered as an answer. Each is a claim about our build that
                a reader takes literally, and which one was written first says
                nothing about which is true here. */}
            <option value="">Say which…</option>
            {/* The label and what it claims, because the choice made here is
                what ships to a customer as our claim about their exposure
. The token itself is on the title, for whoever is
                checking what will be exported. */}
            {JUSTIFICATIONS.map((each) => (
              <option key={each.value} value={each.value} title={each.value}>
                {each.label} — {each.means}
              </option>
            ))}
          </select>
        </div>
      )}

      {offerMitigation && (
        <div className="field">
          <label htmlFor={`${draftKey}-mit`}>
            {needsMitigation ? "The mitigation" : "Advice for customers"}
          </label>
          <input
            id={`${draftKey}-mit`}
            type="text"
            value={mitigation}
            placeholder={
              needsMitigation
                ? "the firewall rule, the setting, the service that is not exposed"
                : "use SSH, or reach it from the management VLAN only"
            }
            onChange={(event) => setMitigation(event.target.value)}
          />
          <span className="hint">
            {needsMitigation
              ? "Nothing watches configuration, so this will not lapse if the mitigation is removed. Say what to check."
              : "Optional. Where you say one, customers are told this is present and staying and what they can do about it. Where you do not, they are told nothing."}
          </span>
        </div>
      )}

      {needsFixedVersion && (
        <div className="field">
          <label htmlFor={`${draftKey}-fixed`}>Fixed in</label>
          <input
            id={`${draftKey}-fixed`}
            type="text"
            value={fixedVersion}
            placeholder="the package version the fix arrived in, as the packager writes it"
            onChange={(event) => setFixedVersion(event.target.value)}
          />
          <span className="hint">
            Backported fixes do not move the upstream version, so nothing here sees them. Recorded
            and never compared against the version shipping.
          </span>
        </div>
      )}

      {needsLanding && (
        <div className="field">
          <label htmlFor={`${draftKey}-lands`}>Lands on</label>
          <input
            id={`${draftKey}-lands`}
            type="date"
            value={lands}
            style={{ width: 180 }}
            onChange={(event) => setLands(event.target.value)}
          />
          <span className="hint">
            When the patch lands. On or before the earliest deadline this covers, nobody else is
            needed.
          </span>
        </div>
      )}

      {needsDate && (
        <div className="field">
          <label htmlFor={`${draftKey}-until`}>Until</label>
          <input
            id={`${draftKey}-until`}
            type="date"
            value={until}
            style={{ width: 180 }}
            onChange={(event) => setUntil(event.target.value)}
          />
          {/* The threshold as a number, before the date is written rather
              than after it is submitted. Which side of it a date falls on
              changes what somebody is about to do, and reading it off the
              response is reading it too late. */}
          <span className="hint">
            {days === null
              ? "Under the deferral threshold, no approval is needed; over it, a second person."
              : until === ""
                ? `Up to ${days} days needs nobody; longer waits for a second person.`
                : deferredDays(until) > days
                  ? `That is ${deferredDays(until)} days out, past the ${days}-day threshold: ` +
                    "it waits for a second person."
                  : `That is ${deferredDays(until)} days out, inside the ${days}-day threshold: ` +
                    "it stands on its own."}
          </span>
        </div>
      )}

      <div className="field" style={{ margin: 0 }}>
        <label>Reasoning</label>
        <Editor
          value={reasoning}
          onChange={setReasoning}
          draftKey={draftKey}
          label="Reasoning"
          mentions={mentioning(at.product, undisclosed)}
          attachTo={{ product: at.product, vulnerability: at.vulnerability }}
          placeholder="The reasoning this decision holds on, and what to re-check later."
        />
      </div>

      {submit.error != null && <Failed error={submit.error} what="That could not be recorded." />}

      <div className="actions" style={{ marginTop: 12 }}>
        <button type="button" className="btn" disabled={!ready || submit.isPending} onClick={start}>
          Submit decision
        </button>
        {/* What it is waiting for, beside the control that is waiting. A
            disabled button says that something is missing and never which,
            and the shortcut below it does nothing at all until the same
            question is answered. */}
        {waiting ? (
          <span className="hint" role="status">
            {waiting}
          </span>
        ) : (
          <span className="hint">
            {/* Advertised rather than left to be discovered. Somebody doing a
                hundred of these a day is the person it is for, and a shortcut
                nobody knows about is a shortcut nobody has. */}
            or press <kbd>Ctrl</kbd>+<kbd>Enter</kbd>
          </span>
        )}
      </div>
    </div>
  );

  const plan: Plan = {
    build: `${at.product} · ${at.stream} · ${at.variant}`,
    covered: covering.length,
    total: open.length,
    matching,
    offered,
    reasoning,
    versionHere: at.version,
  };

  const aside = (
    <aside style={{ alignSelf: "start", display: "flex", flexDirection: "column", gap: 10 }}>
      <Covering
        places={open}
        excluded={excluded}
        onChange={setExcluded}
        matching={matching.length}
        differing={offered.length}
      />
      <div className="tier auto" style={{ margin: 0 }}>
        <p className="said">
          {outcome === "affected"
            ? "No approval needed. Goes to remediation."
            : outcome === "deferred"
              ? days === null || until === ""
                ? "Under the threshold this stands alone. Over it, a second person."
                : deferredDays(until) > days
                  ? `${deferredDays(until)} days is past the ${days}-day threshold, so a second ` +
                    "person has to agree."
                  : `${deferredDays(until)} days is inside the ${days}-day threshold, so this ` +
                    "stands on its own."
              : "Dismissals take effect only after a second person approves."}
        </p>
      </div>
    </aside>
  );

  return (
    <>
      {
        <div className="card">
          <h3>Triage</h3>
          {assigning}
          {/* The pane is named for both questions, so the box somebody types
              a judgment into carries its own name. */}
          <h4 className="deciding-head">Decision</h4>
          <div className="writing">
            {form}
            {aside}
          </div>
        </div>
      }
      <Review
        open={reviewing}
        plan={plan}
        busy={submit.isPending}
        error={submit.error}
        onCancel={() => setReviewing(false)}
        onConfirm={(applied) => submit.mutate(applied)}
      />
    </>
  );
}
