// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { mayOf, useWho } from "../app/session";
import {
  useDecideLead,
  useEscalateLead,
  useFixLead,
  useLead,
  type Evidence,
  type LeadOutcome,
  type LeadPlace,
  type LeadReason,
} from "../api/leads";
import { claimAt, leadAt, leadsAt, type Build } from "../app/routes";
import { ChoiceCards } from "../ui/ChoiceCards";
import { Editor } from "../ui/Editor";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { labeled } from "../ui/Outcome";
import { linkable } from "../ui/addressable";
import { on } from "../ui/when";
import { LEAD_OUTCOMES, LEAD_REASONS, LEAD_TONES, located, reasonSaid, stateSaid } from "./leads";
import { Handoff } from "./LeadHandoff";

// One lead on one build: what the analyzer said, the path it took, the leads
// that are the same flaw, and where the lead stands. Somebody who triages
// internal material judges it here, pulls it out of the baseline, or closes it
// as fixed once a run no longer sees it, and hands a confirmed one off as a
// flaw.
export function Lead() {
  const { product = "", stream = "", variant = "", place = "" } = useParams();
  const build: Build = { product, stream, variant };
  const lead = useLead(build, place);
  const may = mayOf(useWho().data, product);
  const triages = !!may?.triages_internal;
  const handsOff = triages && !!may?.may_hide;

  if (lead.isPending) return <Loading />;
  if (lead.isError) return <Failed error={lead.error} what="The lead could not be read." />;
  const evidence = lead.data;
  const at = evidence.at;
  // A lead seen only in releases past their end of life is kept as it stands.
  // A move of one already handed off concerns its flaw, and stays offered.
  const ended = !!evidence.past_end_of_life;
  const acts = triages && !ended;

  return (
    <div>
      <div className="screen-head">
        <h2 className="mono">{evidence.rule}</h2>
        <p>
          <span className="mono">{located(at.path, at.start_line)}</span> ·{" "}
          <Link to={leadsAt(product, { stream, variant })}>
            {product} · {stream} · {variant}
          </Link>{" "}
          <span className={`state ${LEAD_TONES[evidence.state]}`}>{stateSaid(evidence.state)}</span>
          {ended && <span className="state closed"> Past end of life</span>}
        </p>
      </div>

      <div className="card">
        <h3>Result</h3>
        <Place place={at} />
        {evidence.withheld && (
          <p className="hint">Part of a case you are not on. Only where it is is shown.</p>
        )}
        <p className="hint">
          Last seen {on(evidence.last_seen)}
          {evidence.not_seen && ` · not seen ${on(evidence.not_seen)}`}
          {evidence.unchanged && " · the code did not change between those builds"}
          {linkable(evidence.compare) && (
            <>
              {" · "}
              <a href={linkable(evidence.compare) ?? undefined} target="_blank" rel="noreferrer">
                Compare builds
              </a>
            </>
          )}
        </p>
      </div>

      {(evidence.steps ?? []).length > 0 && (
        <div className="card">
          <h3>Path</h3>
          <ol>
            {(evidence.steps ?? []).map((step, i) => (
              <li key={i} style={{ marginLeft: (step.depth ?? 0) * 12 }}>
                <Place place={step} />
              </li>
            ))}
          </ol>
        </div>
      )}

      {(evidence.related ?? []).length > 0 && (
        <div className="card">
          <h3>Related locations</h3>
          <ul>
            {(evidence.related ?? []).map((related, i) => (
              <li key={i}>
                <Place place={related} />
              </li>
            ))}
          </ul>
        </div>
      )}

      <Kin build={build} evidence={evidence} />

      <Handoff
        build={build}
        place={place}
        evidence={evidence}
        handsOff={handsOff && (!ended || evidence.state === "handed-off")}
      />

      {!evidence.withheld && evidence.state !== "handed-off" && (
        <div className="card">
          <h3>Decision</h3>
          {evidence.decision ? (
            <p>
              {labeled(evidence.decision.outcome)}
              {evidence.decision.reason && ` · ${reasonSaid(evidence.decision.reason)}`}
              {evidence.decision.needs_approval && evidence.decision.state === "proposed" && (
                <span className="state waiting"> Waiting for approval</span>
              )}{" "}
              {evidence.decision.claim_id !== undefined && (
                <Link to={claimAt(evidence.decision.claim_id)}>
                  Claim {evidence.decision.claim_id}
                </Link>
              )}
            </p>
          ) : acts && evidence.open ? (
            <DecideForm build={build} place={place} />
          ) : (
            <p className="hint">None.</p>
          )}
          {acts && evidence.state === "baseline" && <Escalate product={product} place={place} />}
          {acts && evidence.state === "not-reproduced" && evidence.open && (
            <FixForm build={build} place={place} />
          )}
        </div>
      )}
    </div>
  );
}

// One place the analyzer named: where, what it said there, and the code.
function Place({ place }: { place: LeadPlace }) {
  const href = linkable(place.link);
  const where = located(place.path, place.start_line);
  return (
    <div>
      <div>
        {href ? (
          <a className="mono" href={href} target="_blank" rel="noreferrer" title={place.revision}>
            {where}
          </a>
        ) : (
          <span className="mono" title={place.unlinked}>
            {where}
          </span>
        )}
        {place.function && <span className="hint"> in {place.function}</span>}
        {place.approximate && (
          <span className="hint" title="The line is where the code was, not where it is.">
            {" "}
            · approximate
          </span>
        )}
        {place.patched && (
          <span
            className="hint"
            title="The build patched this file, so the repository is not what was built."
          >
            {" "}
            · patched
          </span>
        )}
      </div>
      {place.message && <div>{place.message}</div>}
      {place.snippet && (
        <pre
          className="mono"
          title={place.snippet_line ? `From line ${place.snippet_line}` : undefined}
        >
          {place.snippet}
        </pre>
      )}
    </div>
  );
}

// The leads another analyzer reported that are the same flaw, and those that
// possibly are.
function Kin({ build, evidence }: { build: Build; evidence: Evidence }) {
  const kin = evidence.kin ?? [];
  if (kin.length === 0) return null;
  const same = kin.filter((each) => each.same);
  const maybe = kin.filter((each) => !each.same);
  const list = (rows: typeof kin) => (
    <ul>
      {rows.map((each) => (
        <li key={each.place}>
          <Link className="mono" to={leadAt(build, each.place)}>
            {each.rule}
          </Link>{" "}
          <span className="mono hint">{located(each.path, each.line)}</span>
        </li>
      ))}
    </ul>
  );
  return (
    <div className="card">
      {same.length > 0 && (
        <>
          <h3 title="One decision here covers these too, unless they have one of their own.">
            Same flaw
          </h3>
          {list(same)}
        </>
      )}
      {maybe.length > 0 && (
        <>
          <h3>Possibly the same flaw</h3>
          {list(maybe)}
        </>
      )}
    </div>
  );
}

function DecideForm({ build, place }: { build: Build; place: string }) {
  const [outcome, setOutcome] = useState<LeadOutcome | "">("");
  const [reason, setReason] = useState<LeadReason | "">("");
  const [reasoning, setReasoning] = useState("");
  const decide = useDecideLead(build, place);
  const needsReason = outcome === "dismissed";
  const ready = outcome !== "" && (!needsReason || reason !== "") && reasoning.trim() !== "";

  return (
    <div>
      <ChoiceCards
        label="Outcome"
        value={outcome}
        onChange={setOutcome}
        options={LEAD_OUTCOMES.map((each) => ({
          value: each,
          label: labeled(each),
          note:
            each === "confirmed" ? "Takes effect now" : "Takes effect when somebody else approves",
        }))}
      />
      {needsReason && (
        <div className="field" style={{ marginTop: 10 }}>
          <label htmlFor="lead-reason">Reason</label>
          <select
            id="lead-reason"
            value={reason}
            onChange={(event) => setReason(event.target.value as LeadReason)}
          >
            <option value="">Choose…</option>
            {(Object.keys(LEAD_REASONS) as LeadReason[]).map((each) => (
              <option key={each} value={each}>
                {LEAD_REASONS[each]}
              </option>
            ))}
          </select>
        </div>
      )}
      {outcome !== "" && (
        <div className="field" style={{ marginTop: 10 }}>
          <Editor
            label="Reasoning"
            value={reasoning}
            onChange={setReasoning}
            rows={4}
            draftKey={`lead:${build.product}:${place}`}
          />
        </div>
      )}
      <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
        <button
          type="button"
          className="btn"
          disabled={!ready || decide.isPending}
          onClick={() =>
            outcome &&
            decide.mutate(
              {
                outcome,
                reasoning: reasoning.trim(),
                ...(needsReason && reason ? { reason } : {}),
              },
              {
                onSuccess: () => {
                  setOutcome("");
                  setReason("");
                  setReasoning("");
                },
              },
            )
          }
        >
          {outcome === "confirmed" || outcome === "" ? "Submit" : "Propose"}
        </button>
      </div>
      {decide.error != null && <Failed error={decide.error} what="Nothing was decided." />}
    </div>
  );
}

function Escalate({ product, place }: { product: string; place: string }) {
  const escalate = useEscalateLead(product, place);
  return (
    <div style={{ marginTop: 10 }}>
      <button
        type="button"
        className="btn quiet"
        disabled={escalate.isPending}
        onClick={() => escalate.mutate()}
        title="Takes it out of the baseline on every build of the product."
      >
        Add to the queue
      </button>
      {escalate.error != null && <Failed error={escalate.error} what="It was not added." />}
    </div>
  );
}

function FixForm({ build, place }: { build: Build; place: string }) {
  const [because, setBecause] = useState("");
  const fix = useFixLead(build, place);
  return (
    <div style={{ marginTop: 10 }}>
      <Editor
        label="Fixed by"
        value={because}
        onChange={setBecause}
        rows={3}
        draftKey={`lead-fixed:${build.product}:${place}`}
      />
      <button
        type="button"
        className="btn"
        style={{ marginTop: 8 }}
        disabled={because.trim() === "" || fix.isPending}
        onClick={() => fix.mutate(because.trim(), { onSuccess: () => setBecause("") })}
      >
        Close as fixed
      </button>
      {fix.error != null && <Failed error={fix.error} what="It was not closed." />}
    </div>
  );
}
