// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { mayOf, useWho } from "../app/session";
import {
  useAssignCodeFinding,
  useDecideCodeFinding,
  useFixCodeFinding,
  useCodeFinding,
  type Evidence,
  type CodeFindingOutcome,
  type CodeFindingOccurrence,
  type CodeFindingReason,
} from "../api/codeFindings";
import { decisionAt, codeFindingAt, codeFindingsAt, type Build } from "../app/routes";
import { ChoiceCards } from "../ui/ChoiceCards";
import { Editor } from "../ui/Editor";
import { Failed } from "../ui/Failed";
import { Holder } from "../ui/Holder";
import { Loading } from "../ui/Loading";
import { labeled } from "../ui/Outcome";
import { linkable } from "../ui/addressable";
import { on } from "../ui/when";
import {
  CODE_FINDING_OUTCOMES,
  CODE_FINDING_REASONS,
  CODE_FINDING_TONES,
  located,
  reasonSaid,
  stateSaid,
} from "./codeFindings";
import { CodeFindingFlaw } from "./CodeFindingFlaw";

// One code finding on one build: what the analyzer said, the path it took, the code findings
// that are the same flaw, and where the code finding stands. Somebody who triages
// internal material judges it here, closes it as fixed once a run no longer
// sees it, and records a confirmed one as a flaw.
export function CodeFinding() {
  const { product = "", stream = "", variant = "", occurrence = "" } = useParams();
  const build: Build = { product, stream, variant };
  const codeFinding = useCodeFinding(build, occurrence);
  const may = mayOf(useWho().data, product);
  const triages = !!may?.triages_internal;
  const recordsFlaws = triages && !!may?.may_hide;

  if (codeFinding.isPending) return <Loading />;
  if (codeFinding.isError)
    return <Failed error={codeFinding.error} what="The code finding could not be read." />;
  const evidence = codeFinding.data;
  const at = evidence.at;
  // A code finding seen only in releases past their end of life is kept as it stands.
  // A move of one already recorded as a flaw concerns its flaw, and stays offered.
  const ended = !!evidence.past_end_of_life;
  const acts = triages && !ended;
  // A code finding recorded as a flaw, included in disclosure or not, is closed work for its
  // holder: its flaw is assigned instead.
  const assigns = triages && !ended && !evidence.recorded_as_flaw;

  return (
    <div>
      <div className="screen-head">
        <h2 className="mono">{evidence.rule}</h2>
        <p>
          <span className="mono">{located(at.path, at.start_line)}</span> ·{" "}
          <Link to={codeFindingsAt(product, { stream, variant })}>
            {product} · {stream} · {variant}
          </Link>{" "}
          <span className={`state ${CODE_FINDING_TONES[evidence.state]}`}>
            {stateSaid(evidence.state)}
          </span>
          {ended && <span className="state closed"> Past end of life</span>}
          {evidence.third_party && (
            <span className="state closed" title="The analysis run declared this path third-party">
              {" "}
              Third-party
            </span>
          )}
        </p>
      </div>

      <div className="card">
        <h3>Result</h3>
        <Location location={at} />
        {evidence.open && (
          <CodeFindingAssignee
            build={build}
            occurrence={occurrence}
            evidence={evidence}
            assigns={assigns}
          />
        )}
        <p className="hint">
          Last seen {on(evidence.last_seen)}
          {evidence.last_commit && <Commit sha={evidence.last_commit} />}
          {evidence.not_seen && ` · not seen ${on(evidence.not_seen)}`}
          {evidence.not_seen && evidence.not_seen_commit && (
            <Commit sha={evidence.not_seen_commit} />
          )}
          {evidence.unchanged && " · the code did not change between those builds"}
          {linkable(evidence.compare) && (
            <>
              {" · "}
              <a
                href={linkable(evidence.compare) ?? undefined}
                target="_blank"
                rel="noopener noreferrer"
              >
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
                <Location location={step} />
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
                <Location location={related} />
              </li>
            ))}
          </ul>
        </div>
      )}

      <Kin build={build} evidence={evidence} />

      <CodeFindingFlaw
        build={build}
        occurrence={occurrence}
        evidence={evidence}
        recordsFlaws={recordsFlaws && (!ended || evidence.state === "recorded-as-flaw")}
      />

      {evidence.state !== "recorded-as-flaw" && (
        <div className="card">
          <h3>Decision</h3>
          {evidence.decision_occurrence ? (
            <p>
              {labeled(evidence.decision_occurrence.outcome)}
              {evidence.decision_occurrence.reason &&
                ` · ${reasonSaid(evidence.decision_occurrence.reason)}`}
              {evidence.decision_occurrence.needs_approval &&
                evidence.decision_occurrence.state === "proposed" && (
                  <span className="state waiting"> Waiting for approval</span>
                )}{" "}
              {evidence.decision_occurrence.decision_id !== undefined && (
                <Link to={decisionAt(evidence.decision_occurrence.decision_id)}>
                  Decision {evidence.decision_occurrence.decision_id}
                </Link>
              )}
            </p>
          ) : acts && evidence.open ? (
            <DecideForm build={build} occurrence={occurrence} />
          ) : (
            <p className="hint">None.</p>
          )}
          {acts &&
            evidence.state === "no-longer-detected" &&
            evidence.open &&
            evidence.not_seen_run !== undefined && (
              <FixForm build={build} occurrence={occurrence} fixedIn={evidence.not_seen_run} />
            )}
          {evidence.fixed_in && (
            <p className="hint">
              Fixed in the build made {on(evidence.fixed_in.built)}
              {evidence.fixed_in.commit && (
                <>
                  {" "}
                  at <span className="mono">{evidence.fixed_in.commit.slice(0, 12)}</span>
                </>
              )}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

// The commit the code finding's repository was at in a build, shortened, with the
// whole of it on hover.
function Commit({ sha }: { sha: string }) {
  return (
    <span className="mono" title={sha}>
      {" "}
      at {sha.slice(0, 12)}
    </span>
  );
}

// One location the analyzer named: where, what it said there, and the code.
function Location({ location }: { location: CodeFindingOccurrence }) {
  const href = linkable(location.link);
  const where = located(location.path, location.start_line);
  return (
    <div>
      <div>
        {href ? (
          <a
            className="mono"
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            title={location.revision}
          >
            {where}
          </a>
        ) : (
          <span className="mono" title={location.unlinked}>
            {where}
          </span>
        )}
        {location.function && <span className="hint"> in {location.function}</span>}
        {location.approximate && (
          <span className="hint" title="The line is where the code was, not where it is.">
            {" "}
            · approximate
          </span>
        )}
        {location.patched && (
          <span
            className="hint"
            title="The build patched this file, so the repository is not what was built."
          >
            {" "}
            · patched
          </span>
        )}
      </div>
      {location.message && <div>{location.message}</div>}
      {location.snippet && (
        <pre
          className="mono"
          title={location.snippet_line ? `From line ${location.snippet_line}` : undefined}
        >
          {location.snippet}
        </pre>
      )}
    </div>
  );
}

// The code findings another analyzer reported that are the same flaw, and those that
// possibly are.
function Kin({ build, evidence }: { build: Build; evidence: Evidence }) {
  const kin = evidence.kin ?? [];
  if (kin.length === 0) return null;
  const same = kin.filter((each) => each.same);
  const maybe = kin.filter((each) => !each.same);
  const list = (rows: typeof kin) => (
    <ul>
      {rows.map((each) => (
        <li key={each.occurrence}>
          <Link className="mono" to={codeFindingAt(build, each.occurrence)}>
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
            Also found by
          </h3>
          {list(same)}
        </>
      )}
      {maybe.length > 0 && (
        <>
          <h3>Possibly also found by</h3>
          {list(maybe)}
        </>
      )}
    </div>
  );
}

function DecideForm({ build, occurrence }: { build: Build; occurrence: string }) {
  const [outcome, setOutcome] = useState<CodeFindingOutcome | "">("");
  const [reason, setReason] = useState<CodeFindingReason | "">("");
  const [reasoning, setReasoning] = useState("");
  const decide = useDecideCodeFinding(build, occurrence);
  const needsReason = outcome === "dismissed";
  const ready = outcome !== "" && (!needsReason || reason !== "") && reasoning.trim() !== "";

  return (
    <div>
      <ChoiceCards
        label="Outcome"
        value={outcome}
        onChange={setOutcome}
        options={CODE_FINDING_OUTCOMES.map((each) => ({
          value: each,
          label: labeled(each),
          note:
            each === "confirmed" ? "Takes effect now" : "Takes effect when somebody else approves",
        }))}
      />
      {needsReason && (
        <div className="field" style={{ marginTop: 10 }}>
          <label htmlFor="code-finding-reason">Reason</label>
          <select
            id="code-finding-reason"
            value={reason}
            onChange={(event) => setReason(event.target.value as CodeFindingReason)}
          >
            <option value="">Choose…</option>
            {(Object.keys(CODE_FINDING_REASONS) as CodeFindingReason[]).map((each) => (
              <option key={each} value={each}>
                {CODE_FINDING_REASONS[each]}
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
            draftKey={`code finding:${build.product}:${occurrence}`}
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

// Who is dealing with the code finding, and the picker that changes it for somebody
// who triages it. Applies to every build of the product the code finding is open on.
function CodeFindingAssignee({
  build,
  occurrence,
  evidence,
  assigns,
}: {
  build: Build;
  occurrence: string;
  evidence: Evidence;
  assigns: boolean;
}) {
  const assign = useAssignCodeFinding(build, occurrence);
  const holder = evidence.assigned_to
    ? { identity: evidence.assigned_to, name: evidence.assigned_to_name }
    : null;
  if (!assigns) {
    return holder ? (
      <p className="hint">
        Assigned to {holder.name ?? holder.identity}
        {evidence.assigned_team && " · team"}
      </p>
    ) : null;
  }
  return (
    <div className="assignee">
      <span
        className="l"
        title="Applies to every build with this code finding. Set it to nobody to unassign"
      >
        Assigned to
      </span>
      <div style={{ minWidth: 220 }}>
        <Holder
          product={build.product}
          internal
          value={holder}
          disabled={assign.isPending}
          onPick={(held) => assign.mutate(held)}
        />
      </div>
      {assign.isPending && <span className="hint">Saving…</span>}
      {assign.error != null && <Failed error={assign.error} what="That could not be recorded." />}
    </div>
  );
}

function FixForm({
  build,
  occurrence,
  fixedIn,
}: {
  build: Build;
  occurrence: string;
  fixedIn: number;
}) {
  const [because, setBecause] = useState("");
  const fix = useFixCodeFinding(build, occurrence);
  return (
    <div style={{ marginTop: 10 }}>
      <p className="hint">Fixed in the build of the first run that did not see it.</p>
      <Editor
        label="Fixed by"
        value={because}
        onChange={setBecause}
        rows={3}
        draftKey={`code-finding-fixed:${build.product}:${occurrence}`}
      />
      <button
        type="button"
        className="btn"
        style={{ marginTop: 8 }}
        disabled={because.trim() === "" || fix.isPending}
        onClick={() =>
          fix.mutate({ because: because.trim(), fixedIn }, { onSuccess: () => setBecause("") })
        }
      >
        Close as fixed
      </button>
      {fix.error != null && <Failed error={fix.error} what="It was not closed." />}
    </div>
  );
}
