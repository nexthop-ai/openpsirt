// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Recording a confirmed code finding as a flaw, and the flaw it was recorded as.
//
// Recording one records a private flaw, so it is offered to somebody who
// triages both the security testing code finding and undisclosed work. Including the
// code finding in disclosure makes it part of what is published with the flaw,
// so what that would publish is listed before the choice is sent.

import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import {
  useRecordAsFlaw,
  useFlawOffer,
  useIncludeCodeFinding,
  useUndoRecordAsFlaw,
  type Evidence,
  type FlawOffer,
} from "../api/codeFindings";
import { issueAt, type Build } from "../app/routes";
import { ChoiceCards } from "../ui/ChoiceCards";
import { Editor } from "../ui/Editor";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { on } from "../ui/when";
import { People } from "./FindingPeople";
import { Markdown } from "../ui/Markdown";

type Suggestion = NonNullable<FlawOffer["suggestions"]>[number];
type Seen = NonNullable<FlawOffer["seen"]>[number];

const FROM: Record<Suggestion["from"], (prefix: string) => string> = {
  confirmed: (prefix) => `Confirmed before for ${prefix}`,
  placed: () => "The component it was placed on",
  resembles: (prefix) => `Its name resembles ${prefix}`,
  build: () => "Code in no component",
};

const buildKey = (b: Seen) => `${b.branch_or_tag}\u0000${b.variant}`;

// The flaw card: the form where the code finding is confirmed and not recorded
// as a flaw, the flaw where it is, and nothing otherwise.
export function CodeFindingFlaw({
  build,
  occurrence,
  evidence,
  recordsFlaws,
}: {
  build: Build;
  occurrence: string;
  evidence: Evidence;
  recordsFlaws: boolean;
}) {
  if (evidence.recorded_as_flaw) {
    return (
      <RecordedAsFlaw
        build={build}
        occurrence={occurrence}
        evidence={evidence}
        recordsFlaws={recordsFlaws}
      />
    );
  }
  if (recordsFlaws && evidence.state === "confirmed") {
    return <RecordAsFlawForm build={build} occurrence={occurrence} />;
  }
  return null;
}

function RecordedAsFlaw({
  build,
  occurrence,
  evidence,
  recordsFlaws,
}: {
  build: Build;
  occurrence: string;
  evidence: Evidence;
  recordsFlaws: boolean;
}) {
  const include = useIncludeCodeFinding(build, occurrence);
  const recorded = evidence.recorded_as_flaw;
  // What including a security-testing-only code finding publishes, said before the
  // button is pressed.
  const offering =
    recordsFlaws &&
    recorded !== undefined &&
    !recorded.included_in_disclosure &&
    !recorded.disclosed;
  const offer = useFlawOffer(build, occurrence, offering);
  if (!recorded) return null;
  return (
    <>
      <div className="card">
        <h3>Flaw</h3>
        <p>
          <Link className="mono" to={issueAt(recorded.flaw)}>
            {recorded.flaw}
          </Link>{" "}
          <span className="hint">
            · recorded as a flaw by {recorded.recorded_by_name || recorded.recorded_by}{" "}
            {on(recorded.recorded_at)} ·{" "}
            {recorded.included_in_disclosure ? (
              <span title="Included in its flaw's disclosure">Included in disclosure</span>
            ) : (
              "Security testing only"
            )}
            {recorded.disclosed && " · disclosed"}
          </span>
        </p>
        {offering && offer.data && offer.data.together > 0 && (
          <p className="hint">Goes with {others(offer.data.together)} linked to this flaw.</p>
        )}
        {offering && offer.data && <Discloses discloses={offer.data.discloses} />}
        {offering && offer.isError && (
          <Failed error={offer.error} what="What including it publishes could not be read." />
        )}
        {recordsFlaws && !recorded.disclosed && (
          <button
            type="button"
            className="btn quiet"
            disabled={include.isPending || (offering && !offer.data)}
            onClick={() => include.mutate(!recorded.included_in_disclosure)}
            title={
              recorded.included_in_disclosure
                ? "The flaw's readers stop seeing it. Security testing readers keep it."
                : `${INCLUDE_HOVER} ${PUBLISHED_TO}`
            }
          >
            {recorded.included_in_disclosure ? "Take out of disclosure" : "Include in disclosure"}
          </button>
        )}
        {include.error != null && <Failed error={include.error} what="Nothing changed." />}
        {recordsFlaws && !recorded.disclosed && (
          <UndoRecordAsFlaw build={build} occurrence={occurrence} />
        )}
      </div>
      {!recorded.disclosed && (
        <People
          product={build.product}
          scope={["code-finding", build.product, occurrence]}
          grants="Grants reading this code finding only."
          list={async () =>
            unwrap(
              await api.GET(
                "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/collaborators",
                { params: { path: { ...build, occurrence } } },
              ),
            )
          }
          add={async (identity) =>
            unwrap(
              await api.PUT(
                "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/collaborators/{identity}",
                {
                  params: { path: { ...build, occurrence, identity } },
                },
              ),
            )
          }
          remove={async (identity) =>
            unwrap(
              await api.DELETE(
                "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/collaborators/{identity}",
                {
                  params: { path: { ...build, occurrence, identity } },
                },
              ),
            )
          }
        />
      )}
    </>
  );
}

// Withdrawing the flaw: the code finding is confirmed again and the flaw is
// taken back out of every build as invalid, so it asks why.
function UndoRecordAsFlaw({ build, occurrence }: { build: Build; occurrence: string }) {
  const [open, setOpen] = useState(false);
  const [because, setBecause] = useState("");
  const undo = useUndoRecordAsFlaw(build, occurrence);
  if (!open) {
    return (
      <button
        type="button"
        className="btn quiet"
        style={{ marginLeft: 8 }}
        onClick={() => setOpen(true)}
        title="The code finding is confirmed again. The flaw is closed as invalid on every build."
      >
        Withdraw flaw…
      </button>
    );
  }
  return (
    <div style={{ marginTop: 10 }}>
      <Editor
        label="Reason"
        value={because}
        onChange={setBecause}
        rows={3}
        draftKey={`code-finding-undo:${build.product}:${occurrence}`}
      />
      <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
        <button
          type="button"
          className="btn"
          disabled={because.trim() === "" || undo.isPending}
          onClick={() => undo.mutate(because.trim(), { onSuccess: () => setBecause("") })}
        >
          Withdraw flaw
        </button>
        <button type="button" className="btn quiet" onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
      {undo.error != null && <Failed error={undo.error} what="The flaw was not withdrawn." />}
    </div>
  );
}

function RecordAsFlawForm({ build, occurrence }: { build: Build; occurrence: string }) {
  const offer = useFlawOffer(build, occurrence, true);
  const recordAsFlaw = useRecordAsFlaw(build, occurrence);
  const [picked, setPicked] = useState("");
  const [left, setLeft] = useState<Set<string>>(new Set());
  const [added, setAdded] = useState<Set<string>>(new Set());
  const [summary, setSummary] = useState("");
  const [included, setIncluded] = useState(false);

  if (offer.isPending) return <Loading />;
  if (offer.isError) {
    return (
      <div className="card">
        <h3>Record as a flaw</h3>
        <Failed error={offer.error} what="Recording it as a flaw could not be offered." />
      </div>
    );
  }
  const data = offer.data;
  const prefix = data.prefix ?? "";
  const suggestions = data.suggestions ?? [];
  const seen = data.seen ?? [];
  // A resembling component is a guess, so it is never picked for the person.
  const first = suggestions[0];
  const initial = first && first.from !== "resembles" ? "0" : "";
  const value = picked === "" ? initial : picked;
  const chosen = value === "" ? undefined : suggestions[Number(value)];
  const lacking = new Set((chosen?.lacking ?? []).map(buildKey));
  const unanalyzed = chosen?.unanalyzed ?? [];
  const builds = [
    ...seen.filter((b) => !left.has(buildKey(b)) && !lacking.has(buildKey(b))),
    ...unanalyzed.filter((b) => added.has(buildKey(b))),
  ];
  const ready = chosen !== undefined && builds.length > 0 && summary.trim() !== "";
  const discloses = data.discloses;

  if (recordAsFlaw.data) {
    return (
      <div className="card">
        <h3>Record as a flaw</h3>
        <p>
          Recorded as{" "}
          <Link className="mono" to={issueAt(recordAsFlaw.data.identifier)}>
            {recordAsFlaw.data.identifier}
          </Link>
          .
        </p>
      </div>
    );
  }

  return (
    <div className="card">
      <h3>Record as a flaw</h3>
      {data.third_party && <p className="hint">Third-party code: report the flaw upstream.</p>}
      <ChoiceCards
        label="Component"
        value={value}
        onChange={setPicked}
        options={suggestions.map((each, i) => ({
          value: String(i),
          label: each.component || "The build itself",
          note: [
            FROM[each.from](prefix),
            (each.lacking ?? []).length > 0 && `not in ${(each.lacking ?? []).length} builds`,
            (each.unanalyzed ?? []).length > 0 &&
              `${(each.unanalyzed ?? []).length} builds hold it and are not analyzed`,
          ]
            .filter(Boolean)
            .join(" · "),
        }))}
      />
      <fieldset className="field" style={{ marginTop: 10 }}>
        <legend>Builds</legend>
        {seen.map((b) => {
          const key = buildKey(b);
          return (
            <label key={key} style={{ display: "block" }}>
              <input
                type="checkbox"
                checked={!left.has(key) && !lacking.has(key)}
                disabled={lacking.has(key)}
                onChange={(event) => {
                  const next = new Set(left);
                  if (event.target.checked) next.delete(key);
                  else next.add(key);
                  setLeft(next);
                }}
              />{" "}
              <span className="mono">
                {b.branch_or_tag} · {b.variant}
              </span>
              {lacking.has(key) && <span className="hint"> · does not hold it</span>}
            </label>
          );
        })}
        {unanalyzed.map((b) => {
          const key = buildKey(b);
          return (
            <label
              key={key}
              style={{ display: "block" }}
              title="Nothing analyzes it, and it holds the component."
            >
              <input
                type="checkbox"
                checked={added.has(key)}
                onChange={(event) => {
                  const next = new Set(added);
                  if (event.target.checked) next.add(key);
                  else next.delete(key);
                  setAdded(next);
                }}
              />{" "}
              <span className="mono">
                {b.branch_or_tag} · {b.variant}
              </span>
              <span className="hint"> · not analyzed</span>
            </label>
          );
        })}
      </fieldset>
      <div className="field" style={{ marginTop: 10 }}>
        <Editor
          label="Summary"
          value={summary}
          onChange={setSummary}
          rows={4}
          draftKey={`code-finding-flaw:${build.product}:${occurrence}`}
        />
      </div>
      {data.together > 0 && (
        <p className="hint">Also records {others(data.together)} confirmed with this one.</p>
      )}
      <label style={{ display: "block", marginTop: 10 }} title={INCLUDE_HOVER}>
        <input
          type="checkbox"
          checked={included}
          onChange={(event) => setIncluded(event.target.checked)}
        />{" "}
        Include in disclosure
      </label>
      {included && <Discloses discloses={discloses} />}
      <button
        type="button"
        className="btn"
        style={{ marginTop: 10 }}
        disabled={!ready || recordAsFlaw.isPending}
        onClick={() =>
          chosen &&
          recordAsFlaw.mutate({
            builds: builds.map((b) => ({ branch_or_tag: b.branch_or_tag, variant: b.variant })),
            summary: summary.trim(),
            ...(chosen.component ? { component: chosen.component } : {}),
            ...(chosen.ecosystem ? { ecosystem: chosen.ecosystem } : {}),
            ...(chosen.namespace ? { namespace: chosen.namespace } : {}),
            ...(included ? { include_in_disclosure: true } : {}),
          })
        }
      >
        Record as a flaw
      </button>
      {recordAsFlaw.error != null && (
        <Failed error={recordAsFlaw.error} what="Nothing was recorded as a flaw." />
      )}
    </div>
  );
}

// The other code findings recording as a flaw or including in disclosure takes
// with this one.
function others(n: number): string {
  return n === 1 ? "1 other code finding" : `${n} other code findings`;
}

// What including a code finding in its flaw's disclosure does, on hover.
const INCLUDE_HOVER =
  "Publishes the path, the analyzer's messages, and the decisions and comments on this finding with the flaw. Until then, people on the flaw's case can read it.";

// Who reads an included code finding once its flaw is disclosed. Signed-in
// readers of the product only: a code finding is never in a published VEX or
// CSAF document.
const PUBLISHED_TO =
  "Once the flaw is disclosed, readable by everyone signed in with public access to this product. Not included in published VEX or CSAF.";

// What including a code finding in its flaw's disclosure publishes with the flaw.
function Discloses({ discloses }: { discloses: FlawOffer["discloses"] }) {
  const authors = discloses.authors ?? [];
  const said = discloses.said ?? [];
  return (
    <div className="reading" style={{ marginTop: 10 }}>
      <h4>Disclosed with the flaw</h4>
      <p className="hint">{PUBLISHED_TO}</p>
      {authors.map((a) => (
        <div key={a.identity}>
          <h5>{a.name || a.identity}</h5>
          {(a.notes ?? []).map((n, i) => (
            <div key={i}>
              <p className="hint">
                {n.comment ? "Comment" : "Reasoning"} on decision {n.decision}
              </p>
              <Markdown source={n.body} />
            </div>
          ))}
        </div>
      ))}
      {said.length > 0 && (
        <>
          <h5>Analyzer messages</h5>
          <ul>
            {said.map((m, i) => (
              <li key={i}>
                {m.path && <span className="mono">{m.path}</span>} {m.message}
              </li>
            ))}
          </ul>
        </>
      )}
      {(discloses.paths ?? []).length > 0 && (
        <p>
          Paths <span className="mono">{(discloses.paths ?? []).join(", ")}</span>
        </p>
      )}
      <p className="hint">
        {discloses.snippets > 0
          ? `Source snippets: ${discloses.snippets} published`
          : "Source snippets: not published"}
        {discloses.stripped > 0 && ` · ${discloses.stripped} removed at disclosure`}
      </p>
    </div>
  );
}
