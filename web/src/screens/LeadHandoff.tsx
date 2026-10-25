// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Handing a confirmed lead off as a flaw, and the flaw it was handed off as.
//
// A hand-off records a private flaw, so it is offered to somebody who triages
// both the internal lead and undisclosed work. Moving the lead into the case
// makes it part of what is disclosed with the flaw, so what that would
// disclose is listed before the choice is sent.

import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import {
  useHandOff,
  useHandoffOffer,
  useMoveLead,
  type Evidence,
  type HandoffOffer,
} from "../api/leads";
import { issueAt, type Build } from "../app/routes";
import { ChoiceCards } from "../ui/ChoiceCards";
import { Editor } from "../ui/Editor";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { on } from "../ui/when";
import { People } from "./FindingPeople";

type Suggestion = NonNullable<HandoffOffer["suggestions"]>[number];
type Seen = NonNullable<HandoffOffer["seen"]>[number];

const FROM: Record<Suggestion["from"], (prefix: string) => string> = {
  confirmed: (prefix) => `Confirmed before for ${prefix}`,
  placed: () => "The component it was placed on",
  resembles: (prefix) => `Its name resembles ${prefix}`,
  build: () => "Code in no component",
};

const buildKey = (b: Seen) => `${b.stream}\u0000${b.variant}`;

// The hand-off card: the form where the lead is confirmed and not handed off,
// the flaw where it is handed off, and nothing otherwise.
export function Handoff({
  build,
  place,
  evidence,
  handsOff,
}: {
  build: Build;
  place: string;
  evidence: Evidence;
  handsOff: boolean;
}) {
  if (evidence.handoff) {
    return <HandedOff build={build} place={place} evidence={evidence} handsOff={handsOff} />;
  }
  if (handsOff && evidence.state === "confirmed" && !evidence.withheld) {
    return <HandOffForm build={build} place={place} />;
  }
  return null;
}

function HandedOff({
  build,
  place,
  evidence,
  handsOff,
}: {
  build: Build;
  place: string;
  evidence: Evidence;
  handsOff: boolean;
}) {
  const move = useMoveLead(build, place);
  const handed = evidence.handoff;
  if (!handed) return null;
  return (
    <>
      <div className="card">
        <h3>Flaw</h3>
        <p>
          <Link className="mono" to={issueAt(handed.flaw)}>
            {handed.flaw}
          </Link>{" "}
          <span className="hint">
            · handed off by {handed.handed_by_name || handed.handed_by} {on(handed.handed_at)} ·{" "}
            {handed.moved ? "part of its case" : "kept internal"}
            {handed.disclosed && " · disclosed"}
          </span>
        </p>
        {handsOff && !handed.disclosed && (
          <button
            type="button"
            className="btn quiet"
            disabled={move.isPending}
            onClick={() => move.mutate(!handed.moved)}
            title={
              handed.moved
                ? "Makes it internal again. Internal readers see all of it."
                : "Makes it private. Internal readers see only where it is. Disclosed with the flaw."
            }
          >
            {handed.moved ? "Take out of the case" : "Move into the case"}
          </button>
        )}
        {move.error != null && <Failed error={move.error} what="Nothing was moved." />}
      </div>
      {!handed.disclosed && (
        <People
          product={build.product}
          scope={["lead", build.product, place]}
          grants="Grants reading this lead only."
          list={async () =>
            unwrap(
              await api.GET(
                "/v1/products/{product}/streams/{stream}/variants/{variant}/leads/{place}/collaborators",
                { params: { path: { ...build, place } } },
              ),
            )
          }
          add={async (identity) =>
            unwrap(
              await api.PUT(
                "/v1/products/{product}/streams/{stream}/variants/{variant}/leads/{place}/collaborators/{identity}",
                {
                  params: { path: { ...build, place, identity } },
                },
              ),
            )
          }
          remove={async (identity) =>
            unwrap(
              await api.DELETE(
                "/v1/products/{product}/streams/{stream}/variants/{variant}/leads/{place}/collaborators/{identity}",
                {
                  params: { path: { ...build, place, identity } },
                },
              ),
            )
          }
        />
      )}
    </>
  );
}

function HandOffForm({ build, place }: { build: Build; place: string }) {
  const offer = useHandoffOffer(build, place, true);
  const handOff = useHandOff(build, place);
  const [picked, setPicked] = useState("");
  const [left, setLeft] = useState<Set<string>>(new Set());
  const [summary, setSummary] = useState("");
  const [keep, setKeep] = useState<"keep" | "move">("keep");

  if (offer.isPending) return <Loading />;
  if (offer.isError) {
    return (
      <div className="card">
        <h3>Hand off</h3>
        <Failed error={offer.error} what="The hand-off could not be offered." />
      </div>
    );
  }
  const data = offer.data;
  const prefix = data.prefix ?? "";
  const suggestions = data.suggestions ?? [];
  const seen = data.seen ?? [];
  const chosen = suggestions[Number(picked === "" ? 0 : picked)];
  const lacking = new Set((chosen?.lacking ?? []).map(buildKey));
  const builds = seen.filter((b) => !left.has(buildKey(b)) && !lacking.has(buildKey(b)));
  const ready = chosen !== undefined && builds.length > 0 && summary.trim() !== "";
  const discloses = data.discloses;

  if (handOff.data) {
    return (
      <div className="card">
        <h3>Hand off</h3>
        <p>
          Recorded as{" "}
          <Link className="mono" to={issueAt(handOff.data.identifier)}>
            {handOff.data.identifier}
          </Link>
          .
        </p>
      </div>
    );
  }

  return (
    <div className="card">
      <h3>Hand off</h3>
      <ChoiceCards
        label="Component"
        value={picked === "" ? "0" : picked}
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
                {b.stream} · {b.variant}
              </span>
              {lacking.has(key) && <span className="hint"> · does not hold it</span>}
            </label>
          );
        })}
        {(chosen?.unanalyzed ?? []).map((b) => (
          <div
            key={buildKey(b)}
            className="hint"
            title="Nothing analyzes it, and it ships the code."
          >
            <span className="mono">
              {b.stream} · {b.variant}
            </span>{" "}
            · not analyzed
          </div>
        ))}
      </fieldset>
      <div className="field" style={{ marginTop: 10 }}>
        <Editor
          label="Summary"
          value={summary}
          onChange={setSummary}
          rows={4}
          draftKey={`lead-handoff:${build.product}:${place}`}
        />
      </div>
      <div style={{ marginTop: 10 }}>
        <ChoiceCards
          label="The lead"
          value={keep}
          onChange={setKeep}
          options={[
            { value: "keep", label: "Keep internal", note: "Linked to the flaw, never disclosed" },
            {
              value: "move",
              label: "Move into the case",
              note: "Private now, disclosed with the flaw",
            },
          ]}
        />
      </div>
      {keep === "move" && (
        <div className="reading" style={{ marginTop: 10 }}>
          <p>Disclosed with the flaw:</p>
          <ul>
            {(discloses.authors ?? []).length > 0 && (
              <li>
                What {(discloses.authors ?? []).map((a) => a.name || a.identity).join(", ")} wrote
                about it
              </li>
            )}
            {(discloses.paths ?? []).length > 0 && (
              <li>
                The paths <span className="mono">{(discloses.paths ?? []).join(", ")}</span>
              </li>
            )}
            {discloses.messages > 0 && <li>{discloses.messages} analyzer messages</li>}
            {discloses.snippets > 0 && <li>{discloses.snippets} source snippets</li>}
          </ul>
          {discloses.stripped > 0 && (
            <p className="hint">{discloses.stripped} source snippets are removed at disclosure.</p>
          )}
        </div>
      )}
      <button
        type="button"
        className="btn"
        style={{ marginTop: 10 }}
        disabled={!ready || handOff.isPending}
        onClick={() =>
          chosen &&
          handOff.mutate({
            builds: builds.map((b) => ({ stream: b.stream, variant: b.variant })),
            summary: summary.trim(),
            ...(chosen.component ? { component: chosen.component } : {}),
            ...(chosen.ecosystem ? { ecosystem: chosen.ecosystem } : {}),
            ...(chosen.namespace ? { namespace: chosen.namespace } : {}),
            ...(keep === "move" ? { move: true } : {}),
          })
        }
      >
        Hand off
      </button>
      {handOff.error != null && <Failed error={handOff.error} what="Nothing was handed off." />}
    </div>
  );
}
