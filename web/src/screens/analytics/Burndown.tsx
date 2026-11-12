// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, type Body } from "../../api/client";
import { unwrap } from "../../api/queries";
import { fileAt } from "../../api/links";
import { askForScope, useScope } from "../../app/scope";
import { useWho } from "../../app/session";
import { counted, heldLine, holding } from "../../app/families";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { Empty } from "../../ui/Empty";
import { HeldLine } from "../../ui/HeldLine";
import { notACredential } from "../../ui/noautofill";
import { BANDS, FLOORS } from "../../ui/severities";
import { AddedDone, Burn, BurnLegend, paceWords } from "../../ui/Burn";
import { Sheet } from "./Sheet";
import { scopeWords } from "./catalog";
import { Downloads } from "../../ui/Downloads";

// What is left from a day 0, and whether the pace reaches zero.
//
// Counted once per issue in each package, the trend's unit. Done is a fix, or
// a dismissal while it stands; a proposal waiting for its approver is still
// left.

type Band = (typeof BANDS)[number];
type Chosen = Body<"ChosenBody">;

// The words a severity floor is offered in, least narrow first.
const FLOOR_WORDS: Record<Band | "", string> = {
  "": "All",
  low: "Low+",
  medium: "Medium+",
  high: "High+",
  critical: "Critical",
};
const FLOORS_OFFERED: (Band | "")[] = ["", ...FLOORS];

// The narrowings a link may arrive with. A typed choice is a name or a
// package identifier prefix; the subtree comes from the tree or the component
// screen, which know the build.
const NARROWINGS = [
  "component",
  "purl",
  "beneath",
  "beneath_version",
  "beneath_ecosystem",
  "beneath_namespace",
  "beneath_purl",
] as const;

export function Burndown() {
  const at = useScope();
  const [params, setParams] = useSearchParams();
  const branchOrTag = params.get("branch_or_tag") ?? at.branch_or_tag;
  const variant = params.get("variant") ?? at.variant;
  const sinceAsked = params.get("since") ?? "";
  const floor = (BANDS as readonly string[]).includes(params.get("severity") ?? "")
    ? (params.get("severity") as Band)
    : "";
  const narrowed = {
    component: params.get("component") ?? undefined,
    purl: params.get("purl") ?? undefined,
    beneath: params.get("beneath") ?? undefined,
    beneath_version: params.get("beneath_version") ?? undefined,
    beneath_ecosystem: params.get("beneath_ecosystem") ?? undefined,
    beneath_namespace: params.get("beneath_namespace") ?? undefined,
    beneath_purl: params.get("beneath_purl") ?? undefined,
  };
  const asked = {
    ...(at.product ? { product: at.product } : {}),
    ...(branchOrTag ? { branch_or_tag: branchOrTag } : {}),
    ...(variant ? { variant } : {}),
    ...(sinceAsked ? { since: sinceAsked } : {}),
    ...(floor ? { severity: floor } : {}),
    ...Object.fromEntries(Object.entries(narrowed).filter((entry) => !!entry[1])),
  } as Record<string, string>;
  const needsBuild =
    !!(narrowed.beneath || narrowed.beneath_purl) && !(at.product && branchOrTag && variant);

  const dependencies = holding(useWho().data, "dependency", at.product);
  const figures = counted(dependencies);
  const burndown = useQuery({
    queryKey: ["burndown", asked],
    enabled: figures && !needsBuild,
    retry: false,
    queryFn: async () => unwrap(await api.GET("/v1/burndown", { params: { query: asked } })),
  });

  const query = new URLSearchParams(asked).toString();
  const file = (format: "csv" | "json") => fileAt("/v1/burndown.{format}", format, { query });
  const change = (set: Record<string, string>, drop: readonly string[] = []) => {
    const next = new URLSearchParams(params);
    for (const name of drop) next.delete(name);
    for (const [name, value] of Object.entries(set)) {
      if (value) next.set(name, value);
      else next.delete(name);
    }
    setParams(next, { replace: true });
  };

  const of = [
    scopeWords({
      product: at.product,
      branch_or_tag: branchOrTag || undefined,
      variant: variant || undefined,
    }),
    narrowed.component && `on ${narrowed.component}`,
    narrowed.purl && `on ${narrowed.purl}`,
    narrowed.beneath && `at or under ${narrowed.beneath}`,
    narrowed.beneath_purl && `at or under ${narrowed.beneath_purl}`,
  ]
    .filter(Boolean)
    .join(" · ");
  const data = burndown.data;
  const points = data?.points ?? [];

  return (
    <Sheet
      settled={!figures || needsBuild || burndown.isSuccess}
      name="Findings burndown"
      answers="how much is left from a day 0, and when it reaches zero at this pace."
      of={of}
      asked={[
        data ? `from ${data.since}` : sinceAsked ? `from ${sinceAsked}` : "from the first scan",
        floor && FLOOR_WORDS[floor],
      ]
        .filter(Boolean)
        .join(", ")}
    >
      <div className="controls">
        <label>
          <span>Day 0</span>
          <input
            type="date"
            value={sinceAsked || data?.since || ""}
            onChange={(event) => change({ since: event.target.value })}
          />
        </label>
        {sinceAsked && (
          <button type="button" className="linkish" onClick={() => change({ since: "" })}>
            First scan
          </button>
        )}
        <div className="seg" role="group" aria-label="Severity">
          {FLOORS_OFFERED.map((band) => (
            <button
              key={band || "all"}
              type="button"
              aria-pressed={floor === band}
              onClick={() => change({ severity: band })}
            >
              {FLOOR_WORDS[band]}
            </button>
          ))}
        </div>
        {/* Keyed on the address's choice, so the box empties when Everything
            or a step back clears it. */}
        <Chooser
          key={narrowed.purl ?? narrowed.component ?? ""}
          typed={narrowed.purl ?? narrowed.component ?? ""}
          onChoose={(typed) =>
            change(
              typed.toLowerCase().startsWith("pkg:") ? { purl: typed } : { component: typed },
              NARROWINGS,
            )
          }
        />
        {Object.values(narrowed).some(Boolean) && (
          <button type="button" className="linkish" onClick={() => change({}, NARROWINGS)}>
            Everything
          </button>
        )}
        {figures && !needsBuild && (
          <span style={{ marginLeft: "auto" }} className="noprint">
            <Downloads href={file} />
          </span>
        )}
      </div>

      {figures && <HeldLine at={dependencies} />}
      {!figures ? (
        <Empty title="Nothing to list." detail={heldLine(dependencies)} />
      ) : needsBuild ? (
        <section className="panel">
          <Empty
            title="This needs one build."
            detail="At or under a component is read on one build. Pick a branch and a variant."
          >
            <button type="button" className="btn" onClick={askForScope}>
              Pick a build
            </button>
          </Empty>
        </section>
      ) : burndown.isPending ? (
        <Loading />
      ) : burndown.isError ? (
        <Failed error={burndown.error} what="The burndown could not be read." />
      ) : (
        <>
          <ChosenLine
            chosen={data?.chosen ?? []}
            more={data?.more_chosen ?? false}
            asked={!!(narrowed.purl || narrowed.component)}
          />
          {points.length === 0 ? (
            <Empty title="Nothing to count." detail="Nothing was open here from day 0." />
          ) : (
            data && (
              <>
                <section className="panel">
                  <h3>Left</h3>
                  <p className="reading">
                    {sentence(paceWords(data.projection, points.at(-1)?.left))}
                  </p>
                  <Burn
                    points={points}
                    start={data.start}
                    since={data.since}
                    ahead={data.projection}
                  />
                  <BurnLegend />
                  <p className="hint">
                    {data.start > 0 && `${data.start.toLocaleString()} at the start of day 0. `}
                    Pace: the last {data.projection.days} days. Once per issue in each package.
                  </p>
                </section>
                <section className="panel">
                  <h3>Added and done since day 0</h3>
                  <AddedDone points={points} since={data.since} />
                  <div className="legend">
                    <span>
                      <i style={{ background: "var(--sev-high)" }} /> Added: new and returned
                    </span>
                    <span>
                      <i style={{ background: "var(--ok)" }} /> Done: fixed and dismissed
                    </span>
                  </div>
                </section>
              </>
            )
          )}
        </>
      )}
    </Sheet>
  );
}

function sentence(words: string): string {
  return words.charAt(0).toUpperCase() + words.slice(1) + ".";
}

// A name, or a package identifier prefix such as pkg:github/sonic-net/.
function Chooser({ typed, onChoose }: { typed: string; onChoose: (typed: string) => void }) {
  const [text, setText] = useState(typed);
  return (
    <form
      className="searchbox"
      onSubmit={(event) => {
        event.preventDefault();
        onChoose(text.trim());
      }}
    >
      <input
        {...notACredential}
        type="text"
        value={text}
        aria-label="Component or purl"
        title="A name, or a purl prefix such as pkg:github/sonic-net/"
        placeholder="Component or pkg:…"
        onChange={(event) => setText(event.target.value)}
      />
    </form>
  );
}

// What a name or a prefix chose, with the ecosystem where two share a name.
function ChosenLine({ chosen, more, asked }: { chosen: Chosen[]; more: boolean; asked: boolean }) {
  if (!asked) return null;
  if (chosen.length === 0) {
    return <p className="hint">Nothing it matches is open since day 0.</p>;
  }
  const names = new Map<string, Set<string>>();
  for (const each of chosen) {
    names.set(each.name, (names.get(each.name) ?? new Set()).add(each.ecosystem ?? ""));
  }
  return (
    <p className="hint">
      Matches{" "}
      {chosen.map((each, i) => (
        <span key={`${each.package} ${each.ecosystem ?? ""}`}>
          {i > 0 && ", "}
          <span className="id">{each.package}</span>
          {(names.get(each.name)?.size ?? 0) > 1 && ` (${each.ecosystem || "no ecosystem"})`}
        </span>
      ))}
      {more && " and more"}
    </p>
  );
}
