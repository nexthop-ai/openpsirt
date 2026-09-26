// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Loading } from "../ui/Loading";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type { Body } from "../api/client";
import { unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Outcome } from "../ui/Outcome";
import { drawn, said } from "../ui/states";
import { Severity } from "../ui/Severity";
import { Across } from "../ui/Charts";

// The rows of each column shown before it says how many more there are.
const SHOWN = 8;

// The changes between two builds of one product.
//
// Between any two, not only adjacent ones: what a release note has to answer
// is usually about the last release a customer has, which is rarely the
// previous one.
export function Compare() {
  const { product = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const from = params.get("from") ?? "";
  const fromVariant = params.get("from_variant") ?? "";
  const to = params.get("to") ?? "";
  const toVariant = params.get("to_variant") ?? "";
  const undisclosed = params.get("undisclosed") === "yes";

  const streams = useQuery({
    queryKey: ["streams", product],
    queryFn: async () =>
      unwrap(await api.GET("/v1/products/{product}/streams", { params: { path: { product } } })),
  });
  const variants = useQuery({
    queryKey: ["variants", product],
    queryFn: async () =>
      unwrap(await api.GET("/v1/products/{product}/variants", { params: { path: { product } } })),
  });

  const ready = from !== "" && fromVariant !== "" && to !== "" && toVariant !== "";
  // The same comparison as prose, fetched rather than assembled here: what an
  // API caller gets and what this shows have to be the same words, and two
  // implementations of "how a release note reads" is one that drifts.
  // The request the file is asked for with, which is the screen's own. Built
  // once so that a comparison somebody exports is the comparison in front of
  // them rather than one assembled again from parts.
  const asked = new URLSearchParams({
    from,
    from_variant: fromVariant,
    to,
    to_variant: toVariant,
    ...(undisclosed ? { include_undisclosed: "true" } : {}),
  }).toString();
  // Asked for rather than always shown: most visits are somebody reading the
  // columns, and a wall of markdown above them would be answering a question
  // nobody asked yet. So the query is disabled until the button is pressed.
  //
  // A query rather than a bare fetch, because the prose says "nothing changed
  // between those two" and a failed read that answered the empty string would
  // say it about a comparison nobody was told failed.
  const [wanted, setWanted] = useState(false);
  const [copied, setCopied] = useState(false);
  const notes = useQuery({
    queryKey: ["release-notes", product, from, fromVariant, to, toVariant, undisclosed],
    enabled: wanted && ready,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/comparison/notes", {
          params: {
            path: { product },
            query: {
              from,
              from_variant: fromVariant,
              to,
              to_variant: toVariant,
              ...(undisclosed ? { include_undisclosed: true } : {}),
            },
          },
          parseAs: "text",
        }),
      ) as unknown as string,
  });

  const comparison = useQuery({
    queryKey: ["comparison", product, from, fromVariant, to, toVariant, undisclosed],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/comparison", {
          params: {
            path: { product },
            query: {
              from,
              from_variant: fromVariant,
              to,
              to_variant: toVariant,
              ...(undisclosed ? { include_undisclosed: true } : {}),
            },
          },
        }),
      ),
    enabled: ready,
  });

  // Every build, not the two being compared. The comparison answers "what
  // changed between these two"; this answers "is it getting better or worse",
  // which is the question a release note cannot.
  const releases = useQuery({
    queryKey: ["releases", product],
    queryFn: async () =>
      unwrap(await api.GET("/v1/products/{product}/releases", { params: { path: { product } } })),
  });

  function set(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next);
  }

  const streamNames = (streams.data?.items ?? []).map((each) => each.name ?? "");
  const variantNames = (variants.data?.items ?? []).map((each) => each.name ?? "");

  return (
    <>
      <div className="screen-head">
        <h2>Release comparison</h2>
        <p>
          {product} — what was fixed, what closed without being fixed, what was introduced, and what
          is unchanged between any two builds
        </p>
      </div>

      {(releases.data?.items ?? []).length > 1 && (
        <div className="card">
          <header>
            <h3>Open findings by release</h3>
          </header>
          <Across releases={releases.data?.items ?? []} />
          <p className="hint">Every open finding at each build, before any triage line.</p>
        </div>
      )}

      <div className="card">
        <header
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            flexWrap: "wrap",
            marginBottom: 12,
          }}
        >
          <h3 style={{ margin: 0 }}>Compare</h3>
          <Pick
            label="Earlier build"
            stream={from}
            variant={fromVariant}
            streams={streamNames}
            variants={variantNames}
            onStream={(value) => set("from", value)}
            onVariant={(value) => set("from_variant", value)}
          />
          <span style={{ color: "var(--faint)" }}>to</span>
          <Pick
            label="Later build"
            stream={to}
            variant={toVariant}
            streams={streamNames}
            variants={variantNames}
            onStream={(value) => set("to", value)}
            onVariant={(value) => set("to_variant", value)}
          />
          <span style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
            <button
              type="button"
              className="chip"
              aria-pressed={undisclosed}
              onClick={() => set("undisclosed", undisclosed ? "" : "yes")}
            >
              Include undisclosed
            </button>
          </span>
        </header>

        {/* Its destination is usually a public document, so including
            something embargoed should be a deliberate act rather than a paste
            nobody checked. */}
        <p className="reading" style={{ marginBottom: 12 }}>
          Public findings only, unless you say otherwise.
        </p>

        {!ready ? (
          <Empty title="Pick two builds." detail="Any two compare, not only adjacent ones." />
        ) : comparison.isPending ? (
          <Loading />
        ) : comparison.isError ? (
          <Failed error={comparison.error} what="Those two could not be compared." />
        ) : (
          <>
            <Columns
              fixed={comparison.data?.fixed ?? []}
              closed={comparison.data?.closed_not_fixed ?? []}
              newly={comparison.data?.newly_present ?? []}
              still={comparison.data?.still_present ?? []}
              runsAt={`/products/${encodeURIComponent(product)}/streams/${encodeURIComponent(to)}/variants/${encodeURIComponent(toVariant)}/runs`}
            />

            {/* The same comparison in the form it is actually wanted in
. Asked for rather than always shown: most visits are
                somebody reading the columns, and a wall of markdown above them
                would be answering a question nobody asked yet. */}
            <div className="actions" style={{ marginTop: 14 }}>
              <button
                type="button"
                className="btn"
                disabled={notes.isFetching}
                onClick={() => {
                  setCopied(false);
                  if (wanted) void notes.refetch();
                  else setWanted(true);
                }}
              >
                {wanted ? "Write them again" : "Write release notes"}
              </button>
              {/* One file rather than three, with a column saying which of the
                  three parts a row belongs to: it is one comparison, and
                  three of anything that has to be kept together is three
                  chances to send somebody two of them. */}
              <a
                className="btn quiet"
                href={`/v1/products/${encodeURIComponent(product)}/comparison.csv?${asked}`}
              >
                CSV
              </a>
              <a
                className="btn quiet"
                href={`/v1/products/${encodeURIComponent(product)}/comparison.json?${asked}`}
              >
                JSON
              </a>
              {notes.data !== undefined && (
                <button
                  type="button"
                  className="btn quiet"
                  onClick={() => {
                    void navigator.clipboard?.writeText(notes.data);
                    setCopied(true);
                  }}
                >
                  {copied ? "Copied" : "Copy"}
                </button>
              )}
            </div>
            {wanted && notes.isPending && <Loading />}
            {notes.isError && (
              <Failed error={notes.error} what="The release notes could not be written." />
            )}
            {notes.data !== undefined && <pre className="notes">{notes.data}</pre>}
          </>
        )}
      </div>
    </>
  );
}

// A build is a stream and a variant together, never one of them: the same
// branch built two ways is two builds, and comparing across the pair without
// saying so is how a release note reports the wrong hardware.
function Pick({
  label,
  stream,
  variant,
  streams,
  variants,
  onStream,
  onVariant,
}: {
  label: string;
  stream: string;
  variant: string;
  streams: string[];
  variants: string[];
  onStream: (value: string) => void;
  onVariant: (value: string) => void;
}) {
  return (
    <span style={{ display: "inline-flex", gap: 5, alignItems: "center" }}>
      <select
        aria-label={`${label} stream`}
        style={{ width: "auto" }}
        value={stream}
        onChange={(event) => onStream(event.target.value)}
      >
        <option value="">Select a branch or tag</option>
        {streams.map((name) => (
          <option key={name} value={name}>
            {name}
          </option>
        ))}
      </select>
      <select
        aria-label={`${label} variant`}
        style={{ width: "auto" }}
        value={variant}
        onChange={(event) => onVariant(event.target.value)}
      >
        <option value="">Select a variant</option>
        {variants.map((name) => (
          <option key={name} value={name}>
            {name}
          </option>
        ))}
      </select>
    </span>
  );
}

// The server's own shape rather than a copy of it, so a field the server
// grows arrives here instead of being silently absent.
type Changed = Body<"ChangedBody">;

// Marks read as sentences rather than as field values, because a reader of a
// release note is being told what happened rather than shown a column.
const WENT: Record<string, string> = {
  upgraded: "Upgraded",
  revised: "Revised",
  patched: "Patched",
  removed: "Removed",
  superseded: "Superseded",
  unexplained: "Unexplained",
};

function Columns({
  fixed,
  closed,
  newly,
  still,
  runsAt,
}: {
  fixed: Changed[];
  closed: Changed[];
  newly: Changed[];
  still: Changed[];
  runsAt: string;
}) {
  return (
    <div className="cmp">
      {/* Two columns, because they are two different things and the count of
          the first is what a release coordinator quotes. The server decides
          which row goes where, through the one function the release note and
          the remediation rate also read: a column that made the judgment for
          itself put two scanner faults under "Fixed". */}
      <Column
        kind="was-fixed"
        title="Fixed"
        rows={fixed}
        note="Upgraded, patched, removed, or a recorded flaw declared fixed."
      />
      <Column
        kind="not-fixed"
        title="Closed, not fixed"
        rows={closed}
        runsAt={runsAt}
        note="Superseded means the version moved and took the issue with it. Unexplained means the component is unchanged and the scanner stopped reporting it, which is a fault to look into."
      />
      <Column kind="newly" title="Introduced" rows={newly} />
      {/* What is shipping anyway, and why. The list of what is still there
          is what a release is signed off against, and without what stands
          about each row an approved not-applicable and something nobody has
          looked at read identically — which are opposite answers to the
          question being asked. */}
      <Column
        kind="still"
        title="Unchanged"
        rows={still}
        signOff
        note="A version it arrived from means the upgrade did not reach the fix. What stands about each is beside it: shipping with a known issue is a decision somebody made."
      />
    </div>
  );
}

function Column({
  kind,
  title,
  rows,
  note,
  runsAt,
  signOff,
}: {
  kind: string;
  title: string;
  rows: Changed[];
  note?: string;
  runsAt?: string;
  // signOff draws what stands about each row, and offers the one narrowing a
  // release coordinator actually works from: what nobody has decided.
  signOff?: boolean;
}) {
  const [all, setAll] = useState(false);
  const [blockers, setBlockers] = useState(false);
  const kept = blockers ? rows.filter((row) => row.state !== "agreed") : rows;
  const shown = all ? kept : kept.slice(0, SHOWN);

  return (
    <div className={`col ${kind}`}>
      <header>
        <h4>{title}</h4>
        <span className="n">{kept.length.toLocaleString()}</span>
      </header>
      {signOff && rows.length > 0 && (
        <label className="hint">
          <input
            type="checkbox"
            checked={blockers}
            onChange={(e) => {
              setBlockers(e.target.checked);
              setAll(false);
            }}
          />{" "}
          Only what nobody has agreed to
        </label>
      )}
      {kept.length === 0 ? (
        <p className="hint" style={{ margin: 0 }}>
          {blockers ? "Everything here has been agreed to." : "Nothing."}
        </p>
      ) : (
        <ul>
          {shown.map((row) => (
            <li key={`${row.vulnerability} ${row.component}`}>
              <span className="top">
                <span className="id">{row.vulnerability}</span>
                {row.severity && <Severity word={row.severity} />}
              </span>
              <span className="why">
                {row.because && (
                  <span className={`mark ${row.because}`}>{WENT[row.because] ?? row.because}</span>
                )}
                <span className="id">{row.component}</span>
                {row.arrived_from && (
                  <>
                    {" — upgraded from "}
                    <span className="id">{row.arrived_from}</span>
                    {", and the issue came with it"}
                  </>
                )}
                {/* The run that stopped reporting it. Being told a closure is
                    unexplained and given nowhere to look leaves the reader
                    with the fault and no way to start on it. */}
                {runsAt && row.because === "unexplained" && row.closed_by_run && (
                  <>
                    {" — "}
                    <Link to={`${runsAt}/${row.closed_by_run}`}>the run that stopped</Link>
                  </>
                )}
              </span>
              {/* What stands about it: the outcome where every place of it
                  was answered the same way, the state otherwise, and the
                  date it is due. The row nobody has said anything about is
                  the one a coordinator is looking for. */}
              {signOff && (
                <span className="why">
                  {row.outcome ? (
                    <Outcome outcome={row.outcome} />
                  ) : (
                    <span className={`state ${drawn(row.state)}`}>{said(row.state)}</span>
                  )}
                  {row.justification && <span className="hint"> {row.justification}</span>}
                  {row.due && <span className="hint"> · due {row.due}</span>}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
      {kept.length > SHOWN && (
        <p className="more">
          <button type="button" className="linkish" onClick={() => setAll(!all)}>
            {all ? "Show fewer" : `Show all ${kept.length.toLocaleString()}`}
          </button>
        </p>
      )}
      {note && (
        <p className="reading" style={{ marginTop: 8 }}>
          {note}
        </p>
      )}
    </div>
  );
}
