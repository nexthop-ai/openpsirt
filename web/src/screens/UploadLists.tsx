// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Body } from "../api/client";
import { unwrap } from "../api/queries";
import { settingsAt, type Build } from "../app/routes";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Paged } from "../ui/Paged";
import { Wide } from "../ui/Wide";
import { at as minute } from "../ui/when";

// A page of a list read here.
const PAGE = 50;

// How often a page holding an unsettled run is asked for again.
const UNSETTLED = 15_000;

// The vocabulary the server declares for what became of a run, read out of the
// generated client rather than retyped.
type RunStatus = Body<"AnalysisReceiptBody">["status"];

// What each status is called, its color, and what it means on hover. Keyed on
// the generated union, so a status the server adds is a compile error here.
const RUN_STATES: Record<RunStatus, { cls: string; label: string; means: string }> = {
  queued: { cls: "waiting", label: "Queued", means: "Stored, not yet read" },
  waiting: {
    cls: "waiting",
    label: "Waiting for inventory",
    means: "Read once this build's inventory is",
  },
  applied: { cls: "agreed", label: "Applied", means: "Read and applied" },
  superseded: {
    cls: "open",
    label: "Superseded",
    means: "Built before a run already applied. Kept, changes nothing",
  },
  failed: { cls: "bad", label: "Failed", means: "The reason is beside it" },
};

// The static analysis runs one build was sent, newest first, and the last
// upload of each series that was turned away.
export function AnalysisRuns({ build }: { build: Build }) {
  const { product, stream, variant } = build;
  const [offset, setOffset] = useState(0);
  const runs = useQuery({
    queryKey: ["analyses", product, stream, variant, offset],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams/{stream}/variants/{variant}/analyses", {
          params: { path: { product, stream, variant }, query: { limit: PAGE, offset } },
        }),
      ),
    // Asked again only while a run on the page is still to be read.
    refetchInterval: (query) =>
      query.state.data?.items?.some((r) => r.status === "queued" || r.status === "waiting")
        ? UNSETTLED
        : false,
  });

  if (runs.isPending) return <Loading />;
  if (runs.isError) {
    return <Failed error={runs.error} what="The static analysis runs could not be read." />;
  }
  const items = runs.data.items ?? [];
  const refused = runs.data.refused ?? [];

  return (
    <>
      {refused.map((each) => (
        <div className="alert" key={`${each.series}-${each.at}`} style={{ marginBottom: 10 }}>
          <strong>
            {each.series || "A run naming no series"} turned away {minute(each.at)}
          </strong>
          <span>{each.reason}</span>
        </div>
      ))}

      {items.length === 0 ? (
        <Empty
          title="No static analysis runs."
          detail="A build pipeline sends them with openpsirt-analysis."
        />
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Received</th>
                <th>Built</th>
                <th>Series</th>
                <th>Tool</th>
                <th>Status</th>
                <th className="num" title="Results the build did not hold open">
                  Opened
                </th>
                <th className="num" title="Open results this run reported again">
                  Seen again
                </th>
                <th
                  className="num"
                  title="Open results this comparable run did not report. Blank where it isn't comparable"
                >
                  Not reproduced
                </th>
              </tr>
            </thead>
            <tbody>
              {items.map((run) => {
                const state = RUN_STATES[run.status];
                return (
                  <tr key={run.run_id}>
                    <td>{minute(run.received_at)}</td>
                    <td className="hint">{minute(run.built_at)}</td>
                    <td className="id">{run.series}</td>
                    <td className="hint">
                      {run.tool ? `${run.tool} ${run.tool_version ?? ""}` : "—"}
                    </td>
                    <td>
                      <span className={`state ${state.cls}`} title={state.means}>
                        {state.label}
                      </span>
                      {run.failure && (
                        <div className="hint" style={{ marginTop: 4 }}>
                          {run.failure}
                        </div>
                      )}
                    </td>
                    <td className="num">{run.counts?.opened.toLocaleString() ?? ""}</td>
                    <td className="num">{run.counts?.seen.toLocaleString() ?? ""}</td>
                    <td className="num" title={run.not_comparable || undefined}>
                      {run.comparable ? (run.counts?.not_reproduced.toLocaleString() ?? "") : ""}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Wide>
      )}
      <Paged
        shown={items.length}
        total={runs.data.total}
        offset={offset}
        limit={PAGE}
        onGo={setOffset}
      />
    </>
  );
}

// What each kind of document is called, and the path its list is read from.
const DOCUMENTS = {
  vex: { none: "No VEX documents uploaded.", path: "/v1/products/{product}/vex-statements" },
  "supplier-advisory": {
    none: "No supplier advisories.",
    path: "/v1/products/{product}/supplier-advisories",
  },
} as const;

// The VEX documents or supplier advisories one product holds, one row per
// document however often it was uploaded, the most recently changed first.
export function Documents({ product, type }: { product: string; type: keyof typeof DOCUMENTS }) {
  const [offset, setOffset] = useState(0);
  const kind = DOCUMENTS[type];
  const held = useQuery({
    queryKey: ["upload-documents", product, type, offset],
    queryFn: async () =>
      unwrap(
        await api.GET(kind.path, {
          params: { path: { product }, query: { limit: PAGE, offset } },
        }),
      ),
  });

  if (held.isPending) return <Loading />;
  if (held.isError) return <Failed error={held.error} what="The documents could not be read." />;
  const items = held.data.items ?? [];
  const advisory = type === "supplier-advisory";

  return (
    <>
      {items.length === 0 ? (
        <Empty title={kind.none} detail="An administrator uploads them under Settings.">
          <Link to={settingsAt("suppliers")} className="linkish">
            Supplier settings
          </Link>
        </Empty>
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Publisher</th>
                {advisory && <th>Advisory</th>}
                <th>File</th>
                <th className="num" title="Statements that stand">
                  Standing
                </th>
                <th
                  className="num"
                  title="Statements a later copy no longer made. Kept, not applied"
                >
                  Set aside
                </th>
                <th>First received</th>
                <th title="When an upload last changed what it says">Changed</th>
              </tr>
            </thead>
            <tbody>
              {items.map((doc) => (
                <tr key={`${doc.publisher} ${doc.identifier ?? ""}`}>
                  <td>{doc.publisher}</td>
                  {advisory && <td className="id">{doc.identifier}</td>}
                  <td className="hint" title={`SHA-256 ${doc.digest}`}>
                    {/* An address a feed fetched it from is shown and not
                        linked: it is somebody else's, and nothing here checked
                        where it leads. */}
                    {doc.fetched ? (
                      <span title={doc.document}>From a feed</span>
                    ) : (
                      doc.document || "—"
                    )}
                  </td>
                  <td className="num">{doc.standing.toLocaleString()}</td>
                  <td className="num">{doc.set_aside.toLocaleString()}</td>
                  <td className="hint">{minute(doc.first_received_at)}</td>
                  <td>{minute(doc.changed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Wide>
      )}
      <Paged
        shown={items.length}
        total={held.data.total}
        offset={offset}
        limit={PAGE}
        onGo={setOffset}
      />
    </>
  );
}
