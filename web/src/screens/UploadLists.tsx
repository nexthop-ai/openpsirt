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
  const { product, branch_or_tag: branchOrTag, variant } = build;
  const [offset, setOffset] = useState(0);
  const runs = useQuery({
    queryKey: ["analyses", product, branchOrTag, variant, offset],
    queryFn: async () =>
      unwrap(
        await api.GET(
          "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/analyses",
          {
            params: {
              path: { product, branch_or_tag: branchOrTag, variant },
              query: { limit: PAGE, offset },
            },
          },
        ),
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
          detail="A build pipeline sends them with openpsirt-upload."
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
                  No longer detected
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
                      {run.comparable
                        ? (run.counts?.no_longer_detected.toLocaleString() ?? "")
                        : ""}
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
  vex: { none: "No VEX documents uploaded.", path: "/v1/products/{product}/vex-documents" },
  "supplier-advisory": {
    none: "No supplier advisories.",
    path: "/v1/products/{product}/supplier-advisories",
  },
} as const;

// What became of a document, as a state chip.
const DOCUMENT_STATES = {
  completed: { cls: "agreed", label: "Taken" },
  refused: { cls: "bad", label: "Refused" },
} as const;

type DocumentUpload = Body<"DocumentUploadBody">;

// Who sent a document: the person or key that uploaded it, or the feed that
// fetched it.
function sender(doc: DocumentUpload) {
  if (doc.fetched_by) return `${doc.fetched_by} feed`;
  return doc.uploaded_by_name || doc.uploaded_by || "—";
}

// Every VEX document or supplier advisory that arrived for one product,
// taken and turned away, newest first. They are the product's, so every build
// of it lists the same ones.
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
      <p className="hint" style={{ margin: "0 0 10px" }}>
        All builds of this product
      </p>
      {items.length === 0 ? (
        <Empty
          title={kind.none}
          detail="Administrators upload them under Settings. Uploads from before v0.11.0 aren't listed, and their statements still apply."
        >
          <Link to={settingsAt("suppliers")} className="linkish">
            Supplier settings
          </Link>
        </Empty>
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Received</th>
                <th>From</th>
                <th>Publisher</th>
                {advisory && <th>Advisory</th>}
                <th>File</th>
                <th>Status</th>
                <th className="num" title="Statements it recorded">
                  Recorded
                </th>
                <th
                  className="num"
                  title="Statements an earlier copy made that this one no longer did. Kept, not applied"
                >
                  Set aside
                </th>
              </tr>
            </thead>
            <tbody>
              {items.map((doc, i) => {
                const state = DOCUMENT_STATES[doc.status === "refused" ? "refused" : "completed"];
                return (
                  <tr key={`${doc.received_at} ${i}`}>
                    <td>{minute(doc.received_at)}</td>
                    <td className="hint" title={doc.uploaded_by || undefined}>
                      {sender(doc)}
                    </td>
                    <td>{doc.publisher || "—"}</td>
                    {advisory && <td className="id">{doc.identifier || "—"}</td>}
                    <td className="hint" title={doc.digest ? `SHA-256 ${doc.digest}` : undefined}>
                      {/* An address a feed fetched it from is shown and not
                          linked: it is somebody else's, and nothing here checked
                          where it leads. */}
                      {doc.fetched_by ? (
                        <span title={doc.document}>From the feed</span>
                      ) : (
                        doc.document || "—"
                      )}
                    </td>
                    <td>
                      <span className={`state ${state.cls}`}>{state.label}</span>
                      {doc.current && (
                        <span className="hint" title="What stands now" style={{ marginLeft: 6 }}>
                          Current
                        </span>
                      )}
                      {doc.reason && (
                        <div className="hint" style={{ marginTop: 4 }}>
                          {doc.reason}
                        </div>
                      )}
                    </td>
                    <td className="num">{doc.recorded.toLocaleString()}</td>
                    <td className="num">{doc.set_aside.toLocaleString()}</td>
                  </tr>
                );
              })}
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
