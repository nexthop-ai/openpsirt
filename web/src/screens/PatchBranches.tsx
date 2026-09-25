// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import type { components } from "../api/schema";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Wide } from "../ui/Wide";
import { on, since } from "../ui/when";
import { humaneBytes } from "./bytes";

type Repository = components["schemas"]["PatchRepositoryBody"];

// One page of the report, the most the API returns at once.
const PAGE = 200;

// How often the panel asks again while a visit is under way, so the count
// moves while somebody watches it.
const LIVE = 10_000;

// Where the patch branch lookups stand, in the order the pass works: the visit
// under way, what comes next, what failed, and what is done.
//
// On the System screen because it fails silently: a host that stopped
// answering leaves labels missing from findings, and nothing on a finding
// says so.
export function PatchBranches() {
  const [pages, setPages] = useState(1);
  const progress = useQuery({
    queryKey: ["patch-branches", pages],
    queryFn: async () => {
      const first = unwrap(
        await api.GET("/v1/patch-branches", { params: { query: { limit: PAGE } } }),
      );
      const rows = [...(first.repositories ?? [])];
      for (let page = 1; page < pages && rows.length < first.total; page++) {
        const more = unwrap(
          await api.GET("/v1/patch-branches", {
            params: { query: { limit: PAGE, offset: page * PAGE } },
          }),
        );
        rows.push(...(more.repositories ?? []));
      }
      return { ...first, repositories: rows };
    },
    refetchInterval: (query) =>
      query.state.data?.repositories?.some((row) => row.state === "working") ? LIVE : false,
  });

  if (progress.isPending) return <Loading />;
  if (progress.isError) {
    return (
      <Failed
        error={progress.error}
        what="How far the patch branch lookups have got could not be read."
      />
    );
  }
  const it = progress.data;
  const rows = it.repositories;
  const held = it.held_bytes ?? 0;
  const now = rows.filter((row) => row.state === "working");
  const next = rows.filter(
    (row) => row.state === "waiting" || (row.position && row.state !== "working"),
  );
  const failed = rows.filter((row) => row.state === "failed");
  const excluded = rows.filter((row) => row.state === "excluded");
  const done = rows.filter((row) => row.state === "done");

  return (
    <section className="panel">
      <h3>Patch branches</h3>
      <p className="hint" style={{ marginTop: 0 }}>
        {it.on ? "On" : "Off, in the deployment's configuration"} · {it.looked.toLocaleString()} of{" "}
        {it.commits.toLocaleString()} commits looked up · from {it.links.toLocaleString()} patch
        links
        {held > 0 && ` · copies ${humaneBytes(String(held))}`}
      </p>
      {rows.length === 0 ? (
        <Empty
          title="No patch link names a commit."
          detail="Only links to a commit in a repository are looked up."
        />
      ) : (
        <>
          {now.map((row) => (
            <Visit key={row.url} row={row} />
          ))}
          {next.length > 0 && <Next rows={next} />}
          {failed.length > 0 && <FailedRows rows={failed} />}
          {excluded.length > 0 && (
            <p className="hint">Excluded: {excluded.map((row) => row.host).join(", ")}</p>
          )}
          {done.length > 0 && <Done rows={done} />}
          {rows.length < it.total && (
            <button type="button" className="linkish" onClick={() => setPages(pages + 1)}>
              Show more · {rows.length.toLocaleString()} of {it.total.toLocaleString()}
            </button>
          )}
        </>
      )}
    </section>
  );
}

// The visit under way: which repository, what it is doing, and how far.
function Visit({ row }: { row: Repository }) {
  const looked = row.visit_looked ?? 0;
  const due = looked + (row.due ?? 0);
  return (
    <div className="patchnow">
      <h4>Now</h4>
      <p className="id">{row.url}</p>
      {row.step === "looking-up" ? (
        <>
          <progress className="patchbar" max={Math.max(due, 1)} value={looked} />
          <p className="hint">
            Looking up {looked.toLocaleString()} of {due.toLocaleString()} commits
          </p>
        </>
      ) : (
        <p className="hint">Fetching{row.fetched_at && <>, started {since(row.fetched_at)}</>}</p>
      )}
    </div>
  );
}

// What comes next, in the order the pass takes it.
function Next({ rows }: { rows: Repository[] }) {
  return (
    <>
      <h4>Next</h4>
      <Wide>
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Repository</th>
              <th>Due</th>
              <th>Worst</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.url} className="row">
                <td className="hint">{row.position ?? "—"}</td>
                <td className="id">{row.url}</td>
                <td className="hint">{(row.due ?? row.commits - row.looked).toLocaleString()}</td>
                <td className="hint">{row.worst || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Wide>
    </>
  );
}

// What failed, why, and when it is tried again.
function FailedRows({ rows }: { rows: Repository[] }) {
  return (
    <>
      <h4>Failed</h4>
      <Wide>
        <table>
          <thead>
            <tr>
              <th>Repository</th>
              <th>Why</th>
              <th>Retry</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.url} className="row">
                <td className="id">{row.url}</td>
                <td className="hint" title={row.reason}>
                  {firstLine(row.reason)}
                </td>
                <td className="hint">{row.retry_at ? on(row.retry_at) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Wide>
    </>
  );
}

// What is done, folded away.
function Done({ rows }: { rows: Repository[] }) {
  return (
    <details>
      <summary>Done · {rows.length.toLocaleString()}</summary>
      <Wide>
        <table>
          <thead>
            <tr>
              <th>Repository</th>
              <th>Looked up</th>
              <th>Copy</th>
              <th>Finished</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.url} className="row">
                <td className="id">{row.url}</td>
                <td className="hint">
                  {row.looked.toLocaleString()}
                  {row.looked > row.found &&
                    ` · ${(row.looked - row.found).toLocaleString()} not in repository`}
                </td>
                <td className="hint">
                  {row.held_bytes ? humaneBytes(String(row.held_bytes)) : "—"}
                </td>
                <td className="hint">{row.reached_at ? since(row.reached_at) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Wide>
    </details>
  );
}

// The first line of a host's error, which is the part that says what went
// wrong. The whole of it is on hover.
function firstLine(reason?: string): string {
  const line = (reason ?? "").split("\n")[0] ?? "";
  return line.length > 120 ? `${line.slice(0, 119)}…` : line;
}
