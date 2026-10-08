// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Loading } from "../ui/Loading";
import { on } from "../ui/when";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { mayOf, useWho } from "../app/session";
import { unwrap } from "../api/queries";
import { Editor } from "../ui/Editor";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Paged } from "../ui/Paged";
import { Severity } from "../ui/Severity";
import { useRowOpener } from "../ui/opens";
import { Wide } from "../ui/Wide";
import { useReseed } from "../ui/reseed";
import { issueAt, reportFlawAt } from "../app/routes";
import { scopeQuery, useScope } from "../app/scope";

// The findings approaching disclosure, and the place an embargo is moved (a
// finding saying whether it is disclosed, a movement needing agreement).
//
// Before the date, not on it. The date arriving is the last moment to act
// rather than the first useful warning, so this lists what is running out as
// well as what has run out — and what has run out sits at the top.
//
// The list is itself a disclosure. Every row on it is undisclosed by
// definition, so a product somebody may not read undisclosed work in
// contributes nothing to it, not even a count. That narrowing is the server's.
//
// A row is one issue in one product, the unit an embargo is kept and moved in,
// naming every build in scope that carries it. The server groups them, so a
// page holds whole embargoes and the total counts embargoes.

// The rows one request carries. The server's own default, named here so
// the pager and the request cannot disagree about where a page ends.
const PAGE = 100;

// Not a character a product name or an issue identifier can hold, so a key
// cannot be two embargoes.
const APART = "\u0000";

// One embargo as a string a row, its open form and its answer are keyed on.
export function embargoKey(row: { product?: string; vulnerability?: string }): string {
  return [row.product ?? "", row.vulnerability ?? ""].join(APART);
}

// The builds a row names. The variant is said once where every build shares it,
// which is the ordinary case of one image cut from several branches.
export function buildsWords(
  builds: { stream: string; stream_name?: string; variant: string; variant_name?: string }[],
): string {
  const variants = new Set(builds.map((b) => b.variant_name || b.variant));
  if (variants.size === 1) {
    return `${builds.map((b) => b.stream_name || b.stream).join(", ")} · ${[...variants][0]}`;
  }
  return builds
    .map((b) => `${b.stream_name || b.stream} · ${b.variant_name || b.variant}`)
    .join(", ");
}

export function Disclosing() {
  const queries = useQueryClient();
  const who = useWho().data;
  const scope = scopeQuery(useScope());
  const opener = useRowOpener();
  // The distance ahead to look. Empty is this deployment's own embargo length,
  // which the server supplies: a fixed window shorter than the policy leaves
  // the screen empty while embargoes are running, and an empty screen reads as
  // "nothing is coming".
  const [days, setDays] = useState("");
  const [asking, setAsking] = useState<string | null>(null);
  // Which act is being recorded. Chosen rather than read off the date typed:
  // extending because a fix slipped and shortening because it leaked are
  // different events, and the record says which without anybody inferring it.
  const [act, setAct] = useState<"extension" | "shortening" | "disclosure">("extension");
  const [until, setUntil] = useState("");
  const [because, setBecause] = useState("");
  // What the last act answered, on the row it was taken from.
  const [said, setSaid] = useState<{ key: string; text: string; waiting: boolean } | null>(null);
  const [offset, setOffset] = useState(0);
  // A list moved to another scope starts at its own beginning.
  useReseed(JSON.stringify(scope), () => setOffset(0));

  const rows = useQuery({
    queryKey: ["disclosing", scope, days, offset],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/disclosing", {
          params: {
            query: { ...scope, ...(days ? { within: Number(days) } : {}), limit: PAGE, offset },
          },
        }),
      ),
  });
  // The shortcut to the form that gives a flaw a disclosure date, offered to
  // whoever may record an undisclosed one in the scope's product, or in any
  // product where the scope names none.
  const mayRecord = scope.product
    ? !!mayOf(who, scope.product)?.may_hide
    : !!who?.reach?.some((each) => each.may_hide);

  const move = useMutation({
    mutationFn: async (at: { product: string; vulnerability: string }) =>
      unwrap(
        act === "disclosure"
          ? await api.POST("/v1/products/{product}/issues/{vulnerability}/disclosure", {
              params: { path: at },
              body: { reason: because },
            })
          : act === "shortening"
            ? await api.POST(
                "/v1/products/{product}/issues/{vulnerability}/disclosure/shortening",
                {
                  params: { path: at },
                  body: { until, reason: because },
                },
              )
            : await api.POST("/v1/products/{product}/issues/{vulnerability}/disclosure/extension", {
                params: { path: at },
                body: { until, reason: because },
              }),
      ),
    onSuccess: (asked, at) => {
      setSaid({
        key: embargoKey(at),
        text: asked.in_force
          ? act === "disclosure"
            ? "Disclosed. The findings and everything on them are public."
            : `The date moved to ${until}.`
          : "Recorded. Nothing changes until a second person agrees.",
        waiting: !asked.in_force,
      });
      setAsking(null);
      setUntil("");
      setBecause("");
      void queries.invalidateQueries({ queryKey: ["disclosing"] });
    },
  });

  if (rows.isPending) return <Loading />;
  if (rows.isError) {
    return (
      <Failed error={rows.error} what="The findings approaching disclosure could not be read." />
    );
  }
  const items = rows.data?.items ?? [];
  const total = rows.data?.total;
  // Counted over the page, and said so. The server does not answer how many of
  // the whole list have gone past their date, and a figure computed from one
  // page while the heading beside it says the whole would be two numbers about
  // two populations under one sentence.
  const past = items.filter((row) => row.passed).length;
  const partly = total !== undefined && total > items.length;

  return (
    <>
      <div className="screen-head">
        <h2>
          Disclosing <span className="n">{(total ?? items.length).toLocaleString()}</span>
        </h2>
        <p>
          {scope.product
            ? [scope.product, scope.stream, scope.variant].filter(Boolean).join(" · ")
            : "Every product you can see"}{" "}
          · embargoes running out, soonest first. Reaching a date discloses nothing on its own.
        </p>
        <label className="field" style={{ marginLeft: "auto" }}>
          <span>Within</span>
          <select
            value={days}
            onChange={(event) => {
              // A narrowed list starts at its own beginning.
              setDays(event.target.value);
              setOffset(0);
            }}
          >
            <option value="">The whole embargo window</option>
            <option value="7">Within 7 days</option>
            <option value="30">Within 30 days</option>
            <option value="90">Within 90 days</option>
          </select>
        </label>
        {/* A shortcut to the form every flaw is reported through. Reporting a
            flaw from outside starts a date; the other way is a claim from
            outside ruled a duplicate, which is made on the report. */}
        {mayRecord && (
          <Link className="btn" to={reportFlawAt(scope.product ?? "", undefined, "outside")}>
            Record a reported flaw
          </Link>
        )}
      </div>

      {/* Where the row the act was taken from has left the list: a
          disclosure in force at once, or a date moved past the window. */}
      {said && !items.some((row) => embargoKey(row) === said.key) && (
        <div className="alert info" role="status" style={{ marginBottom: 12 }}>
          <strong>Asked</strong>
          <span>
            {said.text}{" "}
            {said.waiting && (
              <Link to="/review-queue#embargoes" className="linkish">
                Waiting in the review queue →
              </Link>
            )}
          </span>
        </div>
      )}
      {past > 0 && (
        <div className="alert" style={{ marginBottom: 12 }}>
          <strong>
            {past} past its date{partly && " on this page"}
          </strong>
          <span>The date has passed with no decision. Nothing has been published.</span>
        </div>
      )}

      {items.length === 0 ? (
        <Empty
          title="Nothing is approaching a disclosure date."
          detail="Flaws sent in from outside get a disclosure date and appear here, as do flaws an outside report duplicates."
        />
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Issue</th>
                <th>Where</th>
                <th>Discloses</th>
                <th className="num">Locations</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map((row) => {
                const key = embargoKey(row);
                const to = issueAt(row.vulnerability ?? "");
                return (
                  <tr key={key} className="row opens" onClick={opener(to)}>
                    <td>
                      <Severity word={row.severity} />
                    </td>
                    <td>
                      <Link className="id" to={to}>
                        {row.vulnerability}
                      </Link>
                      {row.summary && <div className="hint">{row.summary}</div>}
                    </td>
                    <td className="hint">
                      {[row.product_name || row.product, (row.components ?? []).join(", ")]
                        .filter(Boolean)
                        .join(" · ")}
                      <div>{buildsWords(row.builds ?? [])}</div>
                    </td>
                    <td>
                      <span className={row.passed ? "due over" : "due soon"}>
                        {on(row.disclose_at)}
                        {row.passed && " · past"}
                      </span>
                    </td>
                    <td className="num">{row.places}</td>
                    {/* The form opens in this cell, and a click in it is the
                        form's rather than the row's. */}
                    <td onClick={(event) => event.stopPropagation()}>
                      {/* Moving a date and disclosing both need undisclosed
                          triage in the row's product, which reading this list
                          does not. */}
                      {mayOf(who, row.product ?? "")?.may_hide && (
                        <button
                          type="button"
                          className="linkish"
                          onClick={() => {
                            setSaid(null);
                            setAsking(asking === key ? null : key);
                            setAct("extension");
                            setUntil("");
                            setBecause("");
                          }}
                        >
                          Move or disclose
                        </button>
                      )}
                      {/* The answer on the row the act was taken from. A
                          movement that waits is agreed to on the review
                          queue, in the section beside the ratings. */}
                      {said?.key === key && (
                        <div className="alert info" role="status" style={{ marginTop: 8 }}>
                          <strong>Asked</strong>
                          <span>
                            {said.text}{" "}
                            {said.waiting && (
                              <Link to="/review-queue#embargoes" className="linkish">
                                Waiting in the review queue →
                              </Link>
                            )}
                          </span>
                        </div>
                      )}
                      {asking === key && (
                        <div style={{ marginTop: 8 }}>
                          <label className="field">
                            <span>Act</span>
                            <select
                              value={act}
                              onChange={(event) =>
                                setAct(
                                  event.target.value as "extension" | "shortening" | "disclosure",
                                )
                              }
                            >
                              <option value="extension">Extend — it ends later</option>
                              <option value="shortening">Bring forward — it ends sooner</option>
                              <option value="disclosure">Disclose — public now</option>
                            </select>
                          </label>
                          <p className="hint">
                            {act === "disclosure"
                              ? "Can't be undone. Before the date, past a threshold, a second person agrees."
                              : "Past a threshold a second person agrees."}
                          </p>
                          {act !== "disclosure" && (
                            <label className="field">
                              <span>Until</span>
                              <input
                                type="date"
                                value={until}
                                onChange={(event) => setUntil(event.target.value)}
                              />
                            </label>
                          )}
                          <Editor
                            value={because}
                            onChange={setBecause}
                            rows={3}
                            label={
                              act === "disclosure"
                                ? "The reason it is being disclosed"
                                : act === "shortening"
                                  ? "The reason it is being brought forward"
                                  : "The reason for the extension"
                            }
                            placeholder={
                              act === "disclosure"
                                ? "What is public now, or where it was published."
                                : act === "shortening"
                                  ? "Why the embargo ends sooner — who is publishing, or what got out."
                                  : "The reason the date is moving, and what has to happen before the new one."
                            }
                          />
                          <div className="actions" style={{ marginTop: 8 }}>
                            <button
                              type="button"
                              className="btn"
                              disabled={
                                (act !== "disclosure" && !until) ||
                                !because.trim() ||
                                move.isPending
                              }
                              onClick={() =>
                                move.mutate({
                                  product: row.product ?? "",
                                  vulnerability: row.vulnerability ?? "",
                                })
                              }
                            >
                              {move.isPending ? "Asking…" : "Ask"}
                            </button>
                          </div>
                          {move.isError && (
                            <Failed
                              error={move.error}
                              what={
                                act === "disclosure"
                                  ? "That issue was not disclosed."
                                  : "That date was not moved."
                              }
                            />
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Wide>
      )}
      {/* On the screen whose whole job is catching a date before it arrives,
          a row past the first page was counted and unreachable. */}
      <Paged shown={items.length} total={total} offset={offset} limit={PAGE} onGo={setOffset} />
    </>
  );
}
