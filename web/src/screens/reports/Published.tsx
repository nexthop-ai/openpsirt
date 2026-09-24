// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import { unwrap } from "../../api/queries";
import { useScope } from "../../app/scope";
import { Empty } from "../../ui/Empty";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { on } from "../../ui/when";
import { Sheet } from "./Sheet";
import {
  PeriodPicker,
  WindowPicker,
  asked,
  coveringPeriod,
  daysAsked,
  periodAsked,
} from "./Window";
import { Wide } from "../../ui/Wide";

// The window back. A year by default, because publishing is rare enough that a
// month of it is usually nothing and reads as a tool that is not working.
const WINDOWS = [90, 365, 3650] as const;

// The advisories published, and the ones published twice.
//
// Answered per flaw until now. That is the right shape for somebody about
// to publish a revision — has one gone out, and is what is out still what we
// would generate — and the wrong shape for the question a period asks.
//
// Advisories are about flaws in our own product, recorded here by hand.
// Known issues in third-party components are tracked and fixed rather than
// published about; the document for those is a VEX statement per build, which
// the catalog offers as a file.
export function Published() {
  const at = useScope();
  const [params] = useSearchParams();
  const days = daysAsked(params, 365);
  // An auditor asking what went out in a financial year names two dates; the
  // window answers "lately", which is the other question.
  const period = periodAsked(params);
  const when = asked(period, days);
  const product = at.product ?? "";

  const gone = useQuery({
    queryKey: ["published", product, when],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/advisories/published", {
          params: { query: { ...when, ...(product ? { product } : {}) } },
        }),
      ),
  });

  const rows = gone.data?.items ?? [];
  const revisions = rows.filter((row) => (row.ordinal ?? 1) > 1).length;

  return (
    <Sheet
      settled={gone.isSuccess}
      name="Advisories issued"
      answers="what has been published about our own flaws, and what was published twice."
      asked={coveringPeriod(period, days)}
    >
      <WindowPicker offered={WINDOWS} days={days} />
      <PeriodPicker period={period} />

      {gone.isPending ? (
        <Loading />
      ) : gone.isError ? (
        <Failed error={gone.error} what="The published advisories could not be read." />
      ) : rows.length === 0 ? (
        <section className="panel">
          <Empty
            title="Nothing has been published in this window."
            detail="Advisories cover flaws in our own products. Third-party components are tracked, not published about."
          />
        </section>
      ) : (
        <section className="panel">
          <h3>
            {rows.length.toLocaleString()} {rows.length === 1 ? "advisory" : "advisories"}
            {revisions > 0 && `, ${revisions.toLocaleString()} of them a revision`}
          </h3>
          <p className="hint" style={{ marginTop: 0 }}>
            Newest first.
          </p>
          <Wide>
            <table>
              <thead>
                <tr>
                  <th>Advisory</th>
                  <th>Covers</th>
                  <th>Revision</th>
                  <th>Published</th>
                  <th>By</th>
                  {/* What the sentence above promises. It is what makes "is
                      what is published still what we would generate" a
                      question anybody can answer. */}
                  <th>Digest</th>
                  <th>Said</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={`${row.advisory} ${row.ordinal}`} className="row">
                    {/* The document it went out as. There is no screen for
                        an advisory in its own right, so this goes to what the
                        report is about: the document itself. */}
                    <td>
                      <a
                        className="id linkish"
                        href={`/v1/advisories/${encodeURIComponent(row.advisory)}/document`}
                      >
                        {row.advisory}
                      </a>
                      {row.title && <div className="hint">{row.title}</div>}
                    </td>
                    {/* Both counts, because one issue in three products and
                        three issues in one are different documents and a
                        single number reads the same for each. */}
                    <td className="hint">
                      {row.issues} {row.issues === 1 ? "issue" : "issues"} in {row.products}{" "}
                      {row.products === 1 ? "product" : "products"}
                    </td>
                    <td>
                      {(row.ordinal ?? 1) > 1 ? (
                        <span className="state open">revision {(row.ordinal ?? 1) - 1}</span>
                      ) : (
                        <span className="hint">first</span>
                      )}
                    </td>
                    <td>{on(row.issued_at)}</td>
                    <td className="id">{row.issued_by}</td>
                    <td className="id" title={row.digest}>
                      {row.digest ? row.digest.slice(0, 12) : <span className="hint">—</span>}
                    </td>
                    <td className="hint" style={{ maxWidth: "40ch" }}>
                      {row.summary || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Wide>
        </section>
      )}
    </Sheet>
  );
}
