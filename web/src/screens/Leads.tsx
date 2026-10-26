// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { mayOf, useWho } from "../app/session";
import { fileAt } from "../api/links";
import { PAGE, leadsQuery, useLeads, type LeadState } from "../api/leads";
import { leadAt, leadRulesAt, leadsAt, productAt } from "../app/routes";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Paged } from "../ui/Paged";
import { useRowOpener } from "../ui/opens";
import { Wide } from "../ui/Wide";
import { on } from "../ui/when";
import { LEAD_STATES, LEAD_TONES, located, stateSaid } from "./leads";

// A product's static analysis leads. With no state it is the queue: open
// leads nothing waits on, the baseline left out. A state lists that state's
// leads instead, which is how the baseline is searched.
export function Leads() {
  const { product = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const asked = params.get("state") ?? "";
  const state = Object.hasOwn(LEAD_STATES, asked) ? (asked as LeadState) : undefined;
  const stream = params.get("stream") ?? undefined;
  const variant = params.get("variant") ?? undefined;
  const series = params.get("series") ?? undefined;
  const [offset, setOffset] = useState(0);
  const listed = useLeads(product, { state, stream, variant, series, offset });
  const opener = useRowOpener();
  const reads = !!mayOf(useWho().data, product)?.reads_internal;

  const go = (next?: LeadState) => {
    setOffset(0);
    setParams(
      Object.fromEntries(
        Object.entries({ state: next, stream, variant, series }).filter(
          ([, value]) => value !== undefined,
        ),
      ) as Record<string, string>,
      { replace: true },
    );
  };

  // The list on screen as a file: the same narrowing, every row of it.
  const file = (format: "csv" | "json") =>
    fileAt("/v1/products/{product}/leads.{format}", format, {
      path: { product },
      query: leadsQuery({ state, stream, variant, series }),
    });
  const counts = listed.data?.states ?? {};
  const rows = listed.data?.items ?? [];

  return (
    <div>
      <div className="screen-head">
        <h2>Leads</h2>
        <p>
          Static analysis results in <Link to={productAt(product)}>{product}</Link>
          {stream && ` · ${stream}`}
          {variant && ` · ${variant}`}
          {series && ` · ${series}`}
        </p>
        <span style={{ marginLeft: "auto" }}>
          <Link className="btn quiet" to={leadRulesAt(product)}>
            Dismissal rules
          </Link>{" "}
          <a className="btn quiet" href={file("csv")}>
            CSV
          </a>{" "}
          <a className="btn quiet" href={file("json")}>
            JSON
          </a>
        </span>
      </div>

      <div className="tabs2">
        <button type="button" className="tab2" aria-selected={!state} onClick={() => go()}>
          Queue
        </button>
        {(Object.keys(LEAD_STATES) as LeadState[]).map((each) => (
          <button
            key={each}
            type="button"
            className="tab2"
            aria-selected={state === each}
            onClick={() => go(each)}
          >
            {LEAD_STATES[each]} <span className="n">{(counts[each] ?? 0).toLocaleString()}</span>
          </button>
        ))}
      </div>

      {!state &&
        listed.data &&
        (listed.data.waiting > 0 || listed.data.ruled > 0 || listed.data.past_end_of_life > 0) && (
          <p className="hint">
            {[
              listed.data.waiting > 0 && (
                <span key="waiting">
                  {listed.data.waiting.toLocaleString()} waiting for approval
                </span>
              ),
              listed.data.ruled > 0 && (
                <Link
                  key="ruled"
                  to={leadsAt(product, { state: "dismissed", stream, variant, series })}
                >
                  {listed.data.ruled.toLocaleString()} dismissed by a rule
                </Link>
              ),
              listed.data.past_end_of_life > 0 && (
                <span key="ended" title="Open only in releases past their end of life">
                  {listed.data.past_end_of_life.toLocaleString()} open only past end of life
                </span>
              ),
            ]
              .filter(Boolean)
              .flatMap((each, i) => (i === 0 ? [each] : [" · ", each]))}
          </p>
        )}

      {listed.isPending ? (
        <Loading />
      ) : listed.isError ? (
        <Failed error={listed.error} what="The leads could not be read." />
      ) : rows.length === 0 ? (
        <Empty
          title={state ? `No ${stateSaid(state).toLowerCase()} leads.` : "Nothing in the queue."}
          detail={
            reads
              ? undefined
              : "Leads are internal. Reading them takes internal-read on the product."
          }
        />
      ) : (
        <>
          <Wide>
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Location</th>
                  <th>Message</th>
                  <th>Build</th>
                  <th>Opened</th>
                  <th>State</th>
                  <th>Assigned to</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const to = leadAt(
                    { product, stream: row.stream, variant: row.variant },
                    row.place,
                  );
                  return (
                    <tr
                      key={`${row.place}/${row.stream}/${row.variant}`}
                      className="row opens"
                      onClick={opener(to)}
                    >
                      <td style={{ whiteSpace: "nowrap" }}>
                        <Link className="id" to={to}>
                          {row.rule}
                        </Link>
                      </td>
                      <td className="mono" title={row.function}>
                        {located(row.path, row.line)}
                      </td>
                      <td>
                        {row.withheld ? (
                          <span className="hint" title="Part of a case you are not on.">
                            Withheld
                          </span>
                        ) : (
                          row.message
                        )}
                      </td>
                      <td className="hint" style={{ whiteSpace: "nowrap" }}>
                        {row.stream} · {row.variant}
                        {row.builds > 1 && ` +${row.builds - 1}`}
                      </td>
                      <td className="hint" style={{ whiteSpace: "nowrap" }}>
                        {on(row.opened)}
                      </td>
                      <td>
                        <span className={`state ${LEAD_TONES[row.state]}`}>
                          {stateSaid(row.state)}
                        </span>
                        {row.third_party && (
                          <span
                            className="state closed"
                            title="The analysis run declared this path third-party"
                          >
                            {" "}
                            Third-party
                          </span>
                        )}
                      </td>
                      <td className="hint" style={{ whiteSpace: "nowrap" }}>
                        {row.assigned_to && (row.assigned_to_name ?? row.assigned_to)}
                        {row.assigned_team && " · team"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </Wide>
          <Paged
            shown={rows.length}
            total={listed.data?.total}
            offset={offset}
            limit={PAGE}
            onGo={setOffset}
          />
        </>
      )}
    </div>
  );
}
