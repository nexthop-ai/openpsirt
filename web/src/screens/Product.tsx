// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link, useParams } from "react-router-dom";
import { Loading } from "../ui/Loading";
import { on } from "../ui/when";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { UNNARROWED } from "../app/scope";
import { Failed } from "../ui/Failed";
import { Wide } from "../ui/Wide";
import { mayOf, useWho } from "../app/session";
import { useRulings } from "../api/intake";
import {
  buildFindingsAt,
  inboxAt,
  inventoriesAt,
  productFindingsAt,
  reviewQueueAt,
} from "../app/routes";

// One product's own page.
//
// The state of one product is otherwise five requests and a spreadsheet —
// what is open per build, how much is overdue, how much has been decided, when
// each build was last scanned — every piece of which exists and none of which
// sits together. The products table is an
// administration surface: a triage line in a select and an end-of-support date
// in an input, which is a different job from reading how something is going.
//
// Every number here opens the list that produced it. A figure somebody
// cannot follow is one they stop trusting, and then they go and count it
// themselves.
export function Product() {
  const { product = "" } = useParams();
  const who = useWho();
  // The inbox asks what reading a report asks: reading undisclosed work.
  const mayReadReports = !!mayOf(who.data, product)?.reads_private;
  const waitingRulings = useRulings(product, true, 0, mayReadReports);
  const overview = useQuery({
    queryKey: ["overview", product],
    queryFn: async () =>
      unwrap(await api.GET("/v1/products/{product}/overview", { params: { path: { product } } })),
  });

  if (overview.isPending) return <Loading />;
  if (overview.isError) {
    return <Failed error={overview.error} what="That product could not be read." />;
  }
  const it = overview.data;
  if (!it) return null;
  const builds = it.builds ?? [];
  // The list as the figures here count it, with one more filter where a figure
  // is narrower.
  const counted = (more = "") => new URLSearchParams(UNNARROWED + more);

  return (
    <div>
      <div className="screen-head">
        <h2>{it.display_name || it.name}</h2>
        <p>
          <span className="id">{it.name}</span>
          {it.triage_floor ? (
            <> · triaged at {it.triage_floor} and above</>
          ) : (
            <> · triaged at whatever the deployment says</>
          )}
          {it.end_of_life && <> · out of support {it.end_of_life}</>}
          {mayReadReports && (
            <>
              {" "}
              · <Link to={inboxAt(product)}>Inbox</Link>
              {(waitingRulings.data?.total ?? 0) > 0 && (
                <>
                  {" "}
                  (
                  <Link to={inboxAt(product, true)}>
                    {(waitingRulings.data?.total ?? 0).toLocaleString()} waiting for approval
                  </Link>
                  )
                </>
              )}
            </>
          )}
        </p>
      </div>

      {/* Nothing lists a retired product, so this page is reached by a link
          somebody kept. Unmarked it reads as a product in use whose scans have
          quietly stopped. Out of support is a different thing and says so
          above: that is a date, and this is not tracked here at all. */}
      {it.retired && (
        <div className="alert info" style={{ marginBottom: 14 }}>
          <strong>Retired</strong>
          <span>
            Nothing offers this product and no scan is accepted for it. What is here stays. Declare
            it again to bring it back.
          </span>
        </div>
      )}

      {/* The four numbers somebody asks for, each a link to the list that
          produced it. Overdue and waiting are the two that decide whether
          anything needs doing today.

          Each opens the list unnarrowed. The list writes three narrowings into
          its own address when the address says nothing, and the figures are
          counted with none of them — so without this every number here opened
          a list with fewer rows in it than the number said. */}
      <div className="kpis">
        <Link className="kpi" to={productFindingsAt(product, counted())}>
          <span className="l">Open · {it.name}</span>
          <span className="n">{(it.open ?? 0).toLocaleString()}</span>
          <span className="d">issues at components, as the list counts them</span>
        </Link>
        <Link
          className={`kpi${(it.overdue ?? 0) > 0 ? " urgent" : ""}`}
          to={productFindingsAt(product, counted("&running=overdue"))}
        >
          <span className="l">Past a deadline</span>
          <span className="n">{(it.overdue ?? 0).toLocaleString()}</span>
          <span className="d">already late, across every build</span>
        </Link>
        <Link className="kpi" to={productFindingsAt(product, counted("&state=undecided"))}>
          <span className="l">Nobody has argued about</span>
          <span className="n">{(it.undecided ?? 0).toLocaleString()}</span>
          <span className="d">no place has a decision of any kind</span>
        </Link>
        <Link className="kpi" to={reviewQueueAt({ product })}>
          <span className="l">Waiting on a second person</span>
          <span className="n">{(it.waiting ?? 0).toLocaleString()}</span>
          <span className="d">claims here that nobody has agreed to</span>
        </Link>
      </div>

      <div className="card" style={{ marginTop: 14 }}>
        <h3>Builds</h3>
        {builds.length === 0 ? (
          <Empty
            title="Nothing is declared here yet."
            detail="A build is a branch or tag and a variant. Declare them, and an upload can be filed against one."
          />
        ) : (
          <Wide>
            <table>
              <thead>
                <tr>
                  <th>Build</th>
                  <th className="num">Open</th>
                  <th className="num">Overdue</th>
                  <th className="num">Exploited</th>
                  <th className="num">Undecided</th>
                  <th className="num">Decided</th>
                  <th>Last scanned</th>
                </tr>
              </thead>
              <tbody>
                {builds.map((row) => {
                  const build = { product, stream: row.stream ?? "", variant: row.variant ?? "" };
                  return (
                    <tr key={`${row.stream} ${row.variant}`} className="row">
                      <td>
                        <Link to={buildFindingsAt(build, counted())} className="id">
                          {row.stream}
                        </Link>{" "}
                        <span className="hint">·</span> <span className="id">{row.variant}</span>
                        {row.out_of_support && (
                          <>
                            {" "}
                            <span
                              className="vchip"
                              title="Out of support. Nothing here is late, and a quiet build is expected"
                            >
                              out of support
                            </span>
                          </>
                        )}
                      </td>
                      <td className="num">{(row.open ?? 0).toLocaleString()}</td>
                      <td className="num">
                        {row.overdue ? (
                          <Link
                            to={buildFindingsAt(build, counted("&running=overdue"))}
                            className="due over"
                          >
                            {row.overdue.toLocaleString()}
                          </Link>
                        ) : (
                          <span className="hint">—</span>
                        )}
                      </td>
                      <td className="num">
                        {row.exploited ? (
                          <Link to={buildFindingsAt(build, counted("&exploited=1"))}>
                            {row.exploited.toLocaleString()}
                          </Link>
                        ) : (
                          <span className="hint">—</span>
                        )}
                      </td>
                      <td className="num">
                        {row.undecided ? (
                          <Link to={buildFindingsAt(build, counted("&state=undecided"))}>
                            {row.undecided.toLocaleString()}
                          </Link>
                        ) : (
                          <span className="hint">—</span>
                        )}
                      </td>
                      <td className="num">
                        {row.agreed ? (
                          <Link to={buildFindingsAt(build, counted("&state=agreed"))}>
                            {row.agreed.toLocaleString()}
                          </Link>
                        ) : (
                          <span className="hint">—</span>
                        )}
                      </td>
                      <td className="hint">
                        {/* A build nobody has ever scanned is the row this
                            page exists to show: a product reads as clean when
                            part of it was never looked at. */}
                        {row.last_scan_at ? (
                          <Link to={inventoriesAt(build)}>{on(row.last_scan_at)}</Link>
                        ) : (
                          <span className="alertish">never</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </Wide>
        )}
        <p className="hint" style={{ marginTop: 8 }}>
          Issues at components. <b>Decided</b> means every place has a standing decision.
        </p>
      </div>
    </div>
  );
}
