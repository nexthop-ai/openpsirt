// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom";
import { useLeadSeries, type LeadState } from "../../api/leads";
import { leadsAt } from "../../app/routes";
import { mayOf, useWho } from "../../app/session";
import { useScope } from "../../app/scope";
import { Empty } from "../../ui/Empty";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { Wide } from "../../ui/Wide";
import { LEAD_STATES } from "../leads";
import { Sheet } from "./Sheet";
import { byProduct } from "./catalog";

// The columns, in the order a lead meets them: what is worked first, then
// what has been answered.
const COLUMNS: LeadState[] = [
  "open",
  "not-reproduced",
  "dismissed",
  "not-security",
  "confirmed",
  "handed-off",
  "fixed",
];

// How many leads each analyzer holds, and how far each has been worked.
//
// Internal, like every lead, so a reader who does not read internal material
// in the product is told so rather than shown a table of zeros that reads as
// an analyzer finding nothing.
export function LeadSeries() {
  const at = useScope();
  const product = at.product ?? "";
  const reads = !!mayOf(useWho().data, product)?.reads_internal;
  const counted = useLeadSeries(reads ? product : "");
  const rows = counted.data ?? [];

  return (
    <Sheet
      settled={!reads || counted.isSuccess}
      name="Leads by analyzer"
      answers="how many leads each analyzer holds, and where they stand."
      of={byProduct(at.product)}
    >
      {product === "" ? (
        <section className="panel">
          <Empty title="Pick a product." detail="An analyzer series belongs to one product." />
        </section>
      ) : !reads ? (
        <section className="panel">
          <Empty
            title="Leads are internal."
            detail="Reading them takes internal-read on the product."
          />
        </section>
      ) : counted.isPending ? (
        <Loading />
      ) : counted.isError ? (
        <Failed error={counted.error} what="The lead counts could not be read." />
      ) : rows.length === 0 ? (
        <section className="panel">
          <Empty title="No analyzer has sent results for this product." />
        </section>
      ) : (
        <section className="panel">
          <p className="hint" style={{ marginTop: 0 }}>
            Every build of the product. A lead on two builds in two states counts in both.
          </p>
          <Wide>
            <table>
              <thead>
                <tr>
                  <th>Series</th>
                  {COLUMNS.map((state) => (
                    <th key={state} className="num">
                      {LEAD_STATES[state]}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.series} className="row">
                    <td className="id">{row.series}</td>
                    {COLUMNS.map((state) => {
                      const n = row.states?.[state] ?? 0;
                      return (
                        <td key={state} className="num">
                          <Link
                            to={leadsAt(product, { series: row.series, state })}
                            title={
                              state === "open" && row.waiting > 0
                                ? `${row.waiting.toLocaleString()} waiting for approval`
                                : state === "dismissed" && row.ruled > 0
                                  ? `${row.ruled.toLocaleString()} by a rule`
                                  : undefined
                            }
                          >
                            {n.toLocaleString()}
                          </Link>
                        </td>
                      );
                    })}
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
