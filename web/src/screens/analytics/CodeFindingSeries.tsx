// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom";
import { useCodeFindingSeries, type CodeFindingState } from "../../api/codeFindings";
import { codeFindingsAt } from "../../app/routes";
import { useWho } from "../../app/session";
import { counted as reading, heldLine, holding } from "../../app/families";
import { useScope } from "../../app/scope";
import { Empty } from "../../ui/Empty";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { Wide } from "../../ui/Wide";
import { CODE_FINDING_STATES } from "../codeFindings";
import { Sheet } from "./Sheet";
import { byProduct } from "./catalog";

// The columns, in the order a code finding meets them: what is worked first, then
// what has been answered.
const COLUMNS: CodeFindingState[] = [
  "open",
  "no-longer-detected",
  "dismissed",
  "not-security",
  "confirmed",
  "recorded-as-flaw",
  "fixed",
];

// How many code findings each analyzer holds, and how far each has been worked.
//
// Security testing work, like every code finding, so a reader who does not read
// security testing material in the product is told so rather than shown a table
// of zeros that reads as an analyzer finding nothing.
export function CodeFindingSeries() {
  const at = useScope();
  const product = at.product ?? "";
  const code = holding(useWho().data, "code", product || undefined);
  const reads = reading(code);
  const counted = useCodeFindingSeries(reads ? product : "");
  const rows = counted.data ?? [];

  return (
    <Sheet
      settled={!reads || counted.isSuccess}
      name="Code findings by analyzer"
      answers="how many code findings each analyzer holds, and where they stand."
      of={byProduct(at.product)}
    >
      {product === "" ? (
        <section className="panel">
          <Empty title="Pick a product." detail="An analyzer series belongs to one product." />
        </section>
      ) : !reads ? (
        <section className="panel">
          <Empty title="Nothing to list." detail={heldLine(code)} />
        </section>
      ) : counted.isPending ? (
        <Loading />
      ) : counted.isError ? (
        <Failed error={counted.error} what="The code finding counts could not be read." />
      ) : rows.length === 0 ? (
        <section className="panel">
          <Empty title="No analyzer has sent results for this product." />
        </section>
      ) : (
        <section className="panel">
          <p className="hint" style={{ marginTop: 0 }}>
            Every build of the product. A code finding on two builds in two states counts in both.
          </p>
          <Wide>
            <table>
              <thead>
                <tr>
                  <th>Series</th>
                  {COLUMNS.map((state) => (
                    <th key={state} className="num">
                      {CODE_FINDING_STATES[state]}
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
                            to={codeFindingsAt(product, { series: row.series, state })}
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
