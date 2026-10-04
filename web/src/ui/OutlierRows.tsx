// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Exploited, ExploitedHere, Severity } from "./Severity";
import { Wide } from "./Wide";

// One issue a bulk claim covers that does not look like the rest, as the
// server lists it.
type Outlier = {
  decision_id: number;
  severity?: string;
  vulnerability?: string;
  exploited?: boolean;
  exploited_here?: boolean;
  why?: string[] | null;
};

// OutlierRows is the issues a bulk claim covers that do not look like the rest,
// each with a box to hold it back and the reasons it stands out. The same
// table wherever whoever wrote the claim is offered the choice.
export function OutlierRows<Row extends Outlier>({
  rows,
  holding,
  onToggle,
}: {
  rows: readonly Row[];
  holding: Set<number>;
  onToggle: (row: Row, on: boolean) => void;
}) {
  return (
    <Wide style={{ boxShadow: "none" }}>
      <table>
        <thead>
          <tr>
            <th style={{ width: 30 }} />
            <th>Severity</th>
            <th>Issue</th>
            <th>Reason</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((one) => (
            <tr key={one.decision_id}>
              <td>
                <input
                  type="checkbox"
                  aria-label="Hold back"
                  checked={holding.has(one.decision_id)}
                  onChange={(event) => onToggle(one, event.target.checked)}
                />
              </td>
              <td>
                <Severity word={one.severity} />
              </td>
              <td>
                <span className="id">{one.vulnerability}</span>{" "}
                <ExploitedHere when={one.exploited_here} /> <Exploited when={one.exploited} />
              </td>
              <td className="hint">{(one.why ?? []).join(", ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Wide>
  );
}
