// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom";
import { Wide } from "./Wide";

// One kind of change, or every kind where it is empty.
export type Kind = "" | "removed" | "added" | "changed";

// One name two inventories hold differently: an upload against the one before
// it, or one build against another.
type NameMoved = {
  name?: string;
  change?: string;
  before?: string[] | null;
  after?: string[] | null;
};

// The kinds of change as a row of chips. One kind at a time is asked of the
// server, so that the count in the footer is of that kind rather than of the
// page.
export function KindChips({ only, onPick }: { only: Kind; onPick: (kind: Kind) => void }) {
  return (
    <div className="variants" style={{ marginBottom: 10 }}>
      {(
        [
          ["", "Everything"],
          ["removed", "Removed"],
          ["added", "Added"],
          ["changed", "New version"],
        ] as const
      ).map(([value, label]) => (
        <button
          key={value || "all"}
          type="button"
          className={`chip${only === value ? " on" : ""}`}
          aria-pressed={only === value}
          onClick={() => onPick(value)}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

// The names, what happened to each, and every version on each side.
//
// removedIsGone says a removed name is shipped by nothing on the before side
// either, which is true of one upload against its predecessor and false of two
// builds, where the earlier build still ships it.
export function NamesMoved({
  product,
  rows,
  removedIsGone = true,
}: {
  product: string;
  rows: NameMoved[];
  removedIsGone?: boolean;
}) {
  return (
    <Wide>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Change</th>
            <th>Before</th>
            <th>After</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={`${row.change} ${row.name}`}>
              <td>
                {/* The component's own page, where what is open against it
                    is. A name nothing ships any more has nothing open
                    against it, so it is the one that is not a link. */}
                {removedIsGone && row.change === "removed" ? (
                  row.name
                ) : (
                  <Link
                    to={`/products/${encodeURIComponent(product)}/components/${encodeURIComponent(row.name ?? "")}`}
                  >
                    {row.name}
                  </Link>
                )}
              </td>
              <td>
                <Change change={row.change} />
              </td>
              <td className="hint">{(row.before ?? []).join(", ") || "—"}</td>
              <td className="hint">{(row.after ?? []).join(", ") || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Wide>
  );
}

// What happened to one name, as a word.
//
// A removal is marked rather than merely named: it is the one a reader is
// looking for, and it is the one that reads as harmless.
function Change({ change }: { change?: string }) {
  if (change === "removed") return <span className="sev high">removed</span>;
  if (change === "added") return <span className="chip">added</span>;
  return <span className="chip">new version</span>;
}
