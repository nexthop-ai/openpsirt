// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Empty } from "./Empty";
import { Paged } from "./Paged";
import { Wide } from "./Wide";
import { componentAt } from "../app/routes";

// One kind of change, or every kind where it is empty.
export type Kind = "" | "removed" | "added" | "changed";

// The most one page asks for. Long enough that an ordinary night fits on one
// page, short enough that a build which replaced everything does not arrive as
// one screen of two thousand rows.
export const PAGE = 200;

// MovedPage is one page of names that moved, under the chips that narrow it
// to one kind.
//
// Two different emptinesses. Narrowed to one kind, what is empty is the
// narrowing, and the way back is offered because the chips that produced it
// are above a screen somebody may have scrolled. Unnarrowed, it is the
// inventories themselves, which `nothing` says.
//
// `waiting` stands in for the page while it is read or where it failed.
export function MovedPage({
  product,
  only,
  onPick,
  rows,
  total,
  offset,
  onGo,
  removedIsGone,
  otherwise,
  nothing,
  waiting,
}: {
  product: string;
  only: Kind;
  onPick: (kind: Kind) => void;
  rows: NameMoved[];
  total: number;
  offset: number;
  onGo: (offset: number) => void;
  removedIsGone?: boolean;
  // What else changed, where one kind is asked for and none of it moved.
  otherwise: string;
  nothing: { title: string; detail: string };
  waiting?: ReactNode;
}) {
  return (
    <>
      <KindChips only={only} onPick={onPick} />
      {waiting ??
        (rows.length === 0 ? (
          only ? (
            <Empty
              title={`Nothing was ${only === "changed" ? "moved to a new version" : only}.`}
              detail={otherwise}
            >
              <button type="button" className="btn" onClick={() => onPick("")}>
                Show everything
              </button>
            </Empty>
          ) : (
            <Empty title={nothing.title} detail={nothing.detail} />
          )
        ) : (
          <>
            <NamesMoved product={product} rows={rows} removedIsGone={removedIsGone} />
            <Paged
              shown={rows.length}
              total={total}
              offset={offset}
              limit={PAGE}
              onGo={onGo}
              what="listed"
            />
          </>
        ))}
    </>
  );
}

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
function KindChips({ only, onPick }: { only: Kind; onPick: (kind: Kind) => void }) {
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
function NamesMoved({
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
                  <Link to={componentAt(product, row.name ?? "")}>{row.name}</Link>
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
