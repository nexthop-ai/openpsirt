import { Fragment } from "react";
import { Link, useNavigate } from "react-router-dom";

import { Severity, Exploited } from "../ui/Severity";
import { Wide } from "../ui/Wide";
import { decidedAs } from "../ui/decided";
import { on } from "../ui/when";
import { Peek, Sits } from "./FindingsViews";
import { SORTS, pathTo, type Row } from "./list";
import { bandOf } from "../ui/severities";

// The findings list as a table, and as cards on a narrow screen.
//
// Lifted out of the screen because it is a concept with its own boundary: what
// a row says, what a row's controls do, and what a preview under one holds.
// It takes what it draws and holds none of it, so a row is the only source of
// that row's product — which is what stops the path's product being used by
// accident on the list that spans every product, where there is none.
// How long this has been open here.
//
// The finding's own age, not the year in the identifier: an issue assigned in
// 2019 that first appeared in this product last week has been somebody's
// problem for a week, and the identifier already carries its own year for
// anybody who wants it. This is also the age a deadline relates to.
function openFor(opened: string | undefined): string | null {
  if (!opened) return null;
  const days = Math.floor((Date.now() - Date.parse(opened + "T00:00:00Z")) / 86_400_000);
  if (!Number.isFinite(days) || days < 0) return null;
  if (days < 60) return `open ${days}d`;
  if (days < 730) return `open ${Math.floor(days / 30)}mo`;
  return `open ${Math.floor(days / 365)}y`;
}

// What to say in the Due column, and how to color it.
//
// A blank cell would mean two deliberate things at once — below the line or
// past end of life — on the one screen whose purpose is noticing what is
// running out, so the reason is said.
function dueSays(row: { due?: string; days_left?: number; no_deadline?: string }): {
  text: string;
  tone: "over" | "soon" | "fine" | "none";
} {
  if (!row.due) {
    return {
      text: row.no_deadline === "out-of-support" ? "out of support" : "below the line",
      tone: "none",
    };
  }
  const left = row.days_left ?? 0;
  if (left < 0) return { text: `${-left}d over`, tone: "over" };
  if (left <= 7) return { text: `${left}d left`, tone: "soon" };
  return { text: row.due, tone: "fine" };
}

// What upstream has done, said rather than left to be inferred from a blank.
function upstreamSays(state: string | undefined, fixedIn: string | undefined) {
  if (fixedIn) return { text: fixedIn, kind: "id" as const };
  switch (state) {
    case "wont-fix":
      return { text: "declined", kind: "note" as const };
    case "none":
      return { text: "none yet", kind: "note" as const };
    default:
      return { text: "—", kind: "faint" as const };
  }
}

export function FindingsTable({
  rows,
  shownKeys,
  picked,
  pick,
  pickAll,
  spanning,
  columns,
  oneBuild,
  sortable,
  buildOf,
  siblings,
  carrying,
  prepared,
  set,
  hide,
  peeking,
  setPeeking,
}: {
  rows: Row[];
  // The selection's key for each row on this page, in the same order.
  shownKeys: string[];
  picked: Map<string, Row>;
  pick: (key: string, row: Row, on: boolean) => void;
  pickAll: (rows: Row[], keys: string[], on: boolean) => void;
  // Whether the list spans every product, which is what decides the extra
  // column — and `columns`, which is how many the preview row has to span.
  spanning: boolean;
  columns: number;
  oneBuild: boolean;
  sortable: (label: keyof typeof SORTS) => React.ReactNode;
  // Which build a row's actions and links are about.
  buildOf: (row: Row) => { product: string; stream: string; variant: string };
  // How many other rows on this page are the same issue at another binary of
  // one source package.
  siblings: Map<string, number>;
  // The list's own address as a row carries it, so a finding can walk back to
  // it, and the prepared claim a row may arrive with.
  carrying: string;
  prepared: { name: string } | null | undefined;
  set: (key: string, value: string) => void;
  hide: (component: string) => void;
  peeking: string | null;
  setPeeking: (key: string | null) => void;
}) {
  const navigate = useNavigate();
  return (
    <div className="findings">
      <Wide>
        <table>
          <thead>
            <tr>
              <th style={{ width: 54 }}>
                <input
                  type="checkbox"
                  aria-label="Select every row shown"
                  checked={picked.size > 0 && shownKeys.every((key) => picked.has(key))}
                  onChange={(event) => pickAll(rows, shownKeys, event.target.checked)}
                />
              </th>
              <th>{sortable("Severity")}</th>
              {spanning && <th>Product</th>}
              <th>Issue</th>
              <th>Component</th>
              {/* Both ends of the way down, middle collapsed. */}
              <th>{oneBuild ? "Path" : "Build"}</th>
              <th
                className="num"
                title="EPSS: published probability of exploitation. Orders findings of equal severity"
              >
                {sortable("EPSS")}
              </th>
              <th>Fixed in</th>
              <th className="num">{sortable("Covers")}</th>
              <th>{sortable("Due")}</th>
              <th>State</th>
            </tr>
          </thead>
          <tbody id="findingRows">
            {rows.map((row, i) => {
              const key = `${row.vulnerability} ${row.component} ${row.version} ${row.ecosystem ?? ""}`;
              const at = pathTo(buildOf(row), row, carrying, prepared?.name);
              // How far it is decided comes from the server, defined the
              // way the state filter defines it; a row does not guess from
              // what the build argued away, which is a different claim by
              // a different author.
              const pill = decidedAs(row.state, row.sent_back);
              return (
                <Fragment key={key}>
                  <tr className="row" data-i={i} onClick={() => navigate(at)}>
                    {/* The two controls that belong to the row rather than
                              to what is in it. Side by side in one narrow cell:
                              stacked they read as two unrelated things, and the
                              checkbox drawn at the browser's default size looked
                              like it had arrived from another page. */}
                    <td className="rowpickcell" onClick={(event) => event.stopPropagation()}>
                      <div className="rowpick">
                        <input
                          type="checkbox"
                          aria-label={`Select ${row.vulnerability} in ${row.component}`}
                          checked={picked.has(key)}
                          onChange={(event) => pick(key, row, event.target.checked)}
                        />
                        <button
                          type="button"
                          className="peek"
                          aria-expanded={peeking === key}
                          title="Preview without leaving the list"
                          onClick={(event) => {
                            event.stopPropagation();
                            setPeeking(peeking === key ? null : key);
                          }}
                        >
                          {peeking === key ? "▾" : "▸"}
                        </button>
                      </div>
                    </td>
                    <td>
                      <Severity word={row.severity} />
                      {row.score ? (
                        <span className="hint" style={{ marginLeft: 6 }}>
                          {row.score.toFixed(1)}
                        </span>
                      ) : null}
                    </td>
                    {/* Which product this row is about, where that varies.
                              It is the column the cross-product list exists for,
                              and the only one a product's own list would draw
                              the same value in for every row. */}
                    {spanning && (
                      <td>
                        <Link
                          to={`/products/${encodeURIComponent(row.product ?? "")}/findings`}
                          onClick={(e) => e.stopPropagation()}
                        >
                          {row.product}
                        </Link>
                      </td>
                    )}
                    <td>
                      <Link to={at} className="id" onClick={(e) => e.stopPropagation()}>
                        {row.vulnerability}
                      </Link>{" "}
                      <Exploited when={row.exploited} />
                      {/* The secondary signal. What somebody must not
                                miss is on the finding itself. */}
                      {row.undisclosed && (
                        <span
                          className="state waiting"
                          title={
                            row.disclose_at
                              ? `Not disclosed. The embargo ends ${on(row.disclose_at)}`
                              : "Not disclosed, with no end date set"
                          }
                        >
                          Embargoed
                        </span>
                      )}
                      {(() => {
                        const age = openFor(row.opened);
                        return age ? (
                          <span className="hint" style={{ marginLeft: 6 }}>
                            {age}
                          </span>
                        ) : null;
                      })()}
                      {/* The words people put on this. On the row
                                because the point of marking work is finding it
                                again in a list — a mark only the finding screen
                                showed would be one nobody sees. Each is a filter:
                                seeing one and asking for the rest is the whole
                                motion. */}
                      {/* One line of what the issue actually says. Fifty
                                rows otherwise read "CVE-2026-74280 ·
                                linux-image" fifty times, and telling two of them
                                apart cost a click each — which is the preview
                                control right beside it, used fifty times to do
                                what one line of text does at a glance. */}
                      {row.summary && (
                        <div className="summary" title={row.summary}>
                          {row.summary}
                        </div>
                      )}
                      {(row.tags ?? []).length > 0 && (
                        <span className="marks">
                          {(row.tags ?? []).map((tag) => (
                            <button
                              key={tag}
                              type="button"
                              className="mark"
                              title={`Everything tagged ${tag}`}
                              onClick={(event) => {
                                event.stopPropagation();
                                set("tag", tag);
                              }}
                            >
                              {tag}
                            </button>
                          ))}
                        </span>
                      )}
                    </td>
                    <td>
                      {/* The name opens the component; narrowing and
                                hiding are the two small acts beside it. The
                                name and its controls are one line — held
                                apart, the column sized itself to the name and
                                then had nowhere to put them. */}
                      <span className="compline">
                        <Link
                          className="linkish id compname"
                          title={`Open ${row.component}`}
                          // The row's own product, not the selection's.
                          // Across every product there is no selection, so
                          // this built `/products//components/NAME` — a
                          // path that matches no route, and the app fell
                          // back to the home screen. The source-package
                          // link four rows down already asked the row.
                          to={`/products/${encodeURIComponent(
                            buildOf(row).product,
                          )}/components/${encodeURIComponent(row.component ?? "")}`}
                          onClick={(event) => event.stopPropagation()}
                        >
                          {row.component}
                        </Link>
                        <button
                          type="button"
                          className="linkish onlyit"
                          title={`Everything open against ${row.component}`}
                          onClick={(event) => {
                            event.stopPropagation();
                            set("component", row.component ?? "");
                          }}
                        >
                          only
                        </button>
                        <button
                          type="button"
                          className="linkish hideit"
                          title={`Hide ${row.component} from this list`}
                          onClick={(event) => {
                            event.stopPropagation();
                            hide(row.component ?? "");
                          }}
                        >
                          hide
                        </button>
                      </span>
                      <br />
                      <span className="id" style={{ color: "var(--faint)" }}>
                        {row.version}
                      </span>
                      {/* The same issue at two binaries of one source
                                package is two rows here and one piece of work
                                everywhere else: it is decided once, upgraded
                                once, and routed by one rule. Said on the row
                                rather than folded away, because the places are
                                real and a reader counting them should get the
                                same number the list does — what they were not
                                told is that four of the rows are one bump. */}
                      {(siblings.get(`${row.vulnerability} ${row.source}`) ?? 0) ? (
                        <>
                          {" "}
                          <button
                            type="button"
                            className="linkish hint"
                            title={`Everything open against the ${row.source} source package`}
                            onClick={(event) => {
                              event.stopPropagation();
                              navigate(
                                `/products/${encodeURIComponent(
                                  buildOf(row).product,
                                )}/components/${encodeURIComponent(row.component ?? "")}`,
                              );
                            }}
                          >
                            {row.source} · also at{" "}
                            {siblings.get(`${row.vulnerability} ${row.source}`)} sibling
                            {(siblings.get(`${row.vulnerability} ${row.source}`) ?? 0) === 1
                              ? ""
                              : "s"}
                          </button>
                        </>
                      ) : null}
                    </td>
                    <td>
                      <Sits row={row} />
                    </td>
                    <td className="num hint">{row.likelihood ? row.likelihood.toFixed(3) : "—"}</td>
                    <td>
                      {(() => {
                        const said = upstreamSays(row.fix_state, row.fixed_in);
                        return (
                          <>
                            {/* A version is one token to a reader. Left
                                      to itself the browser breaks at every
                                      hyphen, so "1.26.0-rc.3" arrived as two
                                      lines and three versions as four — the
                                      tallest cell on the row, for a column that
                                      holds three short words. It still wraps,
                                      but only between one version and the
                                      next. */}
                            <span
                              className={said.kind === "id" ? "id" : "hint"}
                              style={said.kind === "faint" ? { color: "var(--faint)" } : undefined}
                            >
                              {said.text.split(", ").map((one, n) => (
                                <Fragment key={one}>
                                  {n > 0 ? ", " : null}
                                  <span className="whole">{one}</span>
                                </Fragment>
                              ))}
                            </span>
                            {row.matched === "identifier" && (
                              <div
                                className="hint"
                                title="Matched on a version range, not a packager advisory. May already be fixed here."
                              >
                                not confirmed
                              </div>
                            )}
                          </>
                        );
                      })()}
                    </td>
                    {/* Counted in the units somebody acts in. Deciding on
                              this row decides about every package and every
                              consumer under it, so those are the numbers shown —
                              a place count is a figure a reader cannot reconcile
                              with anything else on the screen. */}
                    <td className="num">
                      <span
                        title={`${row.places} ${row.places === 1 ? "finding" : "findings"} underneath`}
                      >
                        {row.packages > 1 && (
                          <>
                            {row.packages} packages
                            <span className="hint"> · </span>
                          </>
                        )}
                        {row.consumers} {row.consumers === 1 ? "consumer" : "consumers"}
                      </span>
                      {(row.answered ?? 0) > 0 && (
                        <span
                          className="hint"
                          title="Argued away by the build's own VEX, which is a different claim by a different author"
                        >
                          {" "}
                          · {row.answered} by the build
                        </span>
                      )}
                    </td>
                    <td>
                      {(() => {
                        const says = dueSays(row);
                        return (
                          <span
                            className={says.tone === "none" ? "hint" : `due ${says.tone}`}
                            title={says.tone === "none" ? "No deadline" : `Due ${row.due}`}
                          >
                            {says.text}
                          </span>
                        );
                      })()}
                    </td>
                    <td>
                      <span className={`state ${pill.cls}`}>{pill.word}</span>
                    </td>
                  </tr>
                  {peeking === key && (
                    <tr className="places">
                      <td colSpan={columns}>
                        <Peek
                          at={buildOf(row)}
                          vulnerability={row.vulnerability ?? ""}
                          component={row.component ?? ""}
                          version={row.version ?? ""}
                          to={at}
                        />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </Wide>

      <div className="cards">
        {rows.map((row) => {
          const at = pathTo(buildOf(row), row, carrying, prepared?.name);
          return (
            // The only way to open a finding on a narrow screen, so it
            // has to be reachable without a pointer: a card that answers
            // a click and nothing else is a list nobody can get into
            // from a keyboard.
            <article
              key={`${row.vulnerability} ${row.component} ${row.version} ${row.ecosystem ?? ""}`}
              // The word the badge draws with, so the card's stripe and the
              // badge on it agree. An absent rating gave the card no class at
              // all while the badge beside it said "Unrated".
              className={`fcard ${row.exploited ? "exploited" : bandOf(row.severity)}`}
              role="link"
              tabIndex={0}
              aria-label={`${row.vulnerability} in ${row.component}`}
              onClick={() => navigate(at)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  navigate(at);
                }
              }}
            >
              <header>
                <Severity word={row.severity} />
                <Exploited when={row.exploited} />
              </header>
              <div>
                <span className="id">{row.vulnerability}</span> in{" "}
                <span className="id">{row.component}</span>
              </div>
              <div className="hint">
                {row.packages > 1 && <>{row.packages} packages · </>}
                {row.consumers} {row.consumers === 1 ? "consumer" : "consumers"} · fixed in{" "}
                {row.fixed_in ?? "—"}
              </div>
            </article>
          );
        })}
      </div>
    </div>
  );
}
