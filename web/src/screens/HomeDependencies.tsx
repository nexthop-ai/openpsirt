// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { counted, type Holding } from "../app/families";
import { comparisonAt } from "../app/routes";
import { findingsPath, scopeQuery, useScope, type Scoped } from "../app/scope";
import { Mix, Pace, Releases, Ring, TREND_WEEKS, trendSaid } from "../ui/Charts";
import { Count, known } from "../ui/Count";
import { Failed } from "../ui/Failed";
import { HeldLine } from "../ui/HeldLine";
import { Loading } from "../ui/Loading";
import { Reading } from "../ui/Reading";
import { Severity } from "../ui/Severity";
import { BANDS } from "../ui/severities";
import { mixReading, paceReading } from "../ui/trend";
import { Wide } from "../ui/Wide";
import { SOON_DAYS } from "./FindingsFilters";

// Home's Dependencies figures: the estate's open, known exploited, overdue and
// due soon, the trends and release readiness, all counting dependency findings
// at the picked scope. Drawn only where the reader counts them there; elsewhere
// the family's one line stands in their place.

// The most of the deadline list the tiles read. The response carries the
// whole-answer count beside it, so the figures say when they are a floor
// rather than leaving a page to pass for the answer.
const OVERDUE_LIMIT = 200;

// The findings list, narrowed to what a deadline tile counts: undecided, and
// running out inside the window. Built here so the figure and the screen it
// opens ask the same question.
function runningOut(at: Parameters<typeof findingsPath>[0], within: string): string {
  return findingsPath(at, true, { running: within, state: "undecided" });
}

// The findings list, narrowed to what the readiness panel counts as blocking:
// everything nobody has agreed to, above the product's line as the list is by
// default. The count takes none of the list's other defaults, so neither does
// the link.
export function blockingPath(at: Parameters<typeof findingsPath>[0]): string {
  const asked = new URLSearchParams([
    ["state", "undecided"],
    ["state", "waiting"],
    ["state", "lapsed"],
  ]);
  return findingsPath(at, true, asked);
}

// The Dependencies figures, under the scope the head names.
export function DependencyFigures({
  dependencies,
  counting,
}: {
  dependencies: Holding;
  counting: string;
}) {
  const at = useScope();
  const scope = scopeQuery(at);
  const navigate = useNavigate();
  const figures = counted(dependencies);

  const trend = useQuery({
    queryKey: ["home", "trend", scope],
    enabled: figures,
    queryFn: async () =>
      unwrap(await api.GET("/v1/trend", { params: { query: { weeks: TREND_WEEKS, ...scope } } })),
  });
  const points = trend.data?.items ?? [];
  // The other axis. Asked for whenever a product is picked, and drawn instead
  // of the calendar where the product has releases to plot: a tag never moves
  // again, and releases months apart read on a calendar as slow drift rather
  // than the step change they were.
  const releases = useQuery({
    queryKey: ["home", "release-trend", scope],
    enabled: figures && !!at.product,
    queryFn: async () =>
      unwrap(await api.GET("/v1/trend/releases", { params: { query: { limit: 12, ...scope } } })),
  });
  // Two releases is the fewest that is a shape. One bar reads as broken
  // rather than as sparse, so the calendar stays until there are two.
  const byRelease = (releases.data?.items ?? []).length >= 2;

  // One definition at every scope: the trend's latest point, which counts
  // distinct issues. The findings list counts one row per issue and component,
  // and a tile that switched between the two as the picker moved would quote
  // two figures for one word.
  const exploited = useQuery({
    queryKey: ["home", "exploited", scope],
    // Answered for whatever is selected, like every figure here. Drawn only
    // where a product is picked, because the cross-product list counts a row
    // per product as well — a tile that changed unit as the picker moved
    // would quote two figures for one word.
    enabled: figures && !!at.product,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/findings", {
          params: {
            path: { product: at.product ?? "" },
            query: {
              limit: 1,
              exploited: true,
              ...(at.branch_or_tag ? { branch_or_tag: at.branch_or_tag } : {}),
              ...(at.variant ? { variant: at.variant } : {}),
            },
          },
        }),
      ),
  });
  // The same figures with the scope taken off, so a tile can show what the
  // selection costs rather than leaving somebody to guess at it. Asked only
  // where a scope narrows something: unscoped they would be the same number
  // twice.
  const widely = !!at.product;
  const allOpen = useQuery({
    queryKey: ["home", "trend", "all"],
    enabled: figures && widely,
    queryFn: async () =>
      unwrap(await api.GET("/v1/trend", { params: { query: { weeks: TREND_WEEKS } } })),
  });
  const allLate = useQuery({
    queryKey: ["home", "running-out", "all"],
    enabled: figures && widely,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/running-out", {
          params: { query: { days: SOON_DAYS, limit: OVERDUE_LIMIT } },
        }),
      ),
  });
  // Everything running out inside the window, read once: what is overdue is
  // the part of it that has already run out, so two tiles from one read
  // rather than two reads that can disagree about the same list.
  const late = useQuery({
    queryKey: ["home", "running-out", scope],
    enabled: figures,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/running-out", {
          params: { query: { days: SOON_DAYS, limit: OVERDUE_LIMIT, ...scope } },
        }),
      ),
  });

  const latest = points[points.length - 1];
  const openCount = latest?.open;
  const running = late.data?.items ?? [];
  const overdue = running.filter((row) => (row.days_left ?? 0) < 0);
  const overdueExploited = overdue.filter((row) => row.exploited).length;
  // Not yet late and about to be, which is the one somebody can still do
  // something about: overdue is a report and this is a working list.
  const soon = running.filter((row) => (row.days_left ?? 0) >= 0);
  const soonExploited = soon.filter((row) => row.exploited).length;
  const allRunning = allLate.data?.items ?? [];
  const allOverdue = allRunning.filter((row) => (row.days_left ?? 0) < 0).length;
  const allSoon = allRunning.length - allOverdue;
  const allPoints = allOpen.data?.items ?? [];
  // Whether the page in hand is the whole list. The two tiles below split one
  // read into overdue and due-soon, so neither half can be compared against
  // the cap on its own. The server says how many rows the question has; that
  // is the test.
  const cut = (late.data?.total ?? running.length) > running.length;
  const cutEverywhere = (allLate.data?.total ?? allRunning.length) > allRunning.length;
  // The list is ordered by deadline, soonest first, so every overdue row comes
  // before any row still due. A cut page holding one row still due holds every
  // overdue row, and the overdue count is a floor only where the whole page is
  // overdue. Due soon is a floor wherever the page is cut.
  const overdueCut = cut && soon.length === 0;
  const overdueCutEverywhere = cutEverywhere && allSoon === 0;

  // The same figure without the scope. Nothing where no scope is
  // selected, because the two would be one number said twice.
  function everywhere(n: number | undefined): React.ReactNode {
    if (!widely || n === undefined) return null;
    return <span className="d">{n.toLocaleString()} all products</span>;
  }

  // The same, for a figure read out of a list the server caps. Printed exact, a
  // capped list says there are fewer than there are — and a filtered part of it
  // can read zero while the unfiltered whole is at the cap.
  function everywhereAtLeast(n: number, capped: boolean): React.ReactNode {
    if (!widely) return null;
    return (
      <span className="d">
        {n.toLocaleString()}
        {capped ? "+" : ""} all products
      </span>
    );
  }

  if (!figures) return <HeldLine at={dependencies} />;

  return (
    <>
      <div className="kpis">
        {/* Unnarrowed, because the figure is. The list writes three narrowings
          into its own address when the address says nothing, and none of them
          applies to the count, so the list opens with the number's rows. */}
        <button type="button" className="kpi" onClick={() => navigate(findingsPath(at, true))}>
          <span className="l">Open issues · {counting}</span>
          <span className="n">
            <Count of={trend}>
              {() => (openCount === undefined ? "—" : openCount.toLocaleString())}
            </Count>
          </span>
          {everywhere(known(allOpen) ? allPoints[allPoints.length - 1]?.open : undefined) ?? (
            <span className="d">distinct issues, not findings</span>
          )}
        </button>
        {!!at.product && (
          <button
            type="button"
            className={`kpi${known(exploited) && (exploited.data?.total ?? 0) > 0 ? " urgent" : ""}`}
            onClick={() => navigate(findingsPath(at, true, { exploited: "1" }))}
          >
            <span className="l">
              <i style={{ background: "var(--sev-exploited)" }} /> Known exploited
            </span>
            {/* A dash rather than a zero. "No exploited findings here" and "the
              count could not be read" are opposite answers, and the tile that
              says the first is the one somebody stops looking at. */}
            <span className="n">
              <Count of={exploited}>{() => (exploited.data?.total ?? 0).toLocaleString()}</Count>
            </span>
            {/* No twin. The all-products figure off this endpoint counts a row
              per product, issue and component, so one library's flaw in five
              products reads as five against a scoped figure that reads one —
              two units under one label. */}
            <span className="d">sorted above everything else</span>
          </button>
        )}
        {/* Into the list it counts, narrowed the same way: what is undecided
          and past its deadline. The assignments screen answers a different
          question — what is *mine* — and would disagree with the number for
          everybody but the one person holding all of it. */}
        <button type="button" className="kpi" onClick={() => navigate(runningOut(at, "overdue"))}>
          <span className="l">
            <i style={{ background: "var(--sev-critical)" }} /> Overdue
          </span>
          {/* The list behind this is capped, so a page cut before it reached
            anything still due is said to be a floor rather than passed off as
            the count. */}
          <span className="n">
            <Count of={late}>
              {() => `${overdue.length.toLocaleString()}${overdueCut ? "+" : ""}`}
            </Count>
          </span>
          {(known(allLate) && everywhereAtLeast(allOverdue, overdueCutEverywhere)) || (
            <span className="d">
              {overdueExploited > 0 ? `${overdueExploited} known exploited · ` : ""}undecided, past
              the deadline
              {overdueCut ? " · at least" : ""}
            </span>
          )}
        </button>
        {/* The tile that is actually actionable. Overdue is a report about
          something that has already happened; this is the week somebody can
          still finish. */}
        <button
          type="button"
          className={`kpi${soonExploited > 0 ? " urgent" : ""}`}
          onClick={() => navigate(runningOut(at, String(SOON_DAYS)))}
        >
          <span className="l">
            <i style={{ background: "var(--wait)" }} /> Due soon
          </span>
          <span className="n">
            <Count of={late}>{() => `${soon.length.toLocaleString()}${cut ? "+" : ""}`}</Count>
          </span>
          {(known(allLate) && everywhereAtLeast(allSoon, cutEverywhere)) || (
            <span className="d">
              {soonExploited > 0 ? `${soonExploited} known exploited · ` : ""}undecided, due within{" "}
              {SOON_DAYS} days
              {cut ? " · at least" : ""}
            </span>
          )}
        </button>
      </div>
      <HeldLine at={dependencies} />

      <div className="panels">
        <div className="panel wide">
          <header>
            <h3>
              {byRelease ? "Open issues in each release" : "Trend: open, new and resolved issues"}
            </h3>
            <span className="eyebrow" style={{ marginLeft: "auto" }}>
              {byRelease ? "release over release" : trendSaid} · {counting}
            </span>
          </header>
          {trend.isError ? (
            <Failed error={trend.error} what="The trend could not be read." />
          ) : releases.isError ? (
            <Failed error={releases.error} what="The release trend could not be read." />
          ) : trend.isPending || (!!at.product && releases.isPending) ? (
            <Loading />
          ) : byRelease ? (
            <>
              <Releases points={releases.data?.items ?? []} />
              <p className="hint">Each release against today&rsquo;s vulnerability data.</p>
            </>
          ) : (
            <>
              <Pace points={points} />
              <div className="legend">
                <span>
                  <i style={{ background: "var(--accent)" }} /> Open issues
                </span>
                <span>
                  <i style={{ background: "var(--sev-high)" }} /> New
                </span>
                <span>
                  <i style={{ background: "var(--ok)" }} /> Resolved
                </span>
              </div>
              <p className="reading">{paceReading(points)}</p>
            </>
          )}
        </div>

        <div className="panel wide">
          <header>
            <h3>Severity over time</h3>
            <span className="eyebrow" style={{ marginLeft: "auto" }}>
              Open, by severity
            </span>
          </header>
          <Reading query={trend} what="The trend could not be read.">
            {() => (
              <>
                <Mix points={points} />
                <p className="reading">{mixReading(points)}</p>
              </>
            )}
          </Reading>
        </div>

        <div className="panel">
          <header>
            <h3>Open issues by severity</h3>
            <span className="eyebrow" style={{ marginLeft: "auto" }}>
              Open now
            </span>
          </header>
          <Reading query={trend} what="The trend could not be read.">
            {() => (
              <>
                <Ring point={points[points.length - 1]} />
                <p className="reading">Known exploited is counted with what it is rated.</p>
              </>
            )}
          </Reading>
        </div>

        <Readiness at={at} />
      </div>
    </>
  );
}

// A branch beside the last release cut from it: is what we are about to ship
// better or worse than what we last shipped.
//
// Drawn only where the question has an answer. It needs a whole build picked,
// because a count across products is not a release; and it needs a branch,
// because a tag is one frozen point and is not cut into anything. Where a
// branch has released nothing that has been scanned, the panel says so rather
// than drawing zeroes — a release that shipped clean and a release nobody
// scanned are not the same answer.
function Readiness({ at }: { at: Scoped }) {
  const whole = !!at.product && !!at.branch_or_tag && !!at.variant;
  const ready = useQuery({
    queryKey: ["readiness", at],
    enabled: whole,
    queryFn: async () =>
      unwrap(
        await api.GET(
          "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/readiness",
          {
            params: {
              path: {
                product: at.product ?? "",
                branch_or_tag: at.branch_or_tag ?? "",
                variant: at.variant ?? "",
              },
            },
          },
        ),
      ),
  });

  if (!whole) {
    return (
      <div className="panel">
        <header>
          <h3>Release readiness</h3>
        </header>
        <p className="reading">Pick a branch and a variant to compare.</p>
      </div>
    );
  }
  if (ready.isPending) return null;
  if (ready.isError) {
    return (
      <div className="panel">
        <header>
          <h3>Release readiness</h3>
        </header>
        <Failed error={ready.error} what="The comparison could not be read." />
      </div>
    );
  }
  // A tag is not compared against itself, and the panel is absent rather than
  // present and explaining itself on every visit.
  if (ready.data?.now?.kind === "tag") return null;

  const now = ready.data?.now;
  const shipped = ready.data?.shipped;
  const minimum = ready.data?.minimum_severity;
  const blocking = ready.data?.blocking ?? [];

  return (
    <div className="panel">
      <header>
        <h3>Release readiness</h3>
        <span className="eyebrow" style={{ marginLeft: "auto" }}>
          {at.branch_or_tag} · {at.variant}
        </span>
      </header>
      {shipped ? (
        <>
          {/* Wrapped like every other table on the page: on a narrow screen a
              wide table scrolls sideways and says so. */}
          <Wide>
            <table className="plain">
              <thead>
                <tr>
                  <th />
                  <th className="num">Now</th>
                  <th className="num">{shipped.branch_or_tag_name || shipped.branch_or_tag}</th>
                  <th className="num">Change</th>
                </tr>
              </thead>
              <tbody>
                {BANDS.map((band) => (
                  <tr key={band}>
                    <td style={{ textTransform: "capitalize" }}>{band}</td>
                    <td className="num">{now?.[band] ?? 0}</td>
                    <td className="num hint">{shipped[band] ?? 0}</td>
                    <td className="num">
                      <Change from={shipped[band] ?? 0} to={now?.[band] ?? 0} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Wide>
          <p className="reading">
            {reading(
              now?.critical ?? 0,
              shipped.critical ?? 0,
              shipped.branch_or_tag_name || shipped.branch_or_tag || "",
            )}
            {minimum ? ` Counted at ${minimum} and above.` : ""}
          </p>
        </>
      ) : (
        <p className="reading">{ready.data?.why || "Nothing to compare against yet."}</p>
      )}
      {/* What the count is made of. A number read at the moment there is no
          time to go and assemble the list is a number nobody can act on, and
          this is the screen a release conversation happens in. Anything
          agreed to is absent: agreeing is the decision to ship with it. */}
      {blocking.length > 0 && (
        <>
          <p className="reading" style={{ marginBottom: 4 }}>
            <b>{(ready.data?.blockers ?? 0).toLocaleString()} nobody has agreed to ship with</b>
            {(ready.data?.blockers ?? 0) > blocking.length && (
              <span className="hint"> · the worst {blocking.length} shown</span>
            )}
          </p>
          <ul className="plain">
            {blocking.map((row) => (
              /* Keyed on the version too, because that is what the group is
                 keyed on: one issue at three versions of one component is
                 three rows. */
              <li key={`${row.vulnerability} ${row.component} ${row.version ?? ""}`}>
                <Severity word={row.severity} /> <span className="id">{row.vulnerability}</span>{" "}
                {/* The component is the part that varies, and a Debian kernel
                    package is forty-four characters of it. It shrinks and
                    ellipsizes like the varying part of every other panel list;
                    given `.id` alone it could do neither and ran out of the
                    panel. The whole of it is on the title. */}
                <span className="what id" title={`${row.component} ${row.version ?? ""}`.trim()}>
                  {row.component}
                  {row.version && <span className="hint"> {row.version}</span>}
                </span>
                {row.state && <span className="hint"> · {row.state}</span>}
                {row.due && <span className="hint"> · due {row.due}</span>}
              </li>
            ))}
          </ul>
        </>
      )}
      {at.product && (
        <footer>
          <Link
            to={blockingPath({
              product: at.product,
              branch_or_tag: at.branch_or_tag,
              variant: at.variant,
            })}
            className="linkish"
          >
            Work what is blocking →
          </Link>
          <Link to={comparisonAt(at.product)} className="linkish">
            Release comparison →
          </Link>
        </footer>
      )}
    </div>
  );
}

// The move, said as a direction rather than as a signed number. Fewer is
// better here, so the color follows the meaning and not the arithmetic.
function Change({ from, to }: { from: number; to: number }) {
  const by = to - from;
  if (by === 0) return <span className="hint">same</span>;
  return (
    <span style={{ color: by > 0 ? "var(--sev-high)" : "var(--ok)", fontWeight: 600 }}>
      {by > 0 ? "+" : "−"}
      {Math.abs(by)}
    </span>
  );
}

// One sentence somebody can repeat in a meeting.
function reading(now: number, shipped: number, release: string): string {
  if (now === shipped) return `${now} critical now, the same as ${release} shipped with.`;
  if (now > shipped) {
    return `${now} critical now against ${shipped} in ${release} — ${now - shipped} more than last shipped.`;
  }
  return `${now} critical now against ${shipped} in ${release} — ${shipped - now} fewer than last shipped.`;
}
