import { BANDS } from "../../ui/severities";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import { unwrap } from "../../api/queries";
import { findingsPath, scopeQuery, useScope } from "../../app/scope";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { Paged } from "../../ui/Paged";
import { Empty } from "../../ui/Empty";
import { Severity } from "../../ui/Severity";
import { Because, Outcome } from "../../ui/Outcome";
import { Sheet } from "./Sheet";
import {
  PeriodPicker,
  WindowPicker,
  asked,
  coveringPeriod,
  daysAsked,
  periodAsked,
  stated,
  windowStart,
} from "./Window";
import { Wide } from "../../ui/Wide";

// How long the figures cover. Thirty days is the window the remediation
// metrics names and the one people quote; the others are here because a month
// is too short to see a quarter's shape and too long to see this week's.
const WINDOWS = [7, 30, 90] as const;

// The newest dismissals the sheet shows, and the most repeat deferrals it
// lists. Both are pages of something larger, and both say so underneath.
const NEWEST = 20;
const REPEATS = 50;

// The three outcomes that hide risk, and so the three that need a second
// person. Named together because "what has been argued away" is asked of all
// of them at once, and asked of one it answers about a third of the program.
const DISMISSALS: ("not-applicable" | "wont-fix" | "already-fixed")[] = [
  "not-applicable",
  "wont-fix",
  "already-fixed",
];

// Severity words worst first, the way every other list here orders them. A
// word the ladder does not hold sorts last, which is where "unrated" belongs
// and where anything a producer invented belongs too.
function bandOrder(band: string): number {
  const at = (BANDS as readonly string[]).indexOf(band);
  return at < 0 ? BANDS.length : at;
}

// The findings list, narrowed to what one aging bucket counts. Built here
// rather than typed into each row so the link and the figure cannot come to
// ask different questions.
function openFor(at: Parameters<typeof findingsPath>[0], days: number): string {
  const asked = new URLSearchParams();
  if (days > 0) asked.set("open_for", String(days));
  // The bucket counts everything open, including what the product's line keeps
  // out — so the list it opens has to as well, or the two numbers disagree.
  asked.set("below", "yes");
  return `${findingsPath(at)}?${asked.toString()}`;
}

// How the work is going, rather than what the work is: how fast things are
// fixed, what is aging, how long a judgment waits for a second person, what
// keeps being put off, and what has been argued away.
//
// It is figures rather than a list, so it prints rather than exporting.
// There is no stream behind a set of aggregates, and inventing one would
// publish a file nothing here computed. Every figure links to the list it
// counts instead, and that list exports — which is also what somebody asking
// for "the numbers as a file" actually wants, since a row nobody can trace
// back to a finding is a number in a spreadsheet.
export function Overview() {
  const at = useScope();
  const scope = scopeQuery(at);
  const [params] = useSearchParams();
  const days = daysAsked(params, 30);
  const period = periodAsked(params);
  // What every figure on this sheet covers, and what the lists it links to
  // have to be narrowed by. One value, because a heading saying one stretch
  // over a list showing another is the failure this sheet is easiest to ship.
  const when = asked(period, days);
  // A period naming only its end still runs from the beginning, so there is
  // no date to narrow a list by — and a list narrowed by an empty one opens
  // over all time beside a figure that counts one window.
  const began = stated(period) ? period.from : windowStart(days);

  const pace = useQuery({
    queryKey: ["remediation", scope, when],
    queryFn: async () =>
      unwrap(await api.GET("/v1/remediation", { params: { query: { ...when, ...scope } } })),
  });
  // What has been argued away, which is what an auditor asks for first.
  //
  // All three dismissals, read together because what they have in common
  // is that nothing was changed: "not applicable" claims the code is not
  // reachable, "will not fix" that it is not worth fixing, and "already fixed
  // here" that a packager backported it. Asking only the first is how a
  // program that dismisses everything as "will not fix" reads as a program
  // that has argued nothing away.
  //
  // Read from the record rather than from the decisions list, because the
  // record is the one that takes an outcome repeated and names the place each
  // judgment sits at.
  const argued = useQuery({
    queryKey: ["dismissals", at.product ?? "", when],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/audit", {
          params: {
            query: {
              outcome: DISMISSALS,
              state: ["approved" as const],
              // The window this report states, so the sheet does not carry a
              // header saying ninety days over a list that ignores it. Dated
              // by when the judgment was argued, which is what the record
              // dates by.
              ...(began ? { from: began } : {}),
              ...(period.to ? { to: period.to } : {}),
              limit: NEWEST,
              ...(at.product ? { product: [at.product] } : {}),
            },
          },
        }),
      ),
  });
  const measures = useQuery({
    queryKey: ["measures", when, at.product ?? ""],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/measures", {
          params: { query: { ...when, ...(at.product ? { product: at.product } : {}) } },
        }),
      ),
  });
  const repeated = useQuery({
    queryKey: ["repeated", at.product ?? ""],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/deferrals/repeated", {
          params: { query: { limit: REPEATS, ...(at.product ? { product: at.product } : {}) } },
        }),
      ),
  });

  return (
    <Sheet
      settled={pace.isSuccess && measures.isSuccess && repeated.isSuccess && argued.isSuccess}
      name="Program overview"
      answers="how the work is going, rather than what it is."
      asked={coveringPeriod(period, days)}
    >
      <WindowPicker offered={WINDOWS} days={days} />
      <PeriodPicker period={period} />

      <section className="panel" style={{ marginTop: 14 }}>
        <h3>Keeping pace</h3>
        {pace.isPending ? (
          <Loading />
        ) : pace.isError ? (
          <Failed error={pace.error} what="How fast things are fixed could not be read." />
        ) : (
          <>
            <div className="kpis" style={{ marginTop: 8 }}>
              {/* Both open the list they count. "Fixed" opens what closed in
                  the window, which is a different population from this list's
                  own — asking for it changes what the list is about rather
                  than narrowing it, and the list says so when it is asked. */}
              <Link
                className="kpi"
                to={`${findingsPath(at)}${began ? `?closed_after=${began}` : ""}`}
              >
                <span className="l">Fixed</span>
                <span className="n">{(pace.data?.fixed ?? 0).toLocaleString()}</span>
                <span className="d">
                  distinct issues that went away · a version carrying the issue forward is not a fix
                </span>
              </Link>
              <Link
                className="kpi"
                to={`${findingsPath(at)}${began ? `?opened_after=${began}` : ""}`}
              >
                <span className="l">Appeared</span>
                <span className="n">{(pace.data?.opened ?? 0).toLocaleString()}</span>
                <span className="d">distinct issues, same window and unit as fixed</span>
              </Link>
            </div>

            <h4 style={{ marginTop: 14 }}>Average time to fix</h4>
            {Object.keys(pace.data?.time_to_fix ?? {}).length === 0 ? (
              <p className="hint">Nothing closed in this window.</p>
            ) : (
              <ul className="files">
                {Object.entries(pace.data?.time_to_fix ?? {})
                  // Worst first, the way every other list here orders them.
                  // A bare sort is alphabetical, which printed low above
                  // medium under a heading the aging table forty lines down
                  // orders correctly.
                  .sort(([a], [b]) => bandOrder(a) - bandOrder(b))
                  .map(([band, hours]) => (
                    <li key={band}>
                      <Severity word={band} /> <b>{Math.round((hours as number) / 24)}</b> days
                    </li>
                  ))}
              </ul>
            )}

            <h4 style={{ marginTop: 14 }}>What is aging</h4>
            {/* One number per bucket says a hundred things are over three
                months old and neither whether any of them matters nor
                whether anybody has looked. A bucket of lows that were all
                argued and dismissed is a tidy record; a bucket with four
                criticals nobody has read is a backlog. */}
            <Wide>
              <table>
                <thead>
                  <tr>
                    <th>Open for</th>
                    <th className="num">Issues</th>
                    <th>By severity</th>
                    <th className="num">Nobody has said</th>
                  </tr>
                </thead>
                <tbody>
                  {(pace.data?.aging ?? []).map((bucket) => (
                    <tr key={bucket.label}>
                      {/* Every figure opens the list it counts. A number
                          nobody can act on from where they read it sends
                          somebody to build the same question by hand, and the
                          question they build is not always the same one. */}
                      <td>
                        <Link to={openFor(at, bucket.days ?? 0)}>{bucket.label}</Link>
                      </td>
                      <td className="num">
                        <Link to={openFor(at, bucket.days ?? 0)}>
                          {(bucket.open ?? 0).toLocaleString()}
                        </Link>
                      </td>
                      <td>
                        {Object.entries(bucket.by_severity ?? {})
                          .sort(([a], [b]) => bandOrder(a) - bandOrder(b))
                          .map(([band, n]) => (
                            <span key={band} style={{ marginRight: 8 }}>
                              {band === "unrated" ? (
                                <span className="hint">unrated</span>
                              ) : (
                                <Severity word={band} />
                              )}{" "}
                              {n.toLocaleString()}
                            </span>
                          ))}
                        {Object.keys(bucket.by_severity ?? {}).length === 0 && (
                          <span className="hint">—</span>
                        )}
                      </td>
                      <td className="num">
                        {(bucket.undecided ?? 0) > 0 ? (
                          <Link
                            to={`${openFor(at, bucket.days ?? 0)}&state=undecided`}
                            className="state open"
                          >
                            {(bucket.undecided ?? 0).toLocaleString()}
                          </Link>
                        ) : (
                          <span className="hint">none</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Wide>
            <p className="hint">
              &ldquo;Nobody has said&rdquo; counts what carries no standing judgment. A claim
              waiting on a second person suppresses nothing.
            </p>
          </>
        )}
      </section>

      {/* How long it takes and who is doing it. Every one of these was in
          the record and none was added up: a queue of the same size is a
          different place depending on whether things sit in it for a day or a
          quarter. */}
      <section className="panel" style={{ marginTop: 14 }}>
        <h3>How long triage is taking</h3>
        {/* Said inside the printing area rather than behind noprint: the
            printed header states the sheet's scope over every section, and
            this one does not take it. A sheet that states a scope three of its
            four sections do not honour is one nobody can check. */}
        <p className="hint" style={{ marginTop: 0 }}>
          Every product in this deployment, whatever is picked above.
        </p>
        {measures.isPending ? (
          <Loading />
        ) : measures.isError ? (
          <Failed error={measures.error} what="How triage is going could not be read." />
        ) : (measures.data?.sampled ?? 0) === 0 ? (
          <p className="hint">Nothing was proposed in this window.</p>
        ) : (
          <>
            <p className="reading">
              Three figures rather than an average, which would describe neither a busy day nor a
              slow quarter.
            </p>
            <Wide>
              <table>
                <thead>
                  <tr>
                    <th>Wait</th>
                    <th>Severity</th>
                    <th className="num">Count</th>
                    <th className="num">Middle</th>
                    <th className="num">9 in 10 under</th>
                    <th className="num">Longest</th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    ["Before anybody decided", measures.data?.time_to_decide ?? []],
                    ["Waiting for a second person", measures.data?.time_to_agree ?? []],
                  ].map(([what, bands]) =>
                    (bands as { band?: string }[]).length === 0 ? (
                      <tr key={what as string}>
                        <td>{what as string}</td>
                        <td colSpan={5} className="hint">
                          nothing yet
                        </td>
                      </tr>
                    ) : (
                      (
                        bands as {
                          band?: string;
                          count?: number;
                          median_days?: number;
                          p90_days?: number;
                          worst_days?: number;
                        }[]
                      ).map((row, i) => (
                        <tr key={`${what as string} ${row.band}`}>
                          <td>{i === 0 ? (what as string) : ""}</td>
                          <td>
                            {row.band === "unrated" ? (
                              <span className="hint">unrated</span>
                            ) : (
                              <Severity word={row.band} />
                            )}
                          </td>
                          <td className="num">{(row.count ?? 0).toLocaleString()}</td>
                          <td className="num">{row.median_days} d</td>
                          <td className="num">{row.p90_days} d</td>
                          <td className="num">{row.worst_days} d</td>
                        </tr>
                      ))
                    ),
                  )}
                </tbody>
              </table>
            </Wide>
            <p className="hint">
              Measured over {(measures.data?.sampled ?? 0).toLocaleString()}{" "}
              {(measures.data?.sampled ?? 0) === 1 ? "claim" : "claims"}
              {measures.data?.capped
                ? " — the most recent part of the window rather than all of it"
                : ""}
              . {(measures.data?.sent_back ?? 0).toLocaleString()}{" "}
              {(measures.data?.sent_back ?? 0) === 1 ? "claim was" : "claims were"} sent back for
              more, which is the approver&rsquo;s other answer: a queue moving because claims are
              good and one moving because nobody reads them look alike without it.
            </p>

            <h4 style={{ marginTop: 14 }}>Who got through what</h4>
            {(measures.data?.throughput ?? []).length === 0 ? (
              <p className="hint">Nobody in this window.</p>
            ) : (
              <Wide>
                <table>
                  <thead>
                    <tr>
                      <th>Person</th>
                      <th className="num">Proposed</th>
                      <th className="num">Agreed to</th>
                      <th className="num">Withdrawn</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(measures.data?.throughput ?? []).map((row) => (
                      <tr key={row.person}>
                        <td className="id">{row.person}</td>
                        <td className="num">{(row.proposed ?? 0).toLocaleString()}</td>
                        <td className="num">{(row.approved ?? 0).toLocaleString()}</td>
                        <td className="num">{(row.withdrawn ?? 0).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Wide>
            )}
            <p className="hint">
              Dated by when the approval happened. Narrowed to what you may read.
            </p>
          </>
        )}
      </section>

      <section className="panel" style={{ marginTop: 14 }}>
        <h3>Repeated deferrals</h3>
        <p className="hint">
          One item deferred three times is a judgment; forty is an undocumented policy. This
          product, not this build — and over the whole record, not the window above.{" "}
          {/* The one list on this sheet rather than a figure, so it is the one
              thing here that exports. A review argues over the rows. */}
          <a href={repeatsFile(at.product ?? "", "csv")}>CSV</a> ·{" "}
          <a href={repeatsFile(at.product ?? "", "json")}>JSON</a>
        </p>
        {repeated.isPending ? (
          <Loading />
        ) : repeated.isError ? (
          <Failed error={repeated.error} what="Repeat deferrals could not be read." />
        ) : (repeated.data?.items ?? []).length === 0 ? (
          <Empty
            title="Nothing has been put off more than once."
            detail="Deferrals are recorded either way; this lists only the ones that repeat."
          />
        ) : (
          <Wide>
            <table>
              <thead>
                <tr>
                  <th>Issue</th>
                  <th>Product</th>
                  <th className="num">Times</th>
                  <th className="num">Total days</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {(repeated.data?.items ?? []).map((row) => (
                  <tr key={`${row.product} ${row.vulnerability} ${row.place}`}>
                    <td>
                      <Severity word={row.severity} />{" "}
                      <span className="id">{row.vulnerability}</span>
                    </td>
                    <td>{row.product}</td>
                    <td className="num">{row.times}</td>
                    <td className="num">{row.total_days}</td>
                    <td>
                      {row.standing ? (
                        <span className="state waiting">Still deferred</span>
                      ) : (
                        <span className="hint">ran out</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Wide>
        )}
        {/* How many there are, not how many are listed. A capped list drawn as
            the whole of it is how "forty repeat deferrals" reads as the whole
            shape of a program that has two hundred — and the endpoint now says
            what the whole is, so the footer says it too. */}
        <Paged
          shown={(repeated.data?.items ?? []).length}
          total={repeated.data?.total}
          limit={REPEATS}
          what="listed"
        />
      </section>

      <section className="panel" style={{ marginTop: 14 }}>
        <h3>Dismissals</h3>
        <p className="hint">
          Approved dismissals in this window, newest first. This product, not this build. One row
          per place, the way <Link to="/audit">the record</Link> lists them, so a judgment covering
          forty places is forty rows. All three dismissal outcomes are here.
        </p>
        {argued.isPending ? (
          <Loading />
        ) : argued.isError ? (
          <Failed error={argued.error} what="What was argued away could not be read." />
        ) : (argued.data?.items ?? []).length === 0 ? (
          <Empty
            title="Nothing has been argued away in this window."
            detail="A dismissal appears here once a second person has agreed to it."
          />
        ) : (
          <Wide>
            <table>
              <thead>
                <tr>
                  <th>Issue</th>
                  {/* Which of the three, because they are read together and
                      are not the same claim. */}
                  <th>Dismissed as</th>
                  <th>Component</th>
                  {/* Which place. Without it a claim covering forty of them
                      draws forty rows that differ in nothing a reader can
                      see, which reads as the same dismissal recorded forty
                      times. */}
                  <th>Where</th>
                  <th>Because</th>
                  <th>Reasoning</th>
                </tr>
              </thead>
              <tbody>
                {(argued.data?.items ?? []).map((row) => (
                  <tr key={row.id} className="row">
                    <td>
                      <Link to={`/decisions/${row.id}`} className="id">
                        {row.issue}
                      </Link>
                    </td>
                    <td>
                      <Outcome outcome={row.outcome} />
                    </td>
                    <td className="id">{row.component}</td>
                    <td className="id">
                      {row.consumer || <span className="hint">the build itself</span>}
                    </td>
                    <td>
                      {row.justification ? (
                        <Because code={row.justification} />
                      ) : (
                        <span className="hint">—</span>
                      )}
                    </td>
                    <td className="hint" style={{ maxWidth: "42ch" }}>
                      {(row.reasoning ?? "").split("\n")[0]?.slice(0, 140)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Wide>
        )}
        {/* The record says how many there are; the sheet shows the newest
            page of them. Without this the heading "approved dismissals in this
            window" stands over twenty rows of ninety. */}
        <Paged
          shown={(argued.data?.items ?? []).length}
          total={argued.data?.total}
          limit={NEWEST}
        />
      </section>
    </Sheet>
  );
}

// Where what keeps being put off comes from as a file. A link somebody
// follows rather than a request this page makes, narrowed the way the panel
// above it is.
function repeatsFile(product: string, format: string): string {
  const asked = product ? `?product=${encodeURIComponent(product)}` : "";
  return `/v1/deferrals/repeated.${format}${asked}`;
}
