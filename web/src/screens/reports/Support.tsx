import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import { unwrap } from "../../api/queries";
import { findingsPath, scopeQuery, useScope } from "../../app/scope";
import { Empty } from "../../ui/Empty";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { Sheet } from "./Sheet";
import { Wide } from "../../ui/Wide";

// What is still shipped and no longer maintained.
//
// This is the pile that dropped out of every deadline figure by design.
// Past end-of-life the deadline comes off every open finding on a release, so
// none of it is overdue, none of it is due soon, and none of it reaches a
// count built on either. That is the right behavior — no work will land there
// — and it means asking for it is the only way to see it.
//
// It is not a coverage question and not a compliance one. A release out of
// support going quiet is expected and work on it is not late; what somebody is
// asking here is what a customer is still running that nobody is fixing.
export function Support() {
  const at = useScope();
  const scope = scopeQuery(at);
  const [params, setParams] = useSearchParams();
  // How far ahead to warn. Nothing by default, because this report is about
  // what has already gone and a second population appearing unasked would
  // change what the figures at the top of it count.
  const within = aheadAsked(params);
  const ended = useQuery({
    queryKey: ["out-of-support", scope, within],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/releases/out-of-support", {
          params: { query: { ...scope, ...(within > 0 ? { within } : {}) } },
        }),
      ),
  });

  const rows = ended.data?.items ?? [];
  const ending = ended.data?.ending ?? [];
  const asked = new URLSearchParams({
    ...scope,
    ...(within > 0 ? { within: String(within) } : {}),
  }).toString();

  return (
    <Sheet
      settled={ended.isSuccess}
      name="Releases out of support"
      answers="what is still shipped and no longer maintained."
    >
      <div className="controls">
        <div className="seg" role="group" aria-label="Warn ahead">
          {AHEAD.map((n) => (
            <button
              key={n}
              type="button"
              aria-pressed={within === n}
              onClick={() => {
                const next = new URLSearchParams(params);
                if (n === 0) next.delete("within");
                else next.set("within", String(n));
                setParams(next);
              }}
            >
              {n === 0 ? "what has gone" : `and the next ${n} days`}
            </button>
          ))}
        </div>
      </div>

      {ended.isPending ? (
        <Loading />
      ) : ended.isError ? (
        <Failed error={ended.error} what="What is out of support could not be read." />
      ) : (
        <section className="panel">
          <h3>
            {(ended.data?.total ?? 0).toLocaleString()}{" "}
            {(ended.data?.total ?? 0) === 1 ? "release" : "releases"}, with{" "}
            {(ended.data?.open ?? 0).toLocaleString()} open
          </h3>
          <p className="hint" style={{ marginTop: 0 }}>
            Issues at components, not once per place. Past end-of-life nothing carries a deadline,
            so none of this is overdue.
          </p>
          {rows.length === 0 ? (
            <Empty
              title="Nothing is out of support."
              detail="Appears once the release end-of-life date has passed, or the product's has and it states none of its own."
            />
          ) : (
            <>
              <p className="hint">
                The whole of it as a file — <a href={fileAt("csv", asked)}>CSV</a> ·{" "}
                <a href={fileAt("json", asked)}>JSON</a>, with the day it was taken stated in it.
              </p>
              <Wide>
                <table>
                  <thead>
                    <tr>
                      <th>Product</th>
                      <th>Release</th>
                      <th>Support ended</th>
                      <th className="num">Ago</th>
                      <th className="num">Open</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => (
                      <tr key={`${row.product} ${row.stream}`} className="row">
                        <td>{row.product}</td>
                        <td>
                          {row.stream} <span className="hint">{row.kind}</span>
                        </td>
                        <td>
                          {row.ended_on}{" "}
                          {/* Following the product's date and stating the same
                              one are different: only the first moves when the
                              product changes its mind. */}
                          {row.inherited && <span className="hint">the product&rsquo;s date</span>}
                        </td>
                        <td className="num">
                          {row.ended_days.toLocaleString()} {row.ended_days === 1 ? "day" : "days"}
                        </td>
                        <td className="num">
                          {/* Every figure opens the list it counts, and this
                              one has to say so twice over: the list keeps
                              itself to branches in support by default, which
                              is exactly the population this report is not
                              about. Linked without both, every row here opens
                              an empty list under a number that is not zero. */}
                          <Link
                            to={openAt(row.product, row.stream, row.kind)}
                            className={row.open > 0 ? "state open" : undefined}
                          >
                            {row.open.toLocaleString()}
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Wide>
            </>
          )}
        </section>
      )}

      {/* Kept apart from the pile above rather than sorted into it. The day a
          release crosses, the deadline comes off every open finding on it and
          that work leaves every overdue count at once — so one of these is a
          date somebody can still act before and the other is exposure nobody
          can work on, and a single list makes the warning the tail of the
          bad news. */}
      {ending.length > 0 && (
        <section className="panel" style={{ marginTop: 14 }}>
          <h3>
            {ending.length.toLocaleString()} about to go, with{" "}
            {(ended.data?.ending_open ?? 0).toLocaleString()} open
          </h3>
          <p className="hint" style={{ marginTop: 0 }}>
            On the day each one crosses, what is open on it loses its deadline and leaves every
            overdue count. That is the last moment anything can be planned for it.
          </p>
          <Wide>
            <table>
              <thead>
                <tr>
                  <th>Product</th>
                  <th>Release</th>
                  <th>Support ends</th>
                  <th className="num">Left</th>
                  <th className="num">Open</th>
                </tr>
              </thead>
              <tbody>
                {ending.map((row) => (
                  <tr key={`${row.product} ${row.stream}`} className="row">
                    <td>{row.product}</td>
                    <td>
                      {row.stream} <span className="hint">{row.kind}</span>
                    </td>
                    <td>
                      {row.ended_on}{" "}
                      {row.inherited && <span className="hint">the product&rsquo;s date</span>}
                    </td>
                    <td className="num">
                      {Math.abs(row.ended_days).toLocaleString()}{" "}
                      {Math.abs(row.ended_days) === 1 ? "day" : "days"}
                    </td>
                    <td className="num">
                      {/* Still in support, so this one links as the list's own
                          default would read it rather than past end of life. */}
                      <Link
                        to={endingAt(row.product, row.stream, row.kind)}
                        className={row.open > 0 ? "state open" : undefined}
                      >
                        {row.open.toLocaleString()}
                      </Link>
                    </td>
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

// How far ahead the sheet offers to warn. Nothing, a month, a quarter: the
// horizons a release plan is written in.
const AHEAD = [0, 30, 90] as const;

// The longest warning the sheet will ask for. The value goes to the server,
// which refuses one it cannot answer for, and an edited address is the
// ordinary way a wrong one arrives.
const FURTHEST = 3650;

// aheadAsked is how far ahead the address asks to look, checked rather than
// trusted.
function aheadAsked(params: URLSearchParams): number {
  const asked = params.get("within");
  if (asked === null) return 0;
  const days = Number(asked);
  if (!Number.isFinite(days) || days < 1 || days > FURTHEST) return 0;
  return Math.floor(days);
}

// Where the file comes from. A link somebody follows rather than a request
// this page makes, so the browser fetches it with the session it already has.
function fileAt(format: string, asked: string): string {
  return `/v1/releases/out-of-support.${format}${asked ? `?${asked}` : ""}`;
}

// What is open on one release, as the findings list would show it.
//
// The two filters the list applies to itself are stated rather than left to
// default: it keeps to branches in support unless told otherwise, and every
// release here is out of support, so the default answers nothing. The kind is
// the release's own, because a branch can be past end-of-life too.
// What is open on a release that has not gone yet. The same list, without the
// past-end-of-life filter: this one is still in support, which is what makes
// it something somebody can still act on.
function endingAt(product: string, stream: string, kind: string): string {
  const asked = new URLSearchParams({ stream });
  asked.set("on", kind === "tag" ? "tag" : "branch");
  return `${findingsPath({ product })}?${asked.toString()}`;
}

function openAt(product: string, stream: string, kind: string): string {
  const asked = new URLSearchParams({ stream });
  asked.set("on", kind === "tag" ? "tag" : "branch");
  asked.set("support", "past-eol");
  return `${findingsPath({ product })}?${asked.toString()}`;
}
