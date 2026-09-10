import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import { unwrap } from "../../api/queries";
import { findingsPath, scopeQuery, useScope } from "../../app/scope";
import { Empty } from "../../ui/Empty";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { Sheet } from "./Sheet";

// What is still shipped and no longer maintained.
//
// **This is the pile that dropped out of every deadline figure by design.**
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
  const ended = useQuery({
    queryKey: ["out-of-support", scope],
    queryFn: async () =>
      unwrap(await api.GET("/v1/releases/out-of-support", { params: { query: scope } })),
  });

  const rows = ended.data?.items ?? [];
  const asked = new URLSearchParams(scope).toString();

  return (
    <Sheet name="Releases out of support" answers="what is still shipped and no longer maintained.">
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
            Counted as issues at components rather than once per place, which is how every
            release-level count here is counted. The list a figure opens can show slightly fewer
            rows, because it folds sibling packages built from one source into one. None of it
            carries a deadline: past end-of-life the deadline comes off every open finding, so none
            of this is overdue or due soon and none of it is in any figure built on either. Nothing
            is hidden — the findings and the history stay, and stay reportable. What ended is what
            is expected of us.
          </p>
          {rows.length === 0 ? (
            <Empty
              title="Nothing is out of support."
              detail="A release appears here once its end-of-life date has passed, or its product's has and it has not stated one of its own."
            />
          ) : (
            <>
              <p className="hint">
                The whole of it as a file — <a href={fileAt("csv", asked)}>CSV</a> ·{" "}
                <a href={fileAt("json", asked)}>JSON</a>, with the day it was taken stated in it.
              </p>
              <div className="tablewrap">
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
              </div>
            </>
          )}
        </section>
      )}
    </Sheet>
  );
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
function openAt(product: string, stream: string, kind: string): string {
  const asked = new URLSearchParams({ stream });
  asked.set("on", kind === "tag" ? "tag" : "branch");
  asked.set("support", "past-eol");
  return `${findingsPath({ product })}?${asked.toString()}`;
}
