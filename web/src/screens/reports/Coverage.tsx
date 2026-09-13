import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import { unwrap } from "../../api/queries";
import { scopeQuery, useScope } from "../../app/scope";
import { Empty } from "../../ui/Empty";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { on } from "../../ui/when";
import { Sheet } from "./Sheet";

// What is being scanned, and what has gone silent.
//
// **Every other number here is worthless if a build stopped being scanned**,
// and silence looks exactly like health: a build nothing arrives for reports
// no new findings, fails nothing, and sits above one that is still being
// scanned on every list ordered by what is open. It is the same failure shape
// as a skipped database engine passing a test suite.
//
// The front page names the three quietest and the inventories screen answers
// for one product. This is the whole estate, longest silent first, which is
// the form somebody takes to whoever owns the pipeline.
export function Coverage() {
  const at = useScope();
  const scope = scopeQuery(at);
  const coverage = useQuery({
    queryKey: ["scanning", "report", scope],
    queryFn: async () => unwrap(await api.GET("/v1/scanning", { params: { query: scope } })),
  });

  const builds = coverage.data?.items ?? [];
  const retired = builds.filter((build) => build.retired);
  // Every figure is counted over the builds still in support. A build out of
  // support is never marked quiet — silence there is expected — so counting
  // coverage over all of them puts a release nothing has scanned in a year on
  // the covered side of the figure, which is the opposite of what this report
  // is for.
  const live = builds.filter((build) => !build.retired);
  const quiet = live.filter((build) => build.quiet);
  // Never scanned is its own answer rather than a long silence: a build
  // nothing has ever been filed against may be one nobody wired up, and its
  // days are measured from when it was declared.
  const never = live.filter((build) => !build.last_received_at);
  const asked = new URLSearchParams(scope).toString();

  return (
    <Sheet
      name="Scan coverage"
      answers="what is being scanned, and what has quietly stopped."
      asked={`quiet after ${coverage.data?.quiet_after_days ?? 7} days`}
    >
      {coverage.isPending ? (
        <Loading />
      ) : coverage.isError ? (
        <Failed error={coverage.error} what="What has been scanned could not be read." />
      ) : (
        <>
          <section className="panel">
            <h3>Where the estate stands</h3>
            <div className="kpis" style={{ marginTop: 8 }}>
              <div className="kpi">
                <span className="l">Being scanned</span>
                <span className="n">
                  {(live.length - quiet.length).toLocaleString()} of {live.length.toLocaleString()}
                </span>
                <span className="d">
                  builds still in support, counted whole rather than per product
                </span>
              </div>
              <div className="kpi">
                <span className="l">Gone quiet</span>
                <span className="n">{quiet.length.toLocaleString()}</span>
                <span className="d">
                  nothing has arrived for longer than this deployment allows
                </span>
              </div>
              <div className="kpi">
                <span className="l">Never scanned</span>
                <span className="n">{never.length.toLocaleString()}</span>
                <span className="d">declared and never filed against</span>
              </div>
            </div>
            <p className="hint" style={{ marginTop: 10 }}>
              {retired.length > 0 && (
                <>
                  A further {retired.length.toLocaleString()}{" "}
                  {retired.length === 1 ? "build is" : "builds are"} out of support and left out of
                  those three figures. They are listed below and never counted as quiet: silence
                  there is expected, and a coverage report filling with them stops catching the
                  product that dropped out.{" "}
                </>
              )}
              The whole of it as a file — <a href={fileAt("csv", asked)}>CSV</a> ·{" "}
              <a href={fileAt("json", asked)}>JSON</a>, with the threshold stated in it.
            </p>
          </section>

          <section className="panel" style={{ marginTop: 14 }}>
            <h3>Every build, longest silent first</h3>
            {builds.length === 0 ? (
              <Empty
                title="No build to report on."
                detail="Nothing has been declared at this scope, or nothing here is yours to read."
              />
            ) : (
              <div className="tablewrap">
                <table>
                  <thead>
                    <tr>
                      <th>Product</th>
                      <th>Branch or tag</th>
                      <th>Variant</th>
                      <th>Last inventory</th>
                      <th className="num">Silent for</th>
                      <th>State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {builds.map((build) => (
                      <tr key={`${build.product} ${build.stream} ${build.variant}`} className="row">
                        <td>{build.product}</td>
                        <td>
                          {/* The build's own inventories screen, which is where
                              somebody goes to see what did arrive and when. */}
                          <Link to={scansAt(build.product, build.stream, build.variant)}>
                            {build.stream}
                          </Link>{" "}
                          <span className="hint">{build.stream_kind}</span>
                        </td>
                        <td>{build.variant}</td>
                        <td>
                          {build.last_received_at ? (
                            on(build.last_received_at)
                          ) : (
                            <span className="hint">never</span>
                          )}
                        </td>
                        <td className="num">
                          {build.quiet_days.toLocaleString()}{" "}
                          {build.quiet_days === 1 ? "day" : "days"}
                        </td>
                        <td>
                          {build.quiet ? (
                            <span className="state open">
                              {build.last_received_at ? "quiet" : "never scanned"}
                            </span>
                          ) : build.retired ? (
                            <span className="hint">out of support</span>
                          ) : (
                            <span className="state closed">scanned</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </Sheet>
  );
}

// Where the file comes from. A link somebody follows rather than a request
// this page makes, so the browser fetches it with the session it already has.
function fileAt(format: string, asked: string): string {
  return `/v1/scanning.${format}${asked ? `?${asked}` : ""}`;
}

function scansAt(product: string, stream: string, variant: string): string {
  return (
    `/products/${encodeURIComponent(product)}` +
    `/streams/${encodeURIComponent(stream)}` +
    `/variants/${encodeURIComponent(variant)}/scans`
  );
}
