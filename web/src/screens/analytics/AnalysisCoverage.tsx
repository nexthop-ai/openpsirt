// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom";
import { useAnalysisCoverage, type Analyzed } from "../../api/codeFindings";
import { codeFindingsAt } from "../../app/routes";
import { Empty } from "../../ui/Empty";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { Wide } from "../../ui/Wide";
import { at as minute } from "../../ui/when";
import { REASONS } from "../codeTrend";
import { Sheet } from "./Sheet";
import { Segments, boundedAsked } from "./Window";
import { Files, Gate, WEEKS, inDays, queryOf, useFigureAsked, weeksWords } from "./securityTesting";

// What is analyzed, and what has gone quiet: every series on every build in
// use, its newest run and what it covered, and its own expected interval.
// A series is quiet when no comparable run arrived within its own interval,
// never one window for the deployment: a quarterly scan is not quiet after a
// week.

function standing(each: Analyzed): string {
  if (each.past_end_of_life) return "Past end of life";
  if (each.quiet) return "Gone quiet";
  if (!each.last_arrived) return "Never applied";
  if (each.not_comparable) return "Not comparable";
  return "Arriving";
}

export function AnalysisCoverage() {
  const { product, asked, code, reads, of, params } = useFigureAsked();
  const weeks = boundedAsked(params.get("weeks"), 104, 13);
  const narrowed = {
    branch_or_tag: asked.branch_or_tag,
    variant: asked.variant,
    series: asked.series,
    method: asked.method,
    weeks,
  };
  const coverage = useAnalysisCoverage(product, narrowed, !!product && reads);
  const items = coverage.data?.items ?? [];
  return (
    <Sheet
      settled={!product || !reads || coverage.isSuccess}
      name="Analysis coverage"
      answers="what is analyzed, and what has gone quiet."
      of={of}
      asked={`runs over ${weeksWords(weeks)}`}
    >
      <div className="controls">
        <Segments
          label="Runs over"
          param="weeks"
          offered={WEEKS}
          chosen={weeks}
          words={weeksWords}
        />
        {product && reads && (
          <Files
            path="/v1/products/{product}/analysis-coverage.{format}"
            product={product}
            query={queryOf(narrowed)}
          />
        )}
      </div>
      <Gate product={product} code={code}>
        {coverage.isPending ? (
          <Loading />
        ) : coverage.isError ? (
          <Failed error={coverage.error} what="The analysis coverage could not be read." />
        ) : items.length === 0 ? (
          <section className="panel">
            <Empty
              title="No analyzer runs here."
              detail="No series has sent a run to a build in use."
            />
          </section>
        ) : (
          <section className="panel">
            <h3>
              {coverage.data.quiet === 0
                ? "No series has gone quiet"
                : `${coverage.data.quiet.toLocaleString()} gone quiet`}
            </h3>
            <Wide>
              <table>
                <thead>
                  <tr>
                    <th>Build</th>
                    <th>Series</th>
                    <th>Standing</th>
                    <th>Last run</th>
                    <th
                      className="num"
                      title="The median of its newest gaps between runs on this build"
                    >
                      Usually every
                    </th>
                    <th
                      className="num"
                      title="What its newest run analyzed against what it was meant to"
                    >
                      Units
                    </th>
                    <th>Last comparable</th>
                    <th className="num" title={`Applied over ${weeksWords(weeks)}`}>
                      Applied
                    </th>
                    <th className="num" title="Applied, but its absences prove nothing">
                      Not comparable
                    </th>
                    <th className="num" title="Couldn't be read">
                      Failed
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((each) => (
                    <tr key={`${each.branch_or_tag} ${each.variant} ${each.series}`}>
                      <td>
                        <Link
                          to={codeFindingsAt(product, {
                            branch_or_tag: each.branch_or_tag,
                            variant: each.variant,
                            series: each.series,
                          })}
                        >
                          {each.branch_or_tag_name} · {each.variant_name}
                        </Link>
                      </td>
                      <td>{each.series}</td>
                      <td title={each.not_comparable && REASONS[each.not_comparable]}>
                        {standing(each)}
                        {each.not_comparable && !each.quiet && (
                          <span className="hint">
                            {" "}
                            · {REASONS[each.not_comparable] ?? each.not_comparable}
                          </span>
                        )}
                      </td>
                      <td className="hint">
                        {each.last_arrived ? minute(each.last_arrived) : "—"}
                      </td>
                      <td className="num">
                        {each.expected_days === undefined ? (
                          <span className="hint" title="Fewer than three runs applied">
                            —
                          </span>
                        ) : (
                          inDays(each.expected_days)
                        )}
                      </td>
                      <td className="num hint">
                        {each.units_analyzed === undefined
                          ? "—"
                          : `${each.units_analyzed.toLocaleString()} of ${
                              each.units_expected?.toLocaleString() ?? "?"
                            }`}
                      </td>
                      <td className="hint">
                        {each.last_comparable ? minute(each.last_comparable) : "none"}
                        {each.silent_days !== undefined && (
                          <span title="Counted from the oldest run read where none was comparable">
                            {` · ${inDays(each.silent_days)} silent`}
                          </span>
                        )}
                      </td>
                      <td className="num">{each.applied_runs.toLocaleString()}</td>
                      <td className="num">{each.not_comparable_runs.toLocaleString()}</td>
                      <td className="num">{each.failed_runs.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Wide>
            <p className="hint" title="Needs three applied runs.">
              Quiet: no comparable run in three usual gaps, at least a day; never past end of life.
            </p>
          </section>
        )}
      </Gate>
    </Sheet>
  );
}
