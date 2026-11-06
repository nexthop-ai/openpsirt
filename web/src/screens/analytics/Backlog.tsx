// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import { unwrap } from "../../api/queries";
import { fileAt } from "../../api/links";
import { scopeQuery, useScope } from "../../app/scope";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { Mix, Pace, PaceLegend, folded } from "../../ui/Charts";
import { settled } from "../../ui/trend";
import { Empty } from "../../ui/Empty";
import { Sheet } from "./Sheet";
import { Segments, StepSegments, boundedAsked } from "./Window";
import { Wide } from "../../ui/Wide";
import { useWho } from "../../app/session";
import { counted, heldLine, holding } from "../../app/families";
import { HeldLine } from "../../ui/HeldLine";
// The ladder, written down once. The columns are fixed rather than read off
// the data: ones that appear and vanish with the rows are columns nobody can
// build a spreadsheet against.
import { BANDS } from "../../ui/severities";

// The direction of the backlog, and the kind of thing making it move.
//
// The first question a manager asks, with a name, a window, a file, and the
// scope it is asked of.
//
// The flows are what a backlog is read for. Ten arriving and ten corrected is
// a team keeping pace where both are low, and a team losing ground where what
// arrives is critical and what leaves is not, which a line of totals draws as
// flat.

// The windows worth asking this over, by step. Two years is the longest the
// server answers for in either.
const WEEKS = [4, 13, 26, 52, 104] as const;
const DAYS = [14, 30, 90, 365, 730] as const;

export function Backlog() {
  const at = useScope();
  const scope = scopeQuery(at);
  const [params] = useSearchParams();
  // Daily unless the address says weekly. A value outside the range falls
  // back to the step's default, and a fraction is cut to a whole number.
  const daily = params.get("step") !== "week";
  const weeks = boundedAsked(params.get("weeks"), 104, 13);
  const days = boundedAsked(params.get("days"), 730, 30);
  const window = daily ? { days } : { weeks };

  // The backlog is dependency findings, asked and drawn only where the reader
  // reads them at the scope.
  const dependencies = holding(useWho().data, "dependency", at.product);
  const figures = counted(dependencies);
  const trend = useQuery({
    queryKey: ["backlog", scope, window],
    enabled: figures,
    queryFn: async () =>
      unwrap(await api.GET("/v1/trend", { params: { query: { ...scope, ...window } } })),
  });

  const points = trend.data?.items ?? [];
  // From where scanning began: a leading empty step is the absence of us.
  const flows = settled(points);
  const asked = new URLSearchParams({
    ...scope,
    ...(daily ? { days: String(days) } : { weeks: String(weeks) }),
  }).toString();
  const file = (format: "csv" | "json") => fileAt("/v1/trend.{format}", format, { query: asked });

  return (
    <Sheet
      settled={!figures || trend.isSuccess}
      name="Backlog over time"
      answers="whether the backlog is growing, and what kind of thing is making it grow."
      asked={daily ? `${days} days` : `${weeks} weeks`}
    >
      <div className="controls">
        <StepSegments daily={daily} />
        {daily ? (
          <Segments
            label="Window"
            param="days"
            offered={DAYS}
            chosen={days}
            words={(n) => (n === 730 ? "two years" : n === 365 ? "a year" : `${n} days`)}
          />
        ) : (
          <Segments
            label="Window"
            param="weeks"
            offered={WEEKS}
            chosen={weeks}
            words={(n) => (n === 104 ? "two years" : n === 52 ? "a year" : `${n} weeks`)}
          />
        )}
        {figures && (
          <span style={{ marginLeft: "auto" }} className="noprint">
            <a className="btn quiet" href={file("csv")}>
              CSV
            </a>{" "}
            <a className="btn quiet" href={file("json")}>
              JSON
            </a>
          </span>
        )}
      </div>

      {figures && <HeldLine at={dependencies} />}
      {!figures ? (
        <Empty title="Nothing to list." detail={heldLine(dependencies)} />
      ) : trend.isPending ? (
        <Loading />
      ) : trend.isError ? (
        <Failed error={trend.error} what="The backlog could not be read." />
      ) : points.length === 0 ? (
        <Empty
          title="Nothing has been scanned yet."
          detail="A trend is what changed between scans, so it starts with the second one."
        />
      ) : (
        <>
          <section className="panel">
            <h3>Open, new, returned and corrected</h3>
            <Pace points={points} unit={daily ? "days" : "weeks"} />
            <PaceLegend />
            <p className="hint">
              Counted once per issue in each package, not per occurrence. An issue that comes back
              is returned, and stops counting as corrected; one back after an upload lost most of a
              build is marked instead.
            </p>
          </section>

          <section className="panel">
            <h3>Open by severity</h3>
            <Mix points={points} />
            <p className="hint">The share matters as much as the total.</p>
          </section>

          <section className="panel">
            <h3>Arrivals and departures</h3>
            <p className="hint" style={{ marginTop: 0 }}>
              Both flows, split the same way.
            </p>
            {flows.length === 0 ? (
              <Empty
                title="Nothing moved."
                detail="Nothing arrived or was corrected in the window."
              />
            ) : (
              <Wide>
                <table>
                  <thead>
                    <tr>
                      <th>{daily ? "Day" : "Week ending"}</th>
                      <th>New</th>
                      {BANDS.map((band) => (
                        <th key={`in ${band}`}>{band}</th>
                      ))}
                      <th>Returned</th>
                      <th title="Back after an upload lost most of the build">After a gap</th>
                      <th>Corrected</th>
                      {BANDS.map((band) => (
                        <th key={`out ${band}`}>{band}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {flows.map((point) => {
                      const arrived = folded(point.new_by_severity ?? {});
                      const answered = folded(point.corrected_by_severity ?? {});
                      return (
                        <tr key={point.at}>
                          <td className="id">{point.at}</td>
                          <td>{(point.new ?? 0).toLocaleString()}</td>
                          {BANDS.map((band) => (
                            <td key={`in ${band}`} className="hint">
                              {(arrived[band] ?? 0).toLocaleString()}
                            </td>
                          ))}
                          <td>{(point.returned ?? 0).toLocaleString()}</td>
                          <td>{(point.restored ?? 0).toLocaleString()}</td>
                          <td>{(point.corrected ?? 0).toLocaleString()}</td>
                          {BANDS.map((band) => (
                            <td key={`out ${band}`} className="hint">
                              {(answered[band] ?? 0).toLocaleString()}
                            </td>
                          ))}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </Wide>
            )}
          </section>
        </>
      )}
    </Sheet>
  );
}
