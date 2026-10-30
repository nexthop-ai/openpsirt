// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom";
import { useCodeFindingFixing, useCodeFindingJudging } from "../../api/codeFindings";
import { codeFindingsAt } from "../../app/routes";
import { Empty } from "../../ui/Empty";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { Wide } from "../../ui/Wide";
import { TIERS } from "../codeTrend";
import { Sheet } from "./Sheet";
import { Segments, boundedAsked } from "./Window";
import {
  Files,
  Gate,
  WEEKS,
  WaitsTable,
  queryOf,
  useFigureAsked,
  weeksWords,
} from "./securityTesting";

// How long a code finding waits for a person: from opening to the first
// decision proposed about it, whatever it decided, and the queue waiting now
// by age. A code finding no longer detected waits in no queue and is counted
// apart.
export function TimeToJudge() {
  const { product, asked, code, reads, needsBuild, of, params } = useFigureAsked();
  const weeks = boundedAsked(params.get("weeks"), 104, 13);
  const judged = useCodeFindingJudging(
    product,
    { ...asked, weeks },
    !!product && reads && !needsBuild,
  );
  return (
    <Sheet
      settled={!product || !reads || needsBuild || judged.isSuccess}
      name="Time to judge"
      answers="how long a new code finding waits for a person."
      of={of}
      asked={weeksWords(weeks)}
    >
      <div className="controls">
        <Segments label="Window" param="weeks" offered={WEEKS} chosen={weeks} words={weeksWords} />
        {product && reads && !needsBuild && (
          <Files
            path="/v1/products/{product}/code-finding-time-to-judge.{format}"
            product={product}
            query={queryOf({ ...asked, weeks })}
          />
        )}
      </div>
      <Gate product={product} code={code} needsBuild={needsBuild}>
        {judged.isPending ? (
          <Loading />
        ) : judged.isError ? (
          <Failed error={judged.error} what="The time to judge could not be read." />
        ) : (
          <>
            <section className="panel">
              <h3>From opening to the first decision</h3>
              <WaitsTable
                waits={judged.data.judged}
                none="Nobody judged a code finding first in these weeks."
              />
              <p className="hint">
                The first decision proposed, whatever it said. The tier is the rule&rsquo;s
                weaknesses, rated now.
              </p>
            </section>
            <section className="panel">
              <h3>Waiting now</h3>
              {(judged.data.waiting ?? []).every((aged) => aged.waiting === 0) ? (
                <Empty title="Nothing is waiting for a person." />
              ) : (
                <Wide>
                  <table>
                    <thead>
                      <tr>
                        <th>Open for</th>
                        <th className="num">Waiting</th>
                        {Object.entries(TIERS).map(([key, label]) => (
                          <th key={key} className="num">
                            {label}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {(judged.data.waiting ?? []).map((aged) => (
                        <tr key={aged.label}>
                          <td>{aged.label}</td>
                          <td className="num">{aged.waiting.toLocaleString()}</td>
                          {Object.keys(TIERS).map((key) => (
                            <td key={key} className="num hint">
                              {(aged.by_tier?.[key] ?? 0).toLocaleString()}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </Wide>
              )}
              <p className="hint">
                {judged.data.oldest && <>Oldest opened {judged.data.oldest}. </>}
                <Link to={codeFindingsAt(product, { ...asked })}>Open the queue</Link>
              </p>
              <p className="hint">
                {judged.data.no_longer_detected === 0 ? (
                  "None is no longer detected now."
                ) : (
                  <>
                    <Link to={codeFindingsAt(product, { ...asked, state: "no-longer-detected" })}>
                      {judged.data.no_longer_detected.toLocaleString()} no longer detected
                    </Link>{" "}
                    now: a run stopped seeing them, so they wait in no queue.
                  </>
                )}
              </p>
            </section>
          </>
        )}
      </Gate>
    </Sheet>
  );
}

// How long until a code finding is fixed: from opening to a person closing it
// as fixed. Dismissals are left out, and what is no longer detected is timed
// apart, because absence is no proof of a fix.
export function TimeToFix() {
  const { product, asked, code, reads, needsBuild, of, params } = useFigureAsked();
  const weeks = boundedAsked(params.get("weeks"), 104, 13);
  const fixing = useCodeFindingFixing(
    product,
    { ...asked, weeks },
    !!product && reads && !needsBuild,
  );
  return (
    <Sheet
      settled={!product || !reads || needsBuild || fixing.isSuccess}
      name="Time to fix"
      answers="how long until a code finding is fixed."
      of={of}
      asked={weeksWords(weeks)}
    >
      <div className="controls">
        <Segments label="Window" param="weeks" offered={WEEKS} chosen={weeks} words={weeksWords} />
        {product && reads && !needsBuild && (
          <Files
            path="/v1/products/{product}/code-finding-time-to-fix.{format}"
            product={product}
            query={queryOf({ ...asked, weeks })}
          />
        )}
      </div>
      <Gate product={product} code={code} needsBuild={needsBuild}>
        {fixing.isPending ? (
          <Loading />
        ) : fixing.isError ? (
          <Failed error={fixing.error} what="The time to fix could not be read." />
        ) : (
          <>
            <section className="panel">
              <h3>From opening to fixed</h3>
              <WaitsTable waits={fixing.data.fixed} none="Nothing was fixed in these weeks." />
              <p className="hint">
                Fixed when a person closed it as fixed on every build here.{" "}
                {fixing.data.dismissed === 0
                  ? "No dismissed code finding was closed as fixed."
                  : `${fixing.data.dismissed.toLocaleString()} closed as fixed and dismissed ${
                      fixing.data.dismissed === 1 ? "is" : "are"
                    } left out.`}
              </p>
            </section>
            <section className="panel">
              <h3>No longer detected, now</h3>
              <WaitsTable
                waits={fixing.data.no_longer_detected}
                none="None is no longer detected now."
              />
              <p className="hint">
                From opening to the first run that missed it. Missed isn&rsquo;t fixed.{" "}
                {fixing.data.no_longer_detected.all.count > 0 && (
                  <Link to={codeFindingsAt(product, { ...asked, state: "no-longer-detected" })}>
                    Open them
                  </Link>
                )}
              </p>
            </section>
          </>
        )}
      </Gate>
    </Sheet>
  );
}
