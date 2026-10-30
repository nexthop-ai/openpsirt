// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom";
import { useCodeFindingPrecision, type CodeFindingAnswered } from "../../api/codeFindings";
import { codeFindingsAt } from "../../app/routes";
import { Empty } from "../../ui/Empty";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { Wide } from "../../ui/Wide";
import { Sheet } from "./Sheet";
import { Files, Gate, queryOf, useFigureAsked } from "./securityTesting";

// Which analyzers and rules are noise: of the code findings somebody judged,
// how many were answered as noise, per series and per analyzer rule, and the
// suppression rules with what each covers.

// The rules shown before the rest are asked for.
const RULES_SHOWN = 25;

function share(each: CodeFindingAnswered): string {
  return each.noise_share === undefined ? "—" : `${Math.round(each.noise_share * 100)}%`;
}

// The parts of a row, in the order a code finding meets them.
function AnsweredCells({ each }: { each: CodeFindingAnswered }) {
  return (
    <>
      <td className="num">{each.judged.toLocaleString()}</td>
      <td className="num">{share(each)}</td>
      <td className="num hint">{each.dismissed.toLocaleString()}</td>
      <td className="num hint">{each.not_security.toLocaleString()}</td>
      <td className="num hint">{each.ruled.toLocaleString()}</td>
      <td className="num hint">{each.confirmed.toLocaleString()}</td>
      <td className="num hint">{each.fixed.toLocaleString()}</td>
      <td className="num hint">{each.unjudged.toLocaleString()}</td>
    </>
  );
}

const HEADS = [
  ["Judged", "Answered by a person or a suppression rule"],
  ["Noise", "Dismissed, not a security issue, or covered by a rule, of those judged"],
  ["Dismissed", "A standing decision dismisses it"],
  ["Not security", "A standing decision says it isn't a security issue"],
  ["By rule", "A suppression rule dismisses it, no decision standing"],
  ["Confirmed", "Confirmed, or recorded as a flaw"],
  ["Fixed", "Closed as fixed, no decision standing"],
  ["Unjudged", "Nothing answers it yet"],
] as const;

export function AnalyzerPrecision() {
  const { product, asked, code, reads, needsBuild, of } = useFigureAsked();
  const precision = useCodeFindingPrecision(product, asked, !!product && reads && !needsBuild);
  return (
    <Sheet
      settled={!product || !reads || needsBuild || precision.isSuccess}
      name="Analyzer precision"
      answers="which analyzers and rules are noise."
      of={of}
      asked="now"
    >
      <div className="controls">
        {product && reads && !needsBuild && (
          <Files
            path="/v1/products/{product}/code-finding-precision.{format}"
            product={product}
            query={queryOf(asked)}
          />
        )}
      </div>
      <Gate product={product} code={code} needsBuild={needsBuild}>
        {precision.isPending ? (
          <Loading />
        ) : precision.isError ? (
          <Failed error={precision.error} what="The analyzer precision could not be read." />
        ) : (
          <>
            <section className="panel">
              <h3>By series</h3>
              {(precision.data.by_series ?? []).length === 0 ? (
                <Empty title="No code finding here." />
              ) : (
                <Wide>
                  <table>
                    <thead>
                      <tr>
                        <th>Series</th>
                        {HEADS.map(([head, hint]) => (
                          <th key={head} className="num" title={hint}>
                            {head}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {(precision.data.by_series ?? []).map((each) => (
                        <tr key={each.series}>
                          <td>
                            <Link to={codeFindingsAt(product, { ...asked, series: each.series })}>
                              {each.series}
                            </Link>
                          </td>
                          <AnsweredCells each={each} />
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </Wide>
              )}
              <p className="hint">
                Each code finding counts once, at the first that holds: a decision, a flaw record, a
                fix, a suppression rule.
              </p>
            </section>
            <section className="panel">
              <h3>Noisiest rules</h3>
              {(precision.data.by_rule ?? []).length === 0 ? (
                <Empty title="No rule has a code finding judged." />
              ) : (
                <Wide>
                  <table>
                    <thead>
                      <tr>
                        <th>Rule</th>
                        <th>Series</th>
                        {HEADS.map(([head, hint]) => (
                          <th key={head} className="num" title={hint}>
                            {head}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {(precision.data.by_rule ?? []).slice(0, RULES_SHOWN).map((each) => (
                        <tr key={`${each.series} ${each.rule}`}>
                          <td className="id">{each.rule}</td>
                          <td className="hint">{each.series}</td>
                          <AnsweredCells each={each} />
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </Wide>
              )}
              {(precision.data.by_rule ?? []).length > RULES_SHOWN && (
                <p className="hint">
                  The {RULES_SHOWN} noisiest of{" "}
                  {(precision.data.by_rule ?? []).length.toLocaleString()} rules judged. The file
                  holds them all.
                </p>
              )}
            </section>
            <section className="panel">
              <h3>Suppression rules</h3>
              {(precision.data.suppression_rules ?? []).length === 0 ? (
                <Empty title="No suppression rule in this product." />
              ) : (
                <Wide>
                  <table>
                    <thead>
                      <tr>
                        <th>Names</th>
                        <th>State</th>
                        <th>Approved</th>
                        <th>Retired</th>
                        <th className="num" title="Open code findings it names now">
                          Covers
                        </th>
                        <th className="num" title="What it covered when approved">
                          At approval
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {(precision.data.suppression_rules ?? []).map((rule) => (
                        <tr key={rule.id}>
                          <td className="id">
                            {[rule.rule, rule.path && `under ${rule.path}`]
                              .filter(Boolean)
                              .join(" ")}
                          </td>
                          <td>{rule.state}</td>
                          <td className="hint">{rule.approved_at?.slice(0, 10) ?? "—"}</td>
                          <td className="hint">{rule.retired_at?.slice(0, 10) ?? "—"}</td>
                          <td className="num">{rule.covering.toLocaleString()}</td>
                          <td className="num hint">
                            {rule.approved_covering === undefined
                              ? "—"
                              : rule.approved_covering.toLocaleString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </Wide>
              )}
              <p className="hint">
                Every branch and variant of the product. What a rule covers is worked out from
                today&rsquo;s paths.
              </p>
            </section>
          </>
        )}
      </Gate>
    </Sheet>
  );
}
