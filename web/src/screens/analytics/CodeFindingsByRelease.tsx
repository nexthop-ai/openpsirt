// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom";
import { useCodeFindingsByRelease } from "../../api/codeFindings";
import { codeFindingsAt } from "../../app/routes";
import { Releases } from "../../ui/Charts";
import { Empty } from "../../ui/Empty";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { Wide } from "../../ui/Wide";
import { TIERS } from "../codeTrend";
import { Sheet } from "./Sheet";
import { Files, Gate, queryOf, useFigureAsked } from "./securityTesting";

// Whether a release shipped fewer code findings than the one before: what is
// not fixed on each tagged release now, release over release. A release is a
// frozen point, so these are bars in the order they went out, never a line.
export function CodeFindingsByRelease() {
  // Every tag is read, so the heading names no branch.
  const { product, asked, code, reads, of } = useFigureAsked({ branchless: true });
  const narrowed = {
    variant: asked.variant,
    series: asked.series,
    method: asked.method,
    component: asked.component,
    component_version: asked.component_version,
  };
  const released = useCodeFindingsByRelease(product, narrowed, !!product && reads);
  const releases = released.data?.releases ?? [];
  return (
    <Sheet
      settled={!product || !reads || released.isSuccess}
      name="Code findings by release"
      answers="whether a release shipped fewer code findings than the one before."
      of={of}
      asked="release over release"
    >
      <div className="controls">
        {product && reads && (
          <Files
            path="/v1/products/{product}/code-findings-by-release.{format}"
            product={product}
            query={queryOf(narrowed)}
          />
        )}
      </div>
      <Gate product={product} code={code}>
        {released.isPending ? (
          <Loading />
        ) : released.isError ? (
          <Failed error={released.error} what="The code findings by release could not be read." />
        ) : releases.length === 0 ? (
          <section className="panel">
            <Empty
              title="No release analyzed."
              detail="No analyzer run was applied to a tag here."
            />
          </section>
        ) : (
          <>
            <section className="panel">
              <h3>Not fixed in each release</h3>
              <Releases
                counts="code findings not fixed"
                each="not fixed"
                points={releases.map((each) => ({
                  branch_or_tag: each.branch_or_tag,
                  branch_or_tag_name: each.branch_or_tag_name,
                  open: each.not_fixed,
                  cut: each.cut,
                }))}
              />
              <p className="hint">Counted now, once per code finding. Only a fix takes one off.</p>
            </section>
            <section className="panel">
              <h3>Release by release</h3>
              <Wide>
                <table>
                  <thead>
                    <tr>
                      <th>Release</th>
                      <th>Went out</th>
                      <th className="num">Not fixed</th>
                      {Object.entries(TIERS).map(([key, label]) => (
                        <th key={key} className="num">
                          {label}
                        </th>
                      ))}
                      <th className="num" title="Nothing answers them">
                        Open
                      </th>
                      <th className="num" title="Dismissed by a decision or a suppression rule">
                        Dismissed
                      </th>
                      <th className="num" title="Decided not a security issue">
                        Not security
                      </th>
                      <th className="num" title="A comparable run didn't see them">
                        No longer detected
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {releases.map((each) => {
                      const on = { branch_or_tag: each.branch_or_tag, ...narrowed };
                      return (
                        <tr key={each.branch_or_tag}>
                          <td>{each.branch_or_tag_name}</td>
                          <td className="hint">{each.cut}</td>
                          <td className="num">{each.not_fixed.toLocaleString()}</td>
                          {Object.keys(TIERS).map((key) => (
                            <td key={key} className="num hint">
                              {(each.by_tier?.[key] ?? 0).toLocaleString()}
                            </td>
                          ))}
                          <td className="num">
                            <Link to={codeFindingsAt(product, { ...on, state: "open" })}>
                              {each.open.toLocaleString()}
                            </Link>
                          </td>
                          <td className="num">
                            <Link to={codeFindingsAt(product, { ...on, state: "dismissed" })}>
                              {each.dismissed.toLocaleString()}
                            </Link>
                          </td>
                          <td className="num">
                            <Link to={codeFindingsAt(product, { ...on, state: "not-security" })}>
                              {each.not_security.toLocaleString()}
                            </Link>
                          </td>
                          <td className="num">
                            <Link
                              to={codeFindingsAt(product, { ...on, state: "no-longer-detected" })}
                            >
                              {each.no_longer_detected.toLocaleString()}
                            </Link>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </Wide>
            </section>
          </>
        )}
      </Gate>
    </Sheet>
  );
}
