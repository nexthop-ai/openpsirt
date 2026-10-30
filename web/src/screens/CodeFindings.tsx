// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useWho } from "../app/session";
import { counted, heldLine, holding } from "../app/families";
import { fileAt } from "../api/links";
import { codeTrendAt } from "./codeTrend";
import {
  PAGE,
  codeFindingsQuery,
  useCodeFindings,
  type CodeFindingMethod,
  type CodeFindingState,
} from "../api/codeFindings";
import {
  codeFindingAt,
  componentAt,
  suppressionRulesAt,
  codeFindingsAt,
  codeFindingsAcrossAt,
  productAt,
} from "../app/routes";
import { askForScope } from "../app/scope";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Paged } from "../ui/Paged";
import { useRowOpener } from "../ui/opens";
import { Wide } from "../ui/Wide";
import { on } from "../ui/when";
import {
  CODE_FINDING_METHODS,
  CODE_FINDING_STATES,
  CODE_FINDING_TONES,
  ON_BUILD_HINT,
  located,
  placedOn,
  stateSaid,
} from "./codeFindings";

// A product's static analysis code findings. With no state it is the queue: open
// code findings nothing waits on. A state lists that state's code findings instead.
//
// With no product in the address it is the same queue over every product the
// reader reads security testing material in, each row naming its product.
export function CodeFindings() {
  const { product = "" } = useParams();
  const across = product === "";
  const [params, setParams] = useSearchParams();
  const asked = params.get("state") ?? "";
  const state = Object.hasOwn(CODE_FINDING_STATES, asked) ? (asked as CodeFindingState) : undefined;
  const branchOrTag = params.get("branch_or_tag") ?? undefined;
  const variant = params.get("variant") ?? undefined;
  const series = params.get("series") ?? undefined;
  const askedMethod = params.get("method") ?? "";
  const method = Object.hasOwn(CODE_FINDING_METHODS, askedMethod)
    ? (askedMethod as CodeFindingMethod)
    : undefined;
  const assigned = params.get("assigned") === "nobody" ? "nobody" : undefined;
  // A source package, or everything under one component of one build: the
  // component screen's and the tree's counts open the queue narrowed so, and
  // every count here follows.
  const placed = {
    component: params.get("component") ?? undefined,
    component_version: params.get("component_version") ?? undefined,
    beneath: params.get("beneath") ?? undefined,
    beneath_version: params.get("beneath_version") ?? undefined,
    beneath_ecosystem: params.get("beneath_ecosystem") ?? undefined,
    beneath_namespace: params.get("beneath_namespace") ?? undefined,
  };
  const [offset, setOffset] = useState(0);
  // Code findings, asked and drawn only where the reader reads them in the
  // product: a queue of zeros reads as an analyzer finding nothing.
  const code = holding(useWho().data, "code", product || undefined);
  const reads = counted(code);
  // At or under a component names one build, so across products it is said
  // to need one and nothing is asked.
  const needsBuild = across && !!placed.beneath;
  const listed = useCodeFindings(
    product,
    {
      state,
      branch_or_tag: branchOrTag,
      variant,
      series,
      method,
      assigned,
      ...placed,
      offset,
    },
    reads && !needsBuild,
  );
  const opener = useRowOpener();

  const go = (next?: CodeFindingState, unheld = assigned, by = method) => {
    setOffset(0);
    setParams(
      Object.fromEntries(
        Object.entries({
          state: next,
          branch_or_tag: branchOrTag,
          variant,
          series,
          method: by,
          assigned: unheld,
          ...placed,
        }).filter(([, value]) => value !== undefined),
      ) as Record<string, string>,
      { replace: true },
    );
  };

  // The list on screen as a file: the same narrowing, every row of it.
  const file = (format: "csv" | "json") =>
    across
      ? fileAt("/v1/code-findings.{format}", format, {
          query: codeFindingsQuery({
            state,
            series,
            method,
            assigned,
            component: placed.component,
            component_version: placed.component_version,
          }),
        })
      : fileAt("/v1/products/{product}/code-findings.{format}", format, {
          path: { product },
          query: codeFindingsQuery({
            state,
            branch_or_tag: branchOrTag,
            variant,
            series,
            method,
            assigned,
            ...placed,
          }),
        });
  // Where the code findings are: one product, or every product read.
  const where = across ? (
    "Code findings in every product you read"
  ) : (
    <>
      Code findings in <Link to={productAt(product)}>{product}</Link>
    </>
  );
  const counts = listed.data?.states ?? {};
  const rows = listed.data?.items ?? [];

  if (!reads) {
    return (
      <div>
        <div className="screen-head">
          <h2>Security testing</h2>
          <p>{where}</p>
        </div>
        <Empty title="Nothing to list." detail={heldLine(code)} />
      </div>
    );
  }

  if (needsBuild) {
    return (
      <div>
        <div className="screen-head">
          <h2>Security testing</h2>
          <p>
            {where}
            {" · at or under "}
            <span className="id">{placed.beneath}</span>
          </p>
        </div>
        <Empty
          title="This needs one build."
          detail="At or under a component is read on one build. Pick a product, a branch and a variant."
        >
          <button type="button" className="btn" onClick={askForScope}>
            Pick a build
          </button>
        </Empty>
      </div>
    );
  }

  return (
    <div>
      <div className="screen-head">
        <h2>Security testing</h2>
        <p>
          {where}
          {branchOrTag && ` · ${branchOrTag}`}
          {variant && ` · ${variant}`}
          {series && ` · ${series}`}
          {method && ` · ${CODE_FINDING_METHODS[method].label}`}
          {assigned && " · unassigned"}
          {placed.component && (
            <>
              {" · on "}
              <span className="id">{placed.component}</span>
              {placed.component_version && ` ${placed.component_version}`}
            </>
          )}
          {placed.beneath && (
            <>
              {" · at or under "}
              <span className="id">{placed.beneath}</span>
              {placed.beneath_version && ` ${placed.beneath_version}`}
            </>
          )}
        </p>
        <span style={{ marginLeft: "auto" }}>
          {/* A suppression rule and a trend belong to one product. */}
          {!across && (
            <>
              <Link
                className="btn quiet"
                to={codeTrendAt({ branch_or_tag: branchOrTag, variant, series, method, ...placed })}
              >
                Over time
              </Link>{" "}
              <Link className="btn quiet" to={suppressionRulesAt(product)}>
                Suppression rules
              </Link>{" "}
            </>
          )}
          <a className="btn quiet" href={file("csv")}>
            CSV
          </a>{" "}
          <a className="btn quiet" href={file("json")}>
            JSON
          </a>
        </span>
      </div>
      <div className="tabs2">
        <button type="button" className="tab2" aria-selected={!state} onClick={() => go()}>
          Queue
        </button>
        {(Object.keys(CODE_FINDING_STATES) as CodeFindingState[]).map((each) => (
          <button
            key={each}
            type="button"
            className="tab2"
            aria-selected={state === each}
            onClick={() => go(each)}
          >
            {CODE_FINDING_STATES[each]}{" "}
            <span className="n">{(counts[each] ?? 0).toLocaleString()}</span>
          </button>
        ))}
      </div>
      <select
        value={method ?? ""}
        onChange={(e) =>
          go(state, assigned, (e.target.value || undefined) as CodeFindingMethod | undefined)
        }
        aria-label="Method"
        title="How the code findings were found"
      >
        <option value="">Any method</option>
        {(Object.keys(CODE_FINDING_METHODS) as CodeFindingMethod[]).map((each) => (
          <option key={each} value={each} title={CODE_FINDING_METHODS[each].hint}>
            {CODE_FINDING_METHODS[each].label}
          </option>
        ))}
      </select>{" "}
      <label className="hint">
        <input
          type="checkbox"
          checked={!!assigned}
          onChange={(e) => go(state, e.target.checked ? "nobody" : undefined)}
        />{" "}
        Unassigned only
      </label>
      {!state &&
        listed.data &&
        (listed.data.waiting > 0 || listed.data.ruled > 0 || listed.data.past_end_of_life > 0) && (
          <p className="hint">
            {[
              listed.data.waiting > 0 && (
                <span key="waiting">
                  {listed.data.waiting.toLocaleString()} waiting for approval
                </span>
              ),
              listed.data.ruled > 0 && (
                <Link
                  key="ruled"
                  to={
                    across
                      ? codeFindingsAcrossAt({
                          state: "dismissed",
                          series,
                          method,
                          assigned,
                          component: placed.component,
                          component_version: placed.component_version,
                        })
                      : codeFindingsAt(product, {
                          state: "dismissed",
                          branch_or_tag: branchOrTag,
                          variant,
                          series,
                          method,
                          assigned,
                          ...placed,
                        })
                  }
                >
                  {listed.data.ruled.toLocaleString()} dismissed by a rule
                </Link>
              ),
              listed.data.past_end_of_life > 0 && (
                <span key="ended" title="Open only in releases past their end of life">
                  {listed.data.past_end_of_life.toLocaleString()} open only past end of life
                </span>
              ),
            ]
              .filter(Boolean)
              .flatMap((each, i) => (i === 0 ? [each] : [" · ", each]))}
          </p>
        )}
      {listed.isPending ? (
        <Loading />
      ) : listed.isError ? (
        <Failed error={listed.error} what="The code findings could not be read." />
      ) : rows.length === 0 ? (
        <Empty
          title={
            state ? `No ${stateSaid(state).toLowerCase()} code findings.` : "Nothing in the queue."
          }
        />
      ) : (
        <>
          <Wide>
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  {across && <th>Product</th>}
                  <th>Location</th>
                  <th>Component</th>
                  <th>Message</th>
                  <th>Build</th>
                  <th>Opened</th>
                  <th>State</th>
                  <th>Assigned to</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  // Across products each row's own product, which the queue
                  // names; in one product, that product.
                  const of = across ? row.product : product;
                  const to = codeFindingAt(
                    { product: of, branch_or_tag: row.branch_or_tag, variant: row.variant },
                    row.occurrence,
                  );
                  return (
                    <tr
                      key={`${of}/${row.occurrence}/${row.branch_or_tag}/${row.variant}`}
                      className="row opens"
                      onClick={opener(to)}
                    >
                      <td style={{ whiteSpace: "nowrap" }}>
                        <Link className="id" to={to}>
                          {row.rule}
                        </Link>
                      </td>
                      {across && (
                        <td className="hint" style={{ whiteSpace: "nowrap" }}>
                          <Link to={productAt(of)}>{row.product_name || of}</Link>
                        </td>
                      )}
                      <td className="mono" title={row.function}>
                        {located(row.path, row.line)}
                      </td>
                      <td className="mono">
                        {placedOn(row).component ? (
                          <Link
                            to={componentAt(of, row.component, undefined, {
                              branch_or_tag: row.branch_or_tag,
                              variant: row.variant,
                            })}
                          >
                            {placedOn(row).label}
                          </Link>
                        ) : (
                          <span className="hint" title={ON_BUILD_HINT}>
                            {placedOn(row).label}
                          </span>
                        )}
                      </td>
                      <td>{row.message}</td>
                      <td className="hint" style={{ whiteSpace: "nowrap" }}>
                        {row.branch_or_tag} · {row.variant}
                        {row.builds > 1 && ` +${row.builds - 1}`}
                      </td>
                      <td className="hint" style={{ whiteSpace: "nowrap" }}>
                        {on(row.opened)}
                      </td>
                      <td>
                        <span className={`state ${CODE_FINDING_TONES[row.state]}`}>
                          {stateSaid(row.state)}
                        </span>
                        {row.third_party && (
                          <span
                            className="state closed"
                            title="The analysis run declared this path third-party"
                          >
                            {" "}
                            Third-party
                          </span>
                        )}
                      </td>
                      <td className="hint" style={{ whiteSpace: "nowrap" }}>
                        {row.assigned_to && (row.assigned_to_name ?? row.assigned_to)}
                        {row.assigned_team && " · team"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </Wide>
          <Paged
            shown={rows.length}
            total={listed.data?.total}
            offset={offset}
            limit={PAGE}
            onGo={setOffset}
          />
        </>
      )}
    </div>
  );
}
