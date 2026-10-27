// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { mayOf, useWho } from "../app/session";
import {
  useApproveSuppressionRule,
  useSuppressionRules,
  useProposeSuppressionRule,
  useRetireSuppressionRule,
  type CodeFindingReason,
  type SuppressionRule,
} from "../api/codeFindings";
import { codeFindingsAt } from "../app/routes";
import { Editor } from "../ui/Editor";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { notACredential } from "../ui/noautofill";
import { Wide } from "../ui/Wide";
import { on } from "../ui/when";
import { CODE_FINDING_REASONS, RULE_STATE_HINTS, reasonSaid, ruleStateSaid } from "./codeFindings";

// The rules deciding which code findings leave a product's queue: standing dismissals
// of an analyzer's rule, a path, or both.
export function SuppressionRules() {
  const { product = "" } = useParams();
  const may = mayOf(useWho().data, product);
  const triages = !!may?.triages_internal;
  const agrees = !!may?.agrees_internal;

  return (
    <div>
      <div className="screen-head">
        <h2>Suppression rules</h2>
        <p>
          Code findings in <Link to={codeFindingsAt(product)}>{product}</Link>
        </p>
      </div>
      <Rules product={product} triages={triages} agrees={agrees} />
      {triages && <ProposeForm product={product} />}
    </div>
  );
}

function Rules({
  product,
  triages,
  agrees,
}: {
  product: string;
  triages: boolean;
  agrees: boolean;
}) {
  const rules = useSuppressionRules(product);
  const approve = useApproveSuppressionRule(product);
  const retire = useRetireSuppressionRule(product);

  if (rules.isPending) return <Loading />;
  if (rules.isError) return <Failed error={rules.error} what="The rules could not be read." />;
  if (rules.data.length === 0) return <Empty title="No suppression rules." />;
  return (
    <div className="card">
      <Wide>
        <table>
          <thead>
            <tr>
              <th>Rule</th>
              <th>Path</th>
              <th>Reason</th>
              <th>Covers</th>
              <th>Proposed</th>
              <th>State</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rules.data.map((rule) => (
              <tr key={rule.id}>
                <td className="mono">{rule.rule ?? <span className="hint">any</span>}</td>
                <td className="mono">{rule.prefix ?? <span className="hint">anywhere</span>}</td>
                <td title={rule.reasoning}>{reasonSaid(rule.reason)}</td>
                <td>
                  {rule.covering.toLocaleString()}
                  {rule.approved_covering !== undefined && (
                    <span className="hint">
                      {" "}
                      · {rule.approved_covering.toLocaleString()} when approved
                    </span>
                  )}
                </td>
                <td className="hint">{on(rule.proposed_at)}</td>
                <td>
                  <span className={`state ${tone(rule)}`} title={RULE_STATE_HINTS[rule.state]}>
                    {ruleStateSaid(rule.state)}
                  </span>
                </td>
                <td style={{ whiteSpace: "nowrap" }}>
                  {agrees &&
                    !rule.yours &&
                    (rule.state === "proposed" || rule.state === "outgrown") && (
                      <button
                        type="button"
                        className="btn quiet"
                        disabled={approve.isPending}
                        onClick={() => approve.mutate(rule.id)}
                      >
                        Approve
                      </button>
                    )}
                  {triages && rule.state !== "retired" && (
                    <button
                      type="button"
                      className="btn quiet"
                      disabled={retire.isPending}
                      onClick={() => retire.mutate(rule.id)}
                    >
                      Retire
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Wide>
      {approve.error != null && <Failed error={approve.error} what="The rule was not approved." />}
      {retire.error != null && <Failed error={retire.error} what="The rule was not retired." />}
    </div>
  );
}

// The chip a rule's state is drawn as.
function tone(rule: SuppressionRule): string {
  switch (rule.state) {
    case "in-force":
      return "agreed";
    case "proposed":
      return "waiting";
    case "retired":
      return "closed";
    default:
      return "warn";
  }
}

function ProposeForm({ product }: { product: string }) {
  const [rule, setRule] = useState("");
  const [prefix, setPrefix] = useState("");
  const [reason, setReason] = useState<CodeFindingReason | "">("");
  const [reasoning, setReasoning] = useState("");
  const propose = useProposeSuppressionRule(product);
  const ready =
    (rule.trim() !== "" || prefix.trim() !== "") && reason !== "" && reasoning.trim() !== "";

  return (
    <div className="card">
      <h3>New rule</h3>
      <div className="field">
        <label htmlFor="suppression-rule-rule">Analyzer rule</label>
        <input
          {...notACredential}
          id="suppression-rule-rule"
          type="text"
          value={rule}
          placeholder="cppcheck/knownConditionTrueFalse"
          onChange={(event) => setRule(event.target.value)}
        />
      </div>
      <div className="field">
        <label htmlFor="suppression-rule-path">Path</label>
        <input
          {...notACredential}
          id="suppression-rule-path"
          type="text"
          value={prefix}
          placeholder="third_party"
          onChange={(event) => setPrefix(event.target.value)}
        />
        <span className="hint">From the top of the checkout. Covers everything under it</span>
      </div>
      <div className="field">
        <label htmlFor="suppression-rule-reason">Reason</label>
        <select
          id="suppression-rule-reason"
          value={reason}
          onChange={(event) => setReason(event.target.value as CodeFindingReason)}
        >
          <option value="">Choose…</option>
          {(Object.keys(CODE_FINDING_REASONS) as CodeFindingReason[]).map((each) => (
            <option key={each} value={each}>
              {CODE_FINDING_REASONS[each]}
            </option>
          ))}
        </select>
      </div>
      <div className="field">
        <Editor
          label="Reasoning"
          value={reasoning}
          onChange={setReasoning}
          rows={3}
          draftKey={`suppression-rule:${product}`}
        />
      </div>
      <button
        type="button"
        className="btn"
        disabled={!ready || propose.isPending}
        onClick={() =>
          reason &&
          propose.mutate(
            {
              reason,
              reasoning: reasoning.trim(),
              ...(rule.trim() ? { rule: rule.trim() } : {}),
              ...(prefix.trim() ? { prefix: prefix.trim() } : {}),
            },
            {
              onSuccess: () => {
                setRule("");
                setPrefix("");
                setReason("");
                setReasoning("");
              },
            },
          )
        }
      >
        Propose
      </button>
      {propose.error != null && <Failed error={propose.error} what="The rule was not proposed." />}
    </div>
  );
}
