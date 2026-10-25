// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { mayOf, useWho } from "../app/session";
import {
  useApproveLeadRule,
  useImportantPaths,
  useLeadRules,
  useProposeLeadRule,
  useRetireLeadRule,
  useSetImportantPaths,
  type LeadReason,
  type LeadRule,
} from "../api/leads";
import { leadsAt } from "../app/routes";
import { Editor } from "../ui/Editor";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { notACredential } from "../ui/noautofill";
import { Wide } from "../ui/Wide";
import { on } from "../ui/when";
import { LEAD_REASONS, RULE_STATE_HINTS, reasonSaid, ruleStateSaid } from "./leads";

// The rules deciding which leads reach a product's queue: standing dismissals
// of an analyzer's rule, a path, or both, and the paths whose leads are pulled
// out of the baseline.
export function LeadRules() {
  const { product = "" } = useParams();
  const may = mayOf(useWho().data, product);
  const triages = !!may?.triages_internal;
  const agrees = !!may?.agrees_internal;

  return (
    <div>
      <div className="screen-head">
        <h2>Dismissal rules</h2>
        <p>
          Leads in <Link to={leadsAt(product)}>{product}</Link>
        </p>
      </div>
      <Rules product={product} triages={triages} agrees={agrees} />
      {triages && <ProposeForm product={product} />}
      <ImportantPaths product={product} triages={triages} />
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
  const rules = useLeadRules(product);
  const approve = useApproveLeadRule(product);
  const retire = useRetireLeadRule(product);

  if (rules.isPending) return <Loading />;
  if (rules.isError) return <Failed error={rules.error} what="The rules could not be read." />;
  if (rules.data.length === 0) return <Empty title="No dismissal rules." />;
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
function tone(rule: LeadRule): string {
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
  const [reason, setReason] = useState<LeadReason | "">("");
  const [reasoning, setReasoning] = useState("");
  const propose = useProposeLeadRule(product);
  const ready =
    (rule.trim() !== "" || prefix.trim() !== "") && reason !== "" && reasoning.trim() !== "";

  return (
    <div className="card">
      <h3>New rule</h3>
      <div className="field">
        <label htmlFor="lead-rule-rule">Analyzer rule</label>
        <input
          {...notACredential}
          id="lead-rule-rule"
          type="text"
          value={rule}
          placeholder="cppcheck/knownConditionTrueFalse"
          onChange={(event) => setRule(event.target.value)}
        />
      </div>
      <div className="field">
        <label htmlFor="lead-rule-path">Path</label>
        <input
          {...notACredential}
          id="lead-rule-path"
          type="text"
          value={prefix}
          placeholder="third_party"
          onChange={(event) => setPrefix(event.target.value)}
        />
        <span className="hint">From the top of the checkout. Covers everything under it</span>
      </div>
      <div className="field">
        <label htmlFor="lead-rule-reason">Reason</label>
        <select
          id="lead-rule-reason"
          value={reason}
          onChange={(event) => setReason(event.target.value as LeadReason)}
        >
          <option value="">Choose…</option>
          {(Object.keys(LEAD_REASONS) as LeadReason[]).map((each) => (
            <option key={each} value={each}>
              {LEAD_REASONS[each]}
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
          draftKey={`lead-rule:${product}`}
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

// The paths whose leads are taken out of the baseline, one to a line.
function ImportantPaths({ product, triages }: { product: string; triages: boolean }) {
  const paths = useImportantPaths(product);
  const set = useSetImportantPaths(product);
  const [typed, setTyped] = useState<string | undefined>(undefined);

  if (paths.isPending) return <Loading />;
  if (paths.isError)
    return <Failed error={paths.error} what="The important paths could not be read." />;
  const shown = typed ?? paths.data.join("\n");
  const asked = shown
    .split("\n")
    .map((each) => each.trim())
    .filter((each) => each !== "");

  return (
    <div className="card">
      <h3 title="Leads under these paths are in the queue from the first run.">Important paths</h3>
      {triages ? (
        <>
          <textarea
            {...notACredential}
            aria-label="Important paths"
            rows={Math.max(3, asked.length + 1)}
            value={shown}
            placeholder="src/net/"
            onChange={(event) => setTyped(event.target.value)}
          />
          <button
            type="button"
            className="btn"
            style={{ marginTop: 8 }}
            disabled={typed === undefined || set.isPending}
            onClick={() => set.mutate(asked, { onSuccess: () => setTyped(undefined) })}
          >
            Save
          </button>
          {set.error != null && <Failed error={set.error} what="The paths were not saved." />}
        </>
      ) : paths.data.length === 0 ? (
        <p className="hint">None.</p>
      ) : (
        <ul>
          {paths.data.map((each) => (
            <li key={each} className="mono">
              {each}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
