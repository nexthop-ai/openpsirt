// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useAfterHandBack } from "../api/intake";
import { useAfterDecision } from "../api/decisions";
import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type Body } from "../api/client";
import { unwrap, whichOf } from "../api/queries";
import { bulkDecisionAt, decisionAt } from "../app/routes";
import { buildKey, fromBuildKey } from "../ui/builds";
import { Editor } from "../ui/Editor";
import { Failed } from "../ui/Failed";
import { Holder, type Held } from "../ui/Holder";
import { notACredential } from "../ui/noautofill";
import { ranked, rankedLabel, rankedWhy, upgradeCount } from "../ui/ranked";
import { Wide } from "../ui/Wide";
import { binaries, findingsAt, promiseLinks } from "./componentLinks";

// Moving one source package to a version that fixes it: the releases carrying
// fixes, and the form that promises the upgrade.
type Build = Body<"PerBuildBody">;
type Package = Body<"FoldPackageBody">;

// The versions offered before the rest are a count. A kernel names
// twenty, and the question is which to take rather than what the whole set is.
export const SHOWN = 5;

// One decision about many issues at this component, which is the answer where
// no version fixes them. Linked from here because this page is where the
// question is asked.
//
// The package's version, ecosystem and namespace travel with the name, because
// a build can hold one name as more than one component.
const bulkDecisionHere = (product: string, row: Build, component: string, pkg?: Package) =>
  bulkDecisionAt(
    { product, branch_or_tag: row.branch_or_tag ?? "", variant: row.variant ?? "" },
    component,
    whichOf({ version: pkg?.version, ecosystem: row.ecosystem, namespace: pkg?.namespace }),
  );

// The releases the fixes landed in: each one the findings name, and what it
// fixed.
//
// Two counts, because they answer different questions. What a release fixed is
// how many name that exact version — its own security content. What reaching it
// closes counts every earlier fix too, which is what somebody choosing between
// two versions asks, and it needs the ecosystem's ordering. Unranked, the two
// are equal and the panel says so.
export function Landed({ here }: { here: Build }) {
  const landed = here.upgrades ?? [];
  const ordered = ranked(landed);
  const total = here.fixable ?? 0;

  return (
    <div className="card" style={{ marginTop: 12 }}>
      <div className="screen-head" style={{ marginBottom: 8 }}>
        <h3>Releases carrying fixes</h3>
        {landed.length > 0 && (
          <span className="eyebrow" style={{ marginLeft: "auto" }}>
            {landed.length} {landed.length === 1 ? "release" : "releases"}
          </span>
        )}
      </div>

      {landed.length === 0 ? (
        <p className="hint">Nothing fixes what is open here.</p>
      ) : (
        <>
          <Wide>
            <table>
              <thead>
                <tr>
                  <th>Release</th>
                  <th className="num" title="The findings open here that release fixes">
                    Fixed here
                  </th>
                  {ordered && (
                    <th
                      className="num"
                      title="Everything moving here closes, counting the earlier fixes too"
                    >
                      Closes
                    </th>
                  )}
                </tr>
              </thead>
              <tbody>
                {landed.map((each) => (
                  <tr key={each.to}>
                    <td className="id">{each.to}</td>
                    <td className="num">{each.fixed_here}</td>
                    {ordered && <td className="num">{each.reached}</td>}
                  </tr>
                ))}
                <tr>
                  <td className="hint">with a fix</td>
                  <td className="num">
                    <b>{total}</b>
                  </td>
                  {ordered && <td />}
                </tr>
              </tbody>
            </table>
          </Wide>
          <p className="hint" style={{ marginTop: 8 }} title={rankedWhy(ordered)}>
            {rankedLabel(ordered)}
          </p>
        </>
      )}
    </div>
  );
}

// Promising an upgrade: the version, the releases it is for, the date, and who
// carries it.
//
// The releases are chosen here, ticked to the ones shipping this version,
// rather than in a column of the table below. The rest of the promise is
// written here, and a control that summons a form from somewhere else is one
// nobody finds.
export function Upgrade({
  product,
  component,
  pkg,
  here,
  covering,
}: {
  product: string;
  component: string;
  pkg: Package;
  here: Build;
  covering: Build[];
}) {
  const queries = useQueryClient();
  const handedOver = useAfterHandBack();
  // A scheduled upgrade is a decision as well as a change of holder.
  const decided = useAfterDecision();
  const landed = here.upgrades ?? [];
  const [to, setTo] = useState(landed[0]?.to ?? "");
  const [by, setBy] = useState("");
  const [because, setBecause] = useState("");
  const [holder, setHolder] = useState<Held | null>(null);
  const [said, setSaid] = useState<string | null>(null);
  // Where the promise just made is followed: its own page while it waits for
  // a second person, and the planned upgrades of the builds it names.
  const [made, setMade] = useState<{
    decisionId: number;
    waiting: boolean;
    builds: { branch_or_tag: string; variant: string }[];
  } | null>(null);
  // Every release shipping this version, because one bump moves all of them.
  const [chosen, setChosen] = useState<Set<string>>(
    () => new Set(covering.map((row) => buildKey(row, row.version))),
  );

  const plan = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/products/{product}/components/{component}/upgrade", {
          params: { path: { product, component } },
          body: {
            to: to.trim(),
            // The source version this entry is, so a release shipping two
            // versions promises the one on screen.
            version: here.version,
            by,
            reasoning: because,
            ...(holder?.kind === "team" ? { team: holder.identity } : {}),
            ...(holder?.kind === "person" ? { person: holder.identity } : {}),
            // The build alone: one bump moves every release shipping the
            // version, and what the server takes is the pair naming each.
            builds: [...chosen].map((each) => {
              const { branch_or_tag: branchOrTag, variant } = fromBuildKey(each);
              return { branch_or_tag: branchOrTag, variant };
            }),
          },
        }),
      ),
    onSuccess: (done) => {
      setSaid(
        `Recorded against ${done.occurrences} ${done.occurrences === 1 ? "occurrence" : "occurrences"}` +
          ` across ${done.issues} ${done.issues === 1 ? "issue" : "issues"}.` +
          (done.waiting
            ? " Past the earliest deadline it covers, so it waits."
            : " In force now.") +
          (done.held ? ` Carried by ${holder?.name ?? "them"}.` : ""),
      );
      setMade({
        decisionId: done.decision_id,
        waiting: done.waiting,
        builds: [...chosen].map((each) => {
          const { branch_or_tag: branchOrTag, variant } = fromBuildKey(each);
          return { branch_or_tag: branchOrTag, variant };
        }),
      });
      setBy("");
      setBecause("");
      setHolder(null);
      void queries.invalidateQueries({ queryKey: ["component"] });
      handedOver();
      decided();
    },
  });

  if (said) {
    return (
      <div className="alert info" style={{ marginTop: 12 }}>
        <strong>Recorded</strong>
        <span>
          {said}{" "}
          {made?.waiting && (
            <>
              <Link to={decisionAt(made.decisionId)} className="linkish">
                Open the decision →
              </Link>{" "}
            </>
          )}
          {promiseLinks(product, made?.builds ?? []).map((link) => (
            <span key={link.to}>
              <Link to={link.to} className="linkish">
                {link.label}
              </Link>{" "}
            </span>
          ))}
        </span>
        <button type="button" className="linkish" onClick={() => setSaid(null)}>
          Schedule another
        </button>
      </div>
    );
  }

  // Nothing to move to is a state rather than an empty form: the work is a
  // decision, and a form that cannot be filled in is one somebody tries anyway.
  if (landed.length === 0) {
    if ((here.issues ?? 0) === 0) return null;
    return (
      <div className="card stuck" style={{ marginTop: 12 }}>
        <h3>There is nothing to upgrade to</h3>
        <p
          className="reading"
          title="An upgrade to any version the scanner named would lapse, because none of them fixes this"
        >
          Nothing fixes the {here.issues} open here.
        </p>
        <p style={{ marginTop: 10 }}>
          <Link className="btn" to={bulkDecisionHere(product, here, component, pkg)}>
            Bulk decision
          </Link>{" "}
          <Link className="btn quiet" to={findingsAt(product, here, binaries(here))}>
            Open issues
          </Link>
        </p>
      </div>
    );
  }

  const ready = to.trim() !== "" && by !== "" && because.trim() !== "" && chosen.size > 0;
  // Counted once per issue by the server. Summed from the per-version counts
  // instead, an issue whose record names three versions counts three times and
  // the total runs past what is open.
  const withFix = here.fixable ?? 0;
  const noFix = Math.max(0, (here.issues ?? 0) - withFix);

  return (
    <div className="card act" style={{ marginTop: 12 }}>
      <h3>Schedule an upgrade</h3>
      {plan.error != null && <Failed error={plan.error} what="That could not be recorded." />}

      {/* The pair that needs no version comparison, from the scanner's own
          word on whether a fix exists at all. Read first, because the half no
          upgrade closes is the half that still needs a decision after the work
          ships. */}
      <div className="kpis tight">
        <span className="kpi">
          <span className="l">A fix exists for</span>
          <span className="n">{withFix.toLocaleString()}</span>
          <span className="d">of the {(here.issues ?? 0).toLocaleString()} open here</span>
        </span>
        <span className="kpi">
          <span className="l">No version fixes</span>
          <span className="n">{noFix.toLocaleString()}</span>
          <span className="d">a decision rather than an upgrade</span>
        </span>
      </div>
      {/* The way to make that decision, beside the number that says how much
          of it there is. Scheduling an upgrade answers the other half of this
          card and nothing on this page answered this one. */}
      {noFix > 0 && (
        <p style={{ marginTop: 6 }}>
          <Link className="linkish" to={bulkDecisionHere(product, here, component, pkg)}>
            Bulk decision on those →
          </Link>
        </p>
      )}

      <div className="filters">
        <div className="field">
          <span>Upgrade to</span>
          <input
            {...notACredential}
            type="text"
            value={to}
            placeholder="the version, as its packager writes it"
            onChange={(event) => setTo(event.target.value)}
          />
          {/* What each candidate would close, beside it. Offered in a list
              rather than a datalist, because the counts are the reason to pick
              one and a datalist shows nothing until somebody clicks into the
              box. Offered, never required: the server is what refuses a version
              it has not heard of, which is what lets somebody name one newer
              than anything reported. */}
          <ul className="tomove">
            {landed.slice(0, SHOWN).map((each, i) => (
              <li key={each.to}>
                <button
                  type="button"
                  className={each.to === to ? "on" : undefined}
                  aria-pressed={each.to === to}
                  onClick={() => setTo(each.to)}
                >
                  <span className="id">{each.to}</span>
                  <span className="why">
                    {upgradeCount(each, " of its own")}
                    {i === 0 && each.ordered && " · furthest along"}
                  </span>
                </button>
              </li>
            ))}
            {landed.length > SHOWN && (
              <li className="hint">{landed.length - SHOWN} more, in the table beside this</li>
            )}
          </ul>
          <span className="hint" title={rankedWhy(ranked(landed))}>
            {rankedLabel(ranked(landed))}
          </span>
        </div>

        <label className="field">
          <span>Done by</span>
          <input
            {...notACredential}
            type="date"
            value={by}
            onChange={(event) => setBy(event.target.value)}
          />
          <span
            className="hint"
            title="On or before the earliest deadline this covers, it stands without a second person"
          >
            nobody else needed on or before the deadline
          </span>
        </label>

        <label className="field">
          <span>Carried by</span>
          <Holder
            product={product}
            value={holder ? { identity: holder.identity, name: holder.name } : null}
            onPick={setHolder}
            placeholder="a person or a team"
            none="No one yet"
          />
          <span
            className="hint"
            title="A team queue stays unassigned until somebody on it takes the work"
          >
            a person or a team
          </span>
        </label>
      </div>

      <div className="field">
        <span>Releases this is for</span>
        <p className="variants">
          {covering.map((row) => {
            const key = buildKey(row, row.version);
            const picked = chosen.has(key);
            return (
              <button
                key={key}
                type="button"
                className={picked ? "vchip on" : "vchip"}
                aria-pressed={picked}
                onClick={() =>
                  setChosen((was) => {
                    const next = new Set(was);
                    if (picked) next.delete(key);
                    else next.add(key);
                    return next;
                  })
                }
              >
                {picked ? "✓ " : ""}
                <span className="id">{row.branch_or_tag}</span>{" "}
                <span className="hint">{row.variant}</span>
              </button>
            );
          })}
        </p>
      </div>

      <Editor
        value={because}
        onChange={setBecause}
        placeholder="The reason this is the answer here."
      />

      <div className="actions" style={{ marginTop: 10 }}>
        <button
          type="button"
          className="btn"
          disabled={!ready || plan.isPending}
          onClick={() => plan.mutate()}
        >
          {plan.isPending ? "Recording…" : `Schedule for ${chosen.size}`}
        </button>
      </div>
    </div>
  );
}
