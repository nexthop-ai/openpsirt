// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { labeled, reasonOffered, reasonsFor } from "./Outcome";
import { useOutcomes } from "./outcomes";
import { notACredential } from "./noautofill";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api, type Body } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";

type Prepared = NonNullable<Body<"SavedBody">["prepares"]>;

// The outcomes a saved filter may prepare, driven off the generated request
// type rather than retyped as options. Fewer than a person may record one at a
// time, and which are left out is the domain's statement rather than this
// screen's. Written as a record so a word the domain gains and this does not
// is a compile error, and so is one kept here after the domain drops it. Each
// is labeled from the one map every other screen reads.
type InBulk = Body<"PreparedBody">["outcome"];

const PREPARES: Record<InBulk, true> = {
  "not-applicable": true,
  mismatched: true,
  deferred: true,
  "wont-fix": true,
  "already-fixed": true,
  affected: true,
};
export type Kept = Body<"SavedBody">;

// The bounds on a prepared deferral's length, mirroring what the endpoint takes
// (`PreparedBody.DeferDays`). Written here because the generated client cannot
// carry them: the document's minimum and maximum do not survive into a type,
// so the screen refusing what the server refuses is a copy either way — one
// copy rather than three.
const DEFER_DAYS = { min: 1, max: 3650 };

// The filters somebody has kept: one list per person, offered on every findings
// list. One reader rather than one per screen: the list, the dropdown and a
// finding opened under a rule all ask the same question, and a second spelling
// of the key is a second cache.
export function useKept(when = true) {
  return useQuery({
    queryKey: ["saved-filters"],
    queryFn: async () => unwrap(await api.GET("/v1/session/me/saved-filters")),
    enabled: when,
    retry: false,
  });
}

// The words of the list's address that say where it is or how it is grouped
// rather than what it is narrowed by: the branch, the variant, a subtree of one
// build, what differs between the builds of a selection, what is spread over
// the variants of one branch, the run that opened it, and the grouping. A saved
// filter keeps none of them, so one filter applies within whatever scope and
// grouping is on screen, and picking one keeps them. The server drops the same
// words from what it keeps.
const SCOPE = [
  "stream",
  "variant",
  "beneath",
  "beneath_version",
  "beneath_ecosystem",
  "beneath_namespace",
  "differs",
  "variants",
  "opened_by_run",
  "view",
];

// The filter a list is currently narrowed by, where its address is exactly one
// somebody kept. Derived rather than remembered, so narrowing further drops it
// and coming back to the list finds it again.
//
// Picking a filter puts its name in the address as `rule`, the word a finding
// already reads the filter's name from, and the list names that one: two
// filters can keep one query, and only the name tells them apart. Changing a
// filter on screen drops the name. An address without one, typed or kept from
// before, is matched by its query.
export function ruleIn(kept: Kept[], params: URLSearchParams): Kept | undefined {
  const named = params.get("rule");
  if (named) return kept.find((one) => one.name === named);
  const current = here(params);
  // A filter that keeps nothing narrows nothing, and would otherwise read as
  // open on every list with no filter on it.
  return kept.find((one) => one.query !== "" && one.query === current);
}

// Filters somebody kept, and what one of them prepares.
//
// Personal. Nothing is shared. No ownership, no permissions, no arguing
// about whose filter is authoritative — which is also what lets somebody keep
// one that is half-formed, the state most of them are in most of the time.
//
// The list's own address is what is kept, so opening one is going back to
// exactly the list that was on screen. A filter naming something the list no
// longer offers simply stops narrowing by it, which is a slightly wider list
// rather than a refusal to open one.
//
// A rule prepares a claim; a person proposes it. A saved filter can carry
// an outcome, a justification, the reasoning and how long a deferral it means;
// picking it fills the decision form of every finding opened from the list,
// and a named person submits the claim as their own for a second person to
// approve. It proposes nothing by itself — the wider form was refused because
// it leaves the approver as the only human judgment on the claim.
export function Saved({
  onBuild,
  onPicked,
}: {
  // Whether the list is scoped to a branch or a variant, which saving leaves
  // out and the confirmation says so.
  onBuild: boolean;
  // Told that a filter was picked, with the address it opens, which replaces
  // the list wholesale. What
  // the picked one prepares is not passed: the list reads that off its own
  // address, so it is dropped by narrowing further and found again by coming
  // back.
  onPicked: (next: URLSearchParams) => void;
}) {
  const [params] = useSearchParams();
  const queries = useQueryClient();
  const [saving, setSaving] = useState(false);
  const [name, setName] = useState("");
  const [rule, setRule] = useState(false);
  const [outcome, setOutcome] = useState("");
  const [justification, setJustification] = useState("");
  const [reasoning, setReasoning] = useState("");
  // The length of the deferral it prepares, in days. A length rather than
  // a date, because a rule saved in March means "put this off for a quarter"
  // and a date would be wrong the week after it was saved.
  const [days, setDays] = useState("");
  // What the last save said, until the next act.
  const [said, setSaid] = useState("");
  // The two outcomes whose claim is which recognized reason applies, and the
  // reasons each may state. A correction carries past every version bump, so
  // the three reasons a bump can change are not among the ones it offers.
  const needsJustification = useOutcomes().needsJustification(outcome);
  const reasons = reasonsFor(outcome);
  // Dropped rather than carried when the outcome moves under it: a correction
  // takes only the reasons no version bump can answer, and a rule prepared
  // with one the endpoint refuses fails when somebody presses the button
  // rather than when they saved the thing that fills it in.
  const reason = reasonOffered(outcome, justification);

  const kept = useKept();
  const save = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PUT("/v1/session/me/saved-filters/{name}", {
          params: { path: { name: name.trim() } },
          body: {
            query: here(params),
            ...(rule && outcome
              ? {
                  prepares: {
                    outcome: outcome as Prepared["outcome"],
                    // Both of these belong to one outcome and are dropped
                    // with it: switching from "not applicable" to "deferred"
                    // hides the Because select and would otherwise keep what
                    // was chosen in it, storing a reason the decision endpoint
                    // refuses.
                    ...(needsJustification && reason
                      ? { justification: reason as Prepared["justification"] }
                      : {}),
                    reasoning: reasoning.trim(),
                    ...(outcome === "deferred" ? { defer_days: Number(days) } : {}),
                  },
                }
              : {}),
          },
        }),
      ),
    onSuccess: () => {
      setSaid(
        onBuild || scoped(params)
          ? "Saved. Applies to whatever branch and variant you're viewing."
          : "Saved.",
      );
      setSaving(false);
      setName("");
      setRule(false);
      setOutcome("");
      setJustification("");
      setReasoning("");
      setDays("");
      void queries.invalidateQueries({ queryKey: ["saved-filters"] });
    },
  });
  const forget = useMutation({
    mutationFn: async (called: string) =>
      unwrap(
        await api.DELETE("/v1/session/me/saved-filters/{name}", {
          params: { path: { name: called } },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["saved-filters"] }),
  });

  const mine = kept.data?.items ?? [];
  const unshown = Math.max(0, (kept.data?.total ?? 0) - mine.length);
  const open = ruleIn(mine, params);

  function pick(called: string) {
    const one = mine.find((each) => each.name === called);
    if (!one) return;
    // The saved address wins outright rather than being merged into what is
    // on screen: opening a saved filter means "show me that list", and a
    // merge would answer a question nobody saved. The scope and grouping on
    // screen stay, because the filter applies within them.
    const next = new URLSearchParams(one.query);
    for (const key of SCOPE) {
      const value = params.get(key);
      if (value) next.set(key, value);
    }
    next.set("rule", one.name);
    setSaid("");
    onPicked(next);
  }

  return (
    <>
      <span className="kept">
        <select
          aria-label="Open a saved filter"
          value={open?.name ?? ""}
          onChange={(event) => pick(event.target.value)}
        >
          <option value="">Saved filters…</option>
          {mine.map((one) => (
            <option key={one.name} value={one.name}>
              {one.name}
              {one.prepares ? " ·  prepares a claim" : ""}
            </option>
          ))}
          {unshown > 0 && (
            <option value="" disabled>
              {unshown.toLocaleString()} more over the limit, not shown
            </option>
          )}
        </select>
        {open ? (
          <button
            type="button"
            className="linkish"
            title={`Forget “${open.name}”`}
            disabled={forget.isPending}
            onClick={() => forget.mutate(open.name)}
          >
            Forget
          </button>
        ) : (
          <button
            type="button"
            className="linkish"
            onClick={() => {
              setSaid("");
              setSaving(!saving);
            }}
          >
            {saving ? "Cancel" : "Save this"}
          </button>
        )}
        {said && (
          <span className="hint" role="status">
            {said}
          </span>
        )}
      </span>

      {save.error != null && <Failed error={save.error} what="That was not saved." />}
      {forget.error != null && <Failed error={forget.error} what="That was not forgotten." />}

      {saving && (
        <div className="advanced" style={{ width: "100%" }}>
          <label className="field">
            <span className="l">Call it</span>
            <input
              {...notACredential}
              type="text"
              value={name}
              placeholder="overdue kernel"
              onChange={(event) => setName(event.target.value)}
            />
          </label>
          <label className="field row">
            <input
              type="checkbox"
              checked={rule}
              onChange={(event) => setRule(event.target.checked)}
            />
            <span>And prepare a claim for what it catches</span>
          </label>
          {rule && (
            <>
              <label className="field">
                <span className="l">It would say</span>
                <select value={outcome} onChange={(event) => setOutcome(event.target.value)}>
                  <option value="">Select one</option>
                  {Object.keys(PREPARES).map((word) => (
                    <option key={word} value={word}>
                      {labeled(word)}
                    </option>
                  ))}
                </select>
              </label>
              {needsJustification && (
                <label className="field">
                  <span className="l">Because</span>
                  <select value={reason} onChange={(event) => setJustification(event.target.value)}>
                    <option value="">Select one</option>
                    {/* From the one list rather than typed out again, so the
                        same claim reads the same way where it is chosen and
                        where it is read back, and a reason the vocabulary
                        gains appears here without anybody adding it. Which
                        list it is depends on the outcome: a correction takes
                        only the reasons no version bump can answer. */}
                    {reasons.map((each) => (
                      <option key={each.value} value={each.value}>
                        {each.label}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              {/* A length rather than a date, and the form turns it into one
                  as somebody submits it. A rule saved in March means "put
                  this off for a quarter"; a date kept here would be wrong the
                  week after it was saved. */}
              {outcome === "deferred" && (
                <label className="field">
                  <span className="l">For how long</span>
                  <input
                    {...notACredential}
                    type="number"
                    min={DEFER_DAYS.min}
                    max={DEFER_DAYS.max}
                    step={1}
                    style={{ width: 90 }}
                    value={days}
                    placeholder="90"
                    title="Days, counted from whenever somebody submits it"
                    onChange={(event) => setDays(event.target.value)}
                  />
                  <span className="hint">days, from whenever somebody submits it</span>
                </label>
              )}
              <label className="field" style={{ flexBasis: "100%" }}>
                <span className="l">In these words</span>
                <textarea
                  {...notACredential}
                  rows={3}
                  value={reasoning}
                  placeholder="The driver is not built for this image."
                  onChange={(event) => setReasoning(event.target.value)}
                />
              </label>
              <p className="hint" style={{ flexBasis: "100%", margin: 0 }}>
                {/* The whole of why the narrow form was chosen. A rule that
                    proposed its own claims would leave the approver as the
                    only human judgment on them, and would put a configuration
                    file where a name belongs in the record. */}
                Proposes nothing. Picking the filter fills the decision form, and <b>you</b> submit
                the claim as your own.
              </p>
            </>
          )}
          <button
            type="button"
            className="btn"
            style={{ alignSelf: "end" }}
            disabled={
              name.trim() === "" ||
              save.isPending ||
              (rule &&
                (outcome === "" ||
                  reasoning.trim() === "" ||
                  // A deferral with no length opens the form with the outcome
                  // chosen and no date, which cannot be submitted: the date is
                  // worked out from the length as somebody submits it.
                  (outcome === "deferred" && !whole(days))))
            }
            onClick={() => save.mutate()}
          >
            Save
          </button>
        </div>
      )}
    </>
  );
}

// A typed length the endpoint will take. Whole days, because a
// fractional one passes a range check and comes back refused after a round
// trip.
function whole(days: string): boolean {
  const n = Number(days);
  return Number.isInteger(n) && n >= DEFER_DAYS.min && n <= DEFER_DAYS.max;
}

// The list's current address as a saved filter keeps it: without a leading
// "?", without the page it happens to be on, and without its scope. A saved
// filter is a narrowing rather than a position in one or a place.
export function here(params: URLSearchParams): string {
  const asked = new URLSearchParams(params);
  asked.delete("offset");
  asked.delete("rule");
  for (const key of SCOPE) asked.delete(key);
  return asked.toString();
}

// Whether the address carries scope that saving leaves out. The grouping is
// left out too, and is not what the confirmation is about.
function scoped(params: URLSearchParams): boolean {
  return SCOPE.some((key) => key !== "view" && params.has(key));
}
