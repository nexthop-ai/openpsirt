// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMemo, useState } from "react";
import { useKept } from "../ui/Saved";

// What the decision form on one finding is started from.
type Prefill = {
  outcome?: string;
  justification?: string;
  reasoning?: string;
  // The length of the deferral it offers, which the form turns into a date as
  // it opens. Only a prepared rule carries one: a length is what a rule means
  // by "put this off for a quarter", and a date saved months ago is not.
  deferDays?: number;
  // Cited, never applied: what a VEX document said is not this claim, and
  // this is what lets a later revision to it be noticed.
  fromStatement?: number;
} | null;

// useDecisionPrefill is the decision form's starting point on one finding.
//
// Two things fill it: something the reader started from on this finding, and
// the saved filter the finding was opened under where that filter prepares a
// claim. The reader's own wins, and clearing it clears the rule's too — the
// rule fills a form nobody has answered yet, not one somebody is working in.
//
// `oneFinding` names the finding the screen is on. A params-only change does
// not remount the screen, so what belongs to one finding has to say which.
export function useDecisionPrefill(product: string, oneFinding: string, rule: string) {
  // The starting point, and how many times it has been given one. Starting
  // from something is a fresh form rather than an edit to the one on screen,
  // so the count is what the form is mounted against — two prefills carrying
  // the same words are still two, and the second has to take.
  const [prefill, setPrefill] = useState<{
    // The finding it was started on. Walking to the next one is a fresh form:
    // without this, one decision recorded would leave the count above zero for
    // the rest of the walk and the rule would quietly stop filling anything in.
    at: string;
    n: number;
    from: Prefill;
  }>({ at: oneFinding, n: 0, from: null });
  // The statement started from on the finding being read, which is nothing on
  // one the count was not raised on.
  const own = prefill.at === oneFinding ? prefill : { at: oneFinding, n: 0, from: null };
  function startFrom(from: Prefill) {
    setPrefill({ at: oneFinding, n: own.n + 1, from });
  }

  // The saved filter this was opened under. The address names the filter
  // rather than repeating what it says, so what a rule prepares is decided in
  // one place — and a link somebody sends prepares nothing for the person who
  // opens it, because the filters are personal and a name they have not kept
  // is a name that is not there.
  const rules = useKept(product, rule !== "");
  // The claim that filter prepares, in the words the form takes, and whether it
  // prepares something no form can be submitted from. A rule prepares a claim
  // and a person proposes it: this fills the form in and nothing else.
  const offered = useMemo(() => {
    const one = (rules.data?.items ?? []).find((each) => each.name === rule);
    if (!one?.prepares) return { from: null, lengthless: false };
    const it = one.prepares;
    // A deferral is the one outcome that needs a date, and the date is worked
    // out from the length. Kept without one, it would fill a form that cannot
    // be submitted, under a banner saying the filter prepared it.
    if (it.outcome === "deferred" && !it.defer_days) return { from: null, lengthless: true };
    return {
      from: {
        outcome: it.outcome,
        justification: it.justification ?? "",
        reasoning: it.reasoning,
        ...(it.defer_days ? { deferDays: it.defer_days } : {}),
      },
      lengthless: false,
    };
  }, [rules.data, rule]);
  const prepared = offered.from;

  return {
    startFrom,
    // Whether the reader has started from nothing of their own on this finding.
    untouched: own.n === 0,
    // What the rule prepares, where it prepares something a form can take.
    prepared,
    // The rule prepares a deferral with no length, so nothing was filled in.
    lengthless: offered.lengthless,
    // The rule was asked for and could not be read.
    ruleUnread: rule !== "" && rules.isError,
    // The form's opening values.
    opening: own.n > 0 ? own.from : prepared,
    // What the form is mounted against.
    opened: own.n > 0 ? `own:${oneFinding}:${own.n}` : `rule:${prepared ? rule : ""}:${oneFinding}`,
    // Held until what the rule prepares is known, because a form that opens
    // blank and refills itself a moment later loses whatever somebody put in
    // it first — which is what a reloaded or bookmarked link does, having no
    // answer already in hand.
    settled: rule === "" || !rules.isPending,
  };
}
