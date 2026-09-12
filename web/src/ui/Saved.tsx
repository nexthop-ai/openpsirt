import { notACredential } from "./noautofill";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api, type Body } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";

export type Prepared = NonNullable<Body<"SavedBody">["prepares"]>;

// Filters somebody kept, and what one of them prepares.
//
// **Personal. Nothing is shared.** No ownership, no permissions, no arguing
// about whose filter is authoritative — which is also what lets somebody keep
// one that is half-formed, the state most of them are in most of the time.
//
// **What is kept is the list's own address**, so opening one is going back to
// exactly the list that was on screen. A filter naming something the list no
// longer offers simply stops narrowing by it, which is a slightly wider list
// rather than a refusal to open one.
//
// **A rule prepares a claim; a person proposes it**. A saved filter can carry
// an outcome, a justification, the reasoning and how long a deferral it means;
// picking it fills the decision form of every finding opened from the list,
// and a named person submits the claim as their own for a second person to
// approve. It proposes nothing by itself — the wider form was refused because
// it leaves the approver as the only human judgment on the claim.
export function Saved({
  product,
  onPrepared,
}: {
  // Whose list these narrow. A filter's query names branches and variants
  // belonging to one product, so it is kept and offered there rather than
  // everywhere.
  product: string;
  // Told which filter was picked and what it prepares, so the list can carry
  // it into the decision form. Named as well as read, because the rows travel
  // to the finding under the filter's name rather than its words: what a rule
  // says is decided in one place, and a copy in an address is a second. Null
  // where it prepares nothing, which is most of them.
  onPrepared: (picked: { name: string; prepares: Prepared } | null) => void;
}) {
  const [params, setParams] = useSearchParams();
  const queries = useQueryClient();
  const [saving, setSaving] = useState(false);
  const [name, setName] = useState("");
  const [rule, setRule] = useState(false);
  const [outcome, setOutcome] = useState("");
  const [justification, setJustification] = useState("");
  const [reasoning, setReasoning] = useState("");
  // How long a deferral it prepares, as a number of days. A length rather than
  // a date, because a rule saved in March means "put this off for a quarter"
  // and a date would be wrong the week after it was saved.
  const [days, setDays] = useState("");

  const kept = useQuery({
    queryKey: ["saved-filters", product],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/saved-filters", {
          params: { path: { product } },
        }),
      ),
    retry: false,
  });
  const save = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PUT("/v1/products/{product}/saved-filters/{name}", {
          params: { path: { product, name: name.trim() } },
          body: {
            query: here(params),
            ...(rule && outcome
              ? {
                  prepares: {
                    outcome: outcome as Prepared["outcome"],
                    ...(justification ? { justification } : {}),
                    reasoning: reasoning.trim(),
                    ...(outcome === "deferred" ? { defer_days: Number(days) } : {}),
                  },
                }
              : {}),
          },
        }),
      ),
    onSuccess: () => {
      setSaving(false);
      setName("");
      setRule(false);
      setOutcome("");
      setJustification("");
      setReasoning("");
      setDays("");
      void queries.invalidateQueries({ queryKey: ["saved-filters", product] });
    },
  });
  const forget = useMutation({
    mutationFn: async (called: string) =>
      unwrap(
        await api.DELETE("/v1/products/{product}/saved-filters/{name}", {
          params: { path: { product, name: called } },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["saved-filters"] }),
  });

  const mine = kept.data?.items ?? [];
  const current = here(params);
  const open = mine.find((one) => one.query === current);

  function pick(called: string) {
    const one = mine.find((each) => each.name === called);
    if (!one) return;
    // The saved address wins outright rather than being merged into what is
    // on screen: opening a saved filter means "show me that list", and a
    // merge would answer a question nobody saved.
    setParams(new URLSearchParams(one.query));
    onPrepared(one.prepares ? { name: one.name, prepares: one.prepares } : null);
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
          <button type="button" className="linkish" onClick={() => setSaving(!saving)}>
            {saving ? "Cancel" : "Save this"}
          </button>
        )}
      </span>

      {save.error != null && <Failed error={save.error} what="That was not saved." />}
      {forget.error != null && <Failed error={forget.error} what="That was not forgotten." />}

      {saving && (
        <div className="advanced" style={{ width: "100%" }}>
          <label className="field">
            <span>Call it</span>
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
                <span>It would say</span>
                <select value={outcome} onChange={(event) => setOutcome(event.target.value)}>
                  <option value="">Select one</option>
                  <option value="not-applicable">Not applicable</option>
                  <option value="deferred">Deferred</option>
                  <option value="wont-fix">Will not fix</option>
                  <option value="already-fixed">Already fixed</option>
                  <option value="affected">Affected</option>
                </select>
              </label>
              {outcome === "not-applicable" && (
                <label className="field">
                  <span>Because</span>
                  <select
                    value={justification}
                    onChange={(event) => setJustification(event.target.value)}
                  >
                    <option value="">Select one</option>
                    <option value="component_not_present">the component is not present</option>
                    <option value="vulnerable_code_not_present">
                      the vulnerable code is not present
                    </option>
                    <option value="vulnerable_code_not_in_execute_path">
                      the vulnerable code is never run
                    </option>
                    <option value="vulnerable_code_cannot_be_controlled_by_adversary">
                      nobody outside can reach it
                    </option>
                    <option value="inline_mitigations_already_exist">
                      something already stops it
                    </option>
                  </select>
                </label>
              )}
              {/* A length rather than a date, and the form turns it into one
                  as somebody submits it. A rule saved in March means "put
                  this off for a quarter"; a date kept here would be wrong the
                  week after it was saved. */}
              {outcome === "deferred" && (
                <label className="field">
                  <span>For how long</span>
                  <input
                    {...notACredential}
                    type="number"
                    min={1}
                    max={3650}
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
                <span>In these words</span>
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
                This proposes nothing by itself. Picking the filter fills the decision form with
                these words, and <b>you</b> submit the claim as your own for a second person to
                agree to — so the record says who made it.
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
                  (outcome === "deferred" && !(Number(days) >= 1 && Number(days) <= 3650))))
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

// The list's current address, without a leading "?" and without the page it
// happens to be on: a saved filter is a narrowing rather than a position in
// one.
function here(params: URLSearchParams): string {
  const asked = new URLSearchParams(params);
  asked.delete("offset");
  return asked.toString();
}
