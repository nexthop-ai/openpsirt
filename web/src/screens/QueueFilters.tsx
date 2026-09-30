// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { notACredential } from "../ui/noautofill";
import { labeled, outcomeWords } from "../ui/Outcome";
import type { paths } from "../api/schema";

// The review queue's filters, as the address carries them and the queue and
// its export are asked with. One list, so the screen, the file and a link
// somebody sends ask the same question.
const QUEUE_FILTERS = ["proposed_by", "older_than", "severity", "outcome", "release"] as const;

// The filters as the queue's own parameters declare them.
type Narrowing = Pick<
  NonNullable<paths["/v1/review-queue"]["get"]["parameters"]["query"]>,
  (typeof QUEUE_FILTERS)[number]
>;

// The ages offered, in days. The server takes any number; these are the ones
// a person reaching for "old" means.
const AGES = [7, 30, 90];

// The query the queue and its export are asked with, from the address. A
// value that is not one the server takes is left out rather than sent to be
// refused.
export function queueNarrowing(params: URLSearchParams): Narrowing {
  const out: ReturnType<typeof queueNarrowing> = {};
  const who = params.get("proposed_by")?.trim();
  if (who) out.proposed_by = who;
  const days = Number(params.get("older_than") ?? "");
  if (Number.isInteger(days) && days > 0) out.older_than = days;
  const severity = params.get("severity");
  if (severity === "medium" || severity === "high" || severity === "critical") {
    out.severity = severity;
  }
  const outcomes = params.getAll("outcome").filter((word) => outcomeWords().includes(word));
  if (outcomes.length > 0) out.outcome = outcomes as NonNullable<Narrowing["outcome"]>;
  const release = params.get("release")?.trim();
  if (release) out.release = release;
  return out;
}

// How many of the queue's filters are on.
export function narrowedBy(params: URLSearchParams): number {
  return Object.keys(queueNarrowing(params)).length;
}

export function QueueFilters({
  params,
  onAsk,
}: {
  params: URLSearchParams;
  // The address with one filter changed. The caller clears its selection,
  // because a selection is made out of the list being replaced.
  onAsk: (next: URLSearchParams) => void;
}) {
  const [who, setWho] = useState(params.get("proposed_by") ?? "");
  const [release, setRelease] = useState(params.get("release") ?? "");

  function set(key: (typeof QUEUE_FILTERS)[number], value: string) {
    // Leaving a box without changing it asks nothing new, and asking again
    // would clear a selection made under the same question.
    if ((params.get(key) ?? "") === value.trim()) return;
    const next = new URLSearchParams(params);
    next.delete(key);
    if (value.trim() !== "") next.set(key, value.trim());
    next.delete("offset");
    onAsk(next);
  }

  const on = narrowedBy(params);
  return (
    <div className="filters queuefilters" style={{ marginBottom: 10 }}>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          set("proposed_by", who);
        }}
      >
        <input
          {...notACredential}
          type="text"
          value={who}
          onChange={(event) => setWho(event.target.value)}
          onBlur={() => set("proposed_by", who)}
          placeholder="Proposed by"
          aria-label="Proposed by, by sign-in name"
          style={{ width: 150 }}
        />
      </form>
      <select
        value={params.get("older_than") ?? ""}
        onChange={(event) => set("older_than", event.target.value)}
        aria-label="Age"
      >
        <option value="">Any age</option>
        {AGES.map((days) => (
          <option key={days} value={days}>
            Older than {days} days
          </option>
        ))}
      </select>
      <select
        value={params.get("severity") ?? ""}
        onChange={(event) => set("severity", event.target.value)}
        aria-label="Severity"
      >
        <option value="">Any severity</option>
        <option value="medium">Medium or worse</option>
        <option value="high">High or worse</option>
        <option value="critical">Critical</option>
      </select>
      <select
        value={params.get("outcome") ?? ""}
        onChange={(event) => set("outcome", event.target.value)}
        aria-label="Outcome"
      >
        <option value="">Any outcome</option>
        {outcomeWords().map((word) => (
          <option key={word} value={word}>
            {labeled(word)}
          </option>
        ))}
      </select>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          set("release", release);
        }}
      >
        <input
          {...notACredential}
          type="text"
          value={release}
          onChange={(event) => setRelease(event.target.value)}
          onBlur={() => set("release", release)}
          placeholder="Branch or tag"
          aria-label="Branch or tag name"
          title="Claims covering an open finding in a branch or tag of this name"
          style={{ width: 130 }}
        />
      </form>
      {on > 0 && (
        <button
          type="button"
          className="linkish"
          onClick={() => {
            const next = new URLSearchParams(params);
            for (const key of QUEUE_FILTERS) next.delete(key);
            next.delete("offset");
            setWho("");
            setRelease("");
            onAsk(next);
          }}
        >
          Clear filters
        </button>
      )}
    </div>
  );
}
