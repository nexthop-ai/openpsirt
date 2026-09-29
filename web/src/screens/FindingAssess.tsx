// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";
import { RECORDABLE } from "../ui/severities";
import { RATINGS } from "./FindingClaim";

// The rating the form opens on: the standing one, then the published one, and
// only where the form offers it. A published "negligible" or "none" is a word
// the select cannot show and the route refuses, so it opens on medium instead.
export function startingRating(assessed?: string, published?: string): string {
  const offered = RATINGS as readonly string[];
  return [assessed, published].find((word) => offered.includes(word ?? "")) ?? "medium";
}

// Whether a rating is milder than the published one, on the whole ladder a
// published word can be on. "negligible" and "none" sit below low, so nothing
// the form offers is milder than either. Unrated reads as medium.
export function milderThan(rating: string, published?: string): boolean {
  const rank = (word: string) => (RECORDABLE as readonly string[]).indexOf(word);
  const theirs = rank(published || "medium");
  const ours = rank(rating);
  return ours >= 0 && theirs >= 0 && ours > theirs;
}

// Rating the issue itself, as against what was published.
//
// The finding screen is four readings of the record, split by the question
// each answers. This is the one form among them: a claim about the issue
// rather than about the place it was made from, so it holds in every build of
// this product — and rating it milder waits for a second person.
//
// The form only. What it is about is the severity line it opens from, which
// already names the rating and the product: repeating either here is the same
// fact twice on one screen.
export function Assess({
  product,
  vulnerability,
  published,
  assessed,
  onClose,
  onDone,
}: {
  product: string;
  vulnerability: string;
  published: string;
  assessed?: string;
  onClose: () => void;
  // What was recorded, for the confirmation drawn where the form was.
  onDone: (rated: { severity: string; waiting: boolean }) => void;
}) {
  const queries = useQueryClient();
  // The rating standing, where one is. Somebody opening this to reword the
  // reasoning is not proposing a rating, and seeding from the published one
  // makes saving the reasoning revert the rating without saying so.
  const [severity, setSeverity] = useState<string>(() => startingRating(assessed, published));
  const [reasoning, setReasoning] = useState("");

  const assess = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/products/{product}/issues/{vulnerability}/assessment", {
          params: { path: { product, vulnerability } },
          body: { severity: severity as (typeof RATINGS)[number], reasoning },
        }),
      ),
    onSuccess: (rated) => {
      onDone({ severity: rated.severity, waiting: !!rated.needs_approval });
      setReasoning("");
      void queries.invalidateQueries({ queryKey: ["finding"] });
    },
  });

  const milder = milderThan(severity, published);

  return (
    <div className="rating">
      {assess.error != null && <Failed error={assess.error} what="That could not be recorded." />}
      <div className="ourview">
        <div className="pair">
          <span className="l">Published</span>
          <span className="theirs">{published || "unrated"}</span>
        </div>
        <div className="field" style={{ margin: 0 }}>
          <label htmlFor="rating">Assessed</label>
          <select
            id="rating"
            value={severity}
            style={{ width: "auto" }}
            onChange={(event) => setSeverity(event.target.value)}
          >
            {RATINGS.map((each) => (
              <option key={each} value={each}>
                {each}
              </option>
            ))}
          </select>
        </div>
      </div>
      <p className="hint" style={{ margin: "0 0 8px" }}>
        {milder ? "Milder than published. Needs a second person." : "Applies immediately."}
      </p>
      <div className="field" style={{ marginBottom: 8, maxWidth: "78ch" }}>
        <label htmlFor="why">Reasoning</label>
        <textarea
          id="why"
          style={{ minHeight: 64 }}
          value={reasoning}
          placeholder="The reason the published rating is wrong here"
          onChange={(event) => setReasoning(event.target.value)}
        />
      </div>
      <div className="actions">
        <button
          type="button"
          className="btn"
          disabled={reasoning.trim() === "" || assess.isPending}
          onClick={() => assess.mutate()}
        >
          Save
        </button>
        <button type="button" className="btn quiet" onClick={onClose}>
          Cancel
        </button>
      </div>
    </div>
  );
}
