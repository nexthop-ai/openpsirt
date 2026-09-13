import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";
import { RATINGS } from "./FindingClaim";

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
  onClose,
}: {
  product: string;
  vulnerability: string;
  published: string;
  onClose: () => void;
}) {
  const queries = useQueryClient();
  const [severity, setSeverity] = useState<string>(published || "medium");
  const [reasoning, setReasoning] = useState("");

  const assess = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/products/{product}/issues/{vulnerability}/assessment", {
          params: { path: { product, vulnerability } },
          body: { severity: severity as (typeof RATINGS)[number], reasoning },
        }),
      ),
    onSuccess: () => {
      onClose();
      setReasoning("");
      void queries.invalidateQueries({ queryKey: ["finding"] });
    },
  });

  const milder =
    RATINGS.indexOf(severity as (typeof RATINGS)[number]) <
    RATINGS.indexOf((published || "medium") as (typeof RATINGS)[number]);

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
          placeholder="Why the published rating is wrong here"
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
