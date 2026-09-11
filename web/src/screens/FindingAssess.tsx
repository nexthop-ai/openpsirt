import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";
import { Severity } from "../ui/Severity";
import { RATINGS } from "./FindingClaim";

// Rating the issue itself, as against what was published.
//
// The finding screen is four readings of the record, split by the question
// each answers. This is the one form among them: a claim about the issue
// wherever it appears rather than about the place it was made from, and a
// milder rating waits for a second person.

// What we think of the issue itself, as against what was published. About the
// issue rather than where it sits, so it holds wherever the issue appears ;
// rating it milder waits for a second person.
export function Assess({
  vulnerability,
  published,
  assessed,
}: {
  vulnerability: string;
  published: string;
  assessed: string;
}) {
  const queries = useQueryClient();
  const [open, setOpen] = useState(false);
  const [severity, setSeverity] = useState<string>(published || "medium");
  const [reasoning, setReasoning] = useState("");

  const assess = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/issues/{vulnerability}/assessment", {
          params: { path: { vulnerability } },
          body: { severity: severity as (typeof RATINGS)[number], reasoning },
        }),
      ),
    onSuccess: () => {
      setOpen(false);
      setReasoning("");
      void queries.invalidateQueries({ queryKey: ["finding"] });
    },
  });

  const milder =
    RATINGS.indexOf(severity as (typeof RATINGS)[number]) <
    RATINGS.indexOf((published || "medium") as (typeof RATINGS)[number]);

  if (assessed) {
    return (
      <div className="assess">
        <h3>Issue assessment</h3>
        <p className="reading" style={{ margin: 0 }}>
          Assessed <Severity word={assessed} />, published <Severity word={published} />. The
          assessment orders it and sets its deadline everywhere this issue appears.
        </p>
      </div>
    );
  }

  if (!open) {
    return (
      <div className="assess">
        <h3>Issue assessment</h3>
        <p className="reading" style={{ margin: "0 0 8px" }}>
          Published as <Severity word={published} />. A rating of ours holds wherever the issue
          appears.
        </p>
        <button type="button" className="linkish" onClick={() => setOpen(true)}>
          Rate it differently
        </button>
      </div>
    );
  }

  return (
    <div className="assess">
      <h3>Issue assessment</h3>
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
        {milder
          ? "Milder than published, so a second person has to agree before it takes effect."
          : "At or above what was published, so it takes effect at once."}
      </p>
      <div className="field" style={{ marginBottom: 8, maxWidth: "78ch" }}>
        <label htmlFor="why">Reasoning</label>
        <textarea
          id="why"
          style={{ minHeight: 64 }}
          value={reasoning}
          placeholder="What makes the published rating wrong for this issue, anywhere it appears?"
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
          Save assessment
        </button>
        <button type="button" className="btn quiet" onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
    </div>
  );
}
