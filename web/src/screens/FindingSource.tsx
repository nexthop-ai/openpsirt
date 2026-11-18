// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { decisionAt } from "../app/routes";
import { Failed } from "../ui/Failed";
import { JUSTIFICATIONS_CORRECTING } from "../ui/Outcome";
import { useReseed } from "../ui/reseed";

// A match made through the source package a binary is built from, with the
// files the issue's record names, and the form for correcting every match like
// it at once.
//
// The form is filled from the finding: the package and the source are the
// ones this match names, so only the paths are typed.
export function SourceMatch({
  product,
  vulnerability,
  component,
  through,
  files,
  mayTriage,
}: {
  product: string;
  vulnerability: string;
  component: string;
  through?: string;
  files?: string[] | null;
  mayTriage: boolean;
}) {
  const [open, setOpen] = useState(false);
  useReseed(`${product}|${vulnerability}|${component}`, () => setOpen(false));
  if (!through) return null;
  const listed = files ?? [];
  return (
    <div className="evblock">
      <h4>Matched through source</h4>
      <p title="The scanner matched the source package this is built from, not the package itself">
        Through <span className="id">{through}</span>.{" "}
        {listed.length === 0 ? "The CVE record lists no files." : "The CVE record lists:"}
      </p>
      {listed.length > 0 && (
        <ul className="refs mono" style={{ fontSize: "var(--step--1)" }}>
          {listed.map((file) => (
            <li key={file}>{file}</li>
          ))}
        </ul>
      )}
      {mayTriage &&
        (open ? (
          <Correct
            product={product}
            component={component}
            through={through}
            onClose={() => setOpen(false)}
          />
        ) : (
          <button
            type="button"
            className="linkish"
            title={`Not affected for every issue matched through ${through} whose files are outside what ${component} is built from`}
            onClick={() => setOpen(true)}
          >
            Correct by source paths
          </button>
        ))}
    </div>
  );
}

// A reason saying something is not there, the two a correction takes.
type Correcting = "component_not_present" | "vulnerable_code_not_present";

// The paths typed one a line, as they are named in the source tree.
function pathsOf(typed: string): string[] {
  return typed
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

function Correct({
  product,
  component,
  through,
  onClose,
}: {
  product: string;
  component: string;
  through: string;
  onClose: () => void;
}) {
  const [paths, setPaths] = useState("");
  const [justification, setJustification] = useState<Correcting>("vulnerable_code_not_present");
  const [reasoning, setReasoning] = useState("");

  const propose = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/products/{product}/source-corrections", {
          params: { path: { product } },
          body: {
            package: component,
            source: through,
            paths: pathsOf(paths),
            justification,
            reasoning,
          },
        }),
      ),
  });

  if (propose.data) {
    return (
      <p className="alert info" role="status">
        <span>
          Answers {propose.data.answered.toLocaleString()} now, and later issues as scans find them.
          Waits for a second person.{" "}
          <Link className="linkish" to={decisionAt(propose.data.decision_id)}>
            Open the decision →
          </Link>
        </span>
      </p>
    );
  }

  return (
    <div className="rating">
      {propose.error != null && (
        <Failed error={propose.error} what="That correction could not be recorded." />
      )}
      <p
        className="hint"
        style={{ margin: "0 0 8px" }}
        title={`Every issue in ${component} matched through ${through}, in this product, at every version`}
      >
        Not affected where every listed file is outside these paths.
      </p>
      <div className="field" style={{ marginBottom: 8, maxWidth: "78ch" }}>
        <label htmlFor="sourcepaths">Built from</label>
        <textarea
          id="sourcepaths"
          className="mono"
          style={{ minHeight: 64 }}
          value={paths}
          placeholder={"tools/perf\ntools/lib"}
          title="One path a line, within the source tree"
          onChange={(event) => setPaths(event.target.value)}
        />
      </div>
      <div className="field" style={{ marginBottom: 8 }}>
        <label htmlFor="sourcereason">Reason</label>
        <select
          id="sourcereason"
          style={{ width: "auto" }}
          value={justification}
          onChange={(event) => setJustification(event.target.value as Correcting)}
        >
          {JUSTIFICATIONS_CORRECTING.map((each) => (
            <option key={each.value} value={each.value} title={`${each.value}: ${each.means}`}>
              {each.label}
            </option>
          ))}
        </select>
      </div>
      <div className="field" style={{ marginBottom: 8, maxWidth: "78ch" }}>
        <label htmlFor="sourcereasoning">Reasoning</label>
        <textarea
          id="sourcereasoning"
          style={{ minHeight: 64 }}
          value={reasoning}
          placeholder="How you know the package is built from these paths alone"
          onChange={(event) => setReasoning(event.target.value)}
        />
      </div>
      <div className="actions">
        <button
          type="button"
          className="btn"
          disabled={pathsOf(paths).length === 0 || reasoning.trim() === "" || propose.isPending}
          onClick={() => propose.mutate()}
        >
          Propose
        </button>
        <button type="button" className="btn quiet" onClick={onClose}>
          Cancel
        </button>
      </div>
    </div>
  );
}
