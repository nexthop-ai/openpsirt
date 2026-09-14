import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { useReseed } from "./reseed";

// Composing a CVSS base vector, and showing what it scores.
//
// **The score is worked out on the server, not here.** The formula lives in
// one place and what somebody sees while choosing is what gets stored — a
// second copy in the browser is one that eventually disagrees with the number
// in the database, and the disagreement is invisible.
//
// **Base metrics only.** Temporal and environmental scores describe a moment
// and a deployment, and the deployment reading this is not the one the finding
// is about.

// The eight metrics, their values, and what each value means in words.
//
// The words matter more than the letters: somebody rating a flaw for the first
// time is choosing between "over the network" and "physical access", not
// between N and P.
const METRICS: {
  key: string;
  label: string;
  help: string;
  values: { value: string; label: string }[];
}[] = [
  {
    key: "AV",
    label: "Attack vector",
    help: "Where the attacker has to be",
    values: [
      { value: "N", label: "Network — reachable remotely" },
      { value: "A", label: "Adjacent — same broadcast or shared segment" },
      { value: "L", label: "Local — a shell or a local account" },
      { value: "P", label: "Physical — hands on the device" },
    ],
  },
  {
    key: "AC",
    label: "Attack complexity",
    help: "Whether anything beyond the attacker's control has to line up",
    values: [
      { value: "L", label: "Low — it works whenever they try" },
      { value: "H", label: "High — depends on conditions they cannot arrange" },
    ],
  },
  {
    key: "PR",
    label: "Privileges required",
    help: "What the attacker must already hold",
    values: [
      { value: "N", label: "None" },
      { value: "L", label: "Low — an ordinary account" },
      { value: "H", label: "High — administrative" },
    ],
  },
  {
    key: "UI",
    label: "User interaction",
    help: "Whether somebody else has to do something",
    values: [
      { value: "N", label: "None" },
      { value: "R", label: "Required — a person has to act" },
    ],
  },
  {
    key: "S",
    label: "Scope",
    help: "Whether it reaches past the thing that is vulnerable",
    values: [
      { value: "U", label: "Unchanged — only the vulnerable component" },
      { value: "C", label: "Changed — it reaches beyond it" },
    ],
  },
  {
    key: "C",
    label: "Confidentiality",
    help: "What can be read",
    values: [
      { value: "H", label: "High — everything, or the part that matters" },
      { value: "L", label: "Low — something, but limited" },
      { value: "N", label: "None" },
    ],
  },
  {
    key: "I",
    label: "Integrity",
    help: "What can be changed",
    values: [
      { value: "H", label: "High" },
      { value: "L", label: "Low" },
      { value: "N", label: "None" },
    ],
  },
  {
    key: "A",
    label: "Availability",
    help: "What can be stopped",
    values: [
      { value: "H", label: "High" },
      { value: "L", label: "Low" },
      { value: "N", label: "None" },
    ],
  },
];

// The versions of the scheme this composes a vector under.
//
// The base formula is the same in both, so the two score identically — what
// differs is what the vector says it is, and that is a statement about which
// scheme somebody assessed under rather than a formatting detail.
const NEWEST = "CVSS:3.1";
const KNOWN = [NEWEST, "CVSS:3.0"];

// versionOf is the scheme a vector states, or the newest where it states none.
//
// Kept through an edit. Re-stamping a vector recorded under 3.0 as 3.1 because
// somebody changed one metric rewrites what the original assessment claimed,
// and it is silent — the score does not move, because the formula did not.
export function versionOf(vector: string): string {
  const stated = vector.toUpperCase().split("/")[0] ?? "";
  return KNOWN.includes(stated) ? stated : NEWEST;
}

// vectorOf assembles what has been chosen, or nothing until all eight are.
//
// Nothing rather than a partial vector: eight metrics with one unanswered is
// not a base vector, and a score from seven of them would be a number nobody
// could reproduce.
export function vectorOf(chosen: Record<string, string>, under: string): string {
  const parts = METRICS.map((m) => chosen[m.key]);
  if (parts.some((p) => !p)) return "";
  return under + "/" + METRICS.map((m, i) => `${m.key}:${parts[i]}`).join("/");
}

// The metrics a vector states, which is the reverse of the above. A vector
// somebody pasted names some or all of them; one nothing has been chosen for
// yet names none.
//
// A part this does not recognize is skipped rather than refused: a vector
// carrying temporal or environmental metrics beside the base ones is a vector
// somebody pasted from a scanner, and the eight this composes are still in it.
export function read(vector: string): Record<string, string> {
  const chosen: Record<string, string> = {};
  for (const part of vector.toUpperCase().split("/").slice(1)) {
    const [metric, value] = part.split(":");
    if (metric && value) chosen[metric] = value;
  }
  return chosen;
}

export function Scoring({
  vector,
  onChange,
}: {
  vector: string;
  onChange: (vector: string) => void;
}) {
  const [chosen, setChosen] = useState<Record<string, string>>(() => read(vector));
  const [open, setOpen] = useState(false);

  // Kept in step with whatever the caller holds, so that a vector pasted in
  // whole lights up the metrics it states. Re-seeded rather than remounted:
  // picking the last metric completes the vector, and a remount would collapse
  // the metric list at the moment somebody finished with it.
  useReseed(vector, () => setChosen(read(vector)));

  const scored = useQuery({
    queryKey: ["score", vector],
    enabled: vector !== "",
    queryFn: async () => unwrap(await api.GET("/v1/score", { params: { query: { vector } } })),
  });

  function pick(metric: string, value: string) {
    const next = { ...chosen, [metric]: value };
    setChosen(next);
    onChange(vectorOf(next, versionOf(vector)));
  }

  const answered = METRICS.filter((m) => chosen[m.key]).length;

  return (
    <div className="field">
      <span className="l">Score</span>
      <p className="hint" style={{ marginTop: 0 }}>
        Optional. Leave it during early triage.
      </p>

      <div className="actions" style={{ margin: "4px 0 8px" }}>
        <button type="button" className="btn quiet" onClick={() => setOpen(!open)}>
          {open ? "Hide the metrics" : answered > 0 ? "Change the score" : "Work out a score"}
        </button>
        {vector !== "" && (
          <button
            type="button"
            className="btn quiet"
            onClick={() => {
              setChosen({});
              onChange("");
            }}
          >
            Clear it
          </button>
        )}
        {scored.data?.severity && (
          <span className="hint">
            <b>{scored.data.score?.toFixed(1)}</b> · {scored.data.severity}
          </span>
        )}
        {vector === "" && answered > 0 && (
          <span className="hint">{8 - answered} more to answer — a score needs all eight.</span>
        )}
      </div>

      {open && (
        <div className="fields">
          {METRICS.map((metric) => (
            <div className="field" key={metric.key}>
              <label htmlFor={`cvss-${metric.key}`}>
                {metric.label} <span className="hint">{metric.key}</span>
              </label>
              <select
                id={`cvss-${metric.key}`}
                value={chosen[metric.key] ?? ""}
                onChange={(event) => pick(metric.key, event.target.value)}
              >
                <option value="">{metric.help}</option>
                {metric.values.map((v) => (
                  <option key={v.value} value={v.value}>
                    {v.label}
                  </option>
                ))}
              </select>
            </div>
          ))}
        </div>
      )}

      {vector !== "" && (
        <p className="hint">
          <code>{vector}</code> — the vector is stored and the score is worked out from it.
        </p>
      )}
      {scored.isError && (
        <p className="hint" style={{ color: "var(--sev-high)" }}>
          That vector could not be scored.
        </p>
      )}
    </div>
  );
}
