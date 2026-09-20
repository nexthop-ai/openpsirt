import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { useReseed } from "./reseed";

// Composing a CVSS base vector, and showing what it scores.
//
// The score is worked out on the server, not here. The formula lives in
// one place and what somebody sees while choosing is what gets stored — a
// second copy in the browser is one that eventually disagrees with the number
// in the database, and the disagreement is invisible.
//
// Base metrics only. Temporal and environmental scores describe a moment
// and a deployment, and the deployment reading this is not the one the finding
// is about.

// A metric, its values, and what each value means in words.
//
// The words matter more than the letters: somebody rating a flaw for the first
// time is choosing between "over the network" and "physical access", not
// between N and P.
type Metric = {
  key: string;
  label: string;
  help: string;
  values: { value: string; label: string }[];
};

// The two metrics both generations ask the same way.
const ATTACK_VECTOR: Metric = {
  key: "AV",
  label: "Attack vector",
  help: "The attacker's position",
  values: [
    { value: "N", label: "Network — reachable remotely" },
    { value: "A", label: "Adjacent — same broadcast or shared segment" },
    { value: "L", label: "Local — a shell or a local account" },
    { value: "P", label: "Physical — hands on the device" },
  ],
};

const PRIVILEGES: Metric = {
  key: "PR",
  label: "Privileges required",
  help: "Access the attacker must already hold",
  values: [
    { value: "N", label: "None" },
    { value: "L", label: "Low — an ordinary account" },
    { value: "H", label: "High — administrative" },
  ],
};

// The metrics of a version 3 base vector.
const THREE: Metric[] = [
  ATTACK_VECTOR,
  {
    key: "AC",
    label: "Attack complexity",
    help: "Conditions outside the attacker's control",
    values: [
      { value: "L", label: "Low — it works whenever they try" },
      { value: "H", label: "High — depends on conditions they cannot arrange" },
    ],
  },
  PRIVILEGES,
  {
    key: "UI",
    label: "User interaction",
    help: "Action by somebody else",
    values: [
      { value: "N", label: "None" },
      { value: "R", label: "Required — a person has to act" },
    ],
  },
  {
    key: "S",
    label: "Scope",
    help: "Reach past the vulnerable thing",
    values: [
      { value: "U", label: "Unchanged — only the vulnerable component" },
      { value: "C", label: "Changed — it reaches beyond it" },
    ],
  },
  {
    key: "C",
    label: "Confidentiality",
    help: "Data that can be read",
    values: [
      { value: "H", label: "High — everything, or the part that matters" },
      { value: "L", label: "Low — something, but limited" },
      { value: "N", label: "None" },
    ],
  },
  {
    key: "I",
    label: "Integrity",
    help: "Data that can be changed",
    values: [
      { value: "H", label: "High" },
      { value: "L", label: "Low" },
      { value: "N", label: "None" },
    ],
  },
  {
    key: "A",
    label: "Availability",
    help: "Service that can be stopped",
    values: [
      { value: "H", label: "High" },
      { value: "L", label: "Low" },
      { value: "N", label: "None" },
    ],
  },
];

// The metrics of a version 4 base vector.
//
// Eleven rather than eight, and they are not the eight with three added: what
// version 3 asked once about impact, version 4 asks twice — once about the
// thing that is broken and once about what sits downstream of it.
const FOUR: Metric[] = [
  ATTACK_VECTOR,
  {
    key: "AC",
    label: "Attack complexity",
    help: "Defenses the attacker has to get past",
    values: [
      { value: "L", label: "Low — nothing to defeat" },
      { value: "H", label: "High — a built-in mitigation has to be defeated" },
    ],
  },
  {
    key: "AT",
    label: "Attack requirements",
    help: "Conditions the deployment has to be in",
    values: [
      { value: "N", label: "None — it works on any deployment" },
      { value: "P", label: "Present — it needs a particular state, or a race won" },
    ],
  },
  PRIVILEGES,
  {
    key: "UI",
    label: "User interaction",
    help: "Action by somebody else",
    values: [
      { value: "N", label: "None" },
      { value: "P", label: "Passive — somebody has to be using it" },
      { value: "A", label: "Active — somebody has to take the action" },
    ],
  },
  ...impact("V", "Vulnerable system", "the component itself"),
  ...impact("S", "Subsequent system", "whatever sits downstream of it"),
];

// The three impact metrics, which version 4 asks twice over.
function impact(of: string, subject: string, what: string): Metric[] {
  return [
    ["C", "confidentiality", "Data that can be read"],
    ["I", "integrity", "Data that can be changed"],
    ["A", "availability", "Service that can be stopped"],
  ].map(([letter, aspect, help]) => ({
    key: of + letter,
    label: `${subject} ${aspect}`,
    help: `${help} in ${what}`,
    values: [
      { value: "H", label: "High" },
      { value: "L", label: "Low" },
      { value: "N", label: "None" },
    ],
  }));
}

// The schemes a vector may be composed under, newest first.
//
// Version 3.0 and 3.1 share a base formula and score identically; version 4
// does not, and a number under one is not comparable with a number under the
// other. What they share is the band, which is why a list can hold both.
const SCHEMES: { version: string; metrics: Metric[] }[] = [
  { version: "CVSS:4.0", metrics: FOUR },
  { version: "CVSS:3.1", metrics: THREE },
  { version: "CVSS:3.0", metrics: THREE },
];

// The scheme a new assessment is composed under unless somebody picks another.
//
// Not the newest one. A published advisory is a CSAF 2.0 document, whose score
// object has a field for a version 3 score and none for a version 4 score, so
// a flaw assessed under version 4 publishes without one. Version 4 is offered
// and the screen says what choosing it costs.
const DEFAULT = "CVSS:3.1";

// The metrics one scheme states.
export function metricsOf(version: string): Metric[] {
  return SCHEMES.find((s) => s.version === version)?.metrics ?? THREE;
}

// The metrics only one of the two generations has, which is what tells them
// apart when a vector states no scheme.
const TELLS = [
  { version: "CVSS:4.0", keys: ["AT", "VC", "VI", "VA", "SC", "SI", "SA"] },
  { version: DEFAULT, keys: ["S", "C", "I", "A"] },
];

// versionOf is the scheme a vector is on.
//
// Kept through an edit. Re-stamping a vector recorded under 3.0 as 3.1 because
// somebody changed one metric rewrites what the original assessment claimed,
// and it is silent — the score does not move, because the formula did not.
//
// A vector stating no scheme is read for the metrics that belong to one
// generation and not the other. Stamping it with a default instead labels a
// version 4 vector as version 3, which is a score under a formula that never
// produced it.
export function versionOf(vector: string): string {
  const stated = vector.toUpperCase().split("/")[0] ?? "";
  if (SCHEMES.some((s) => s.version === stated)) return stated;
  const chosen = read(vector);
  for (const tell of TELLS) {
    if (tell.keys.some((key) => chosen[key])) return tell.version;
  }
  return DEFAULT;
}

// vectorOf assembles what has been chosen, or nothing until every metric of
// the scheme is answered.
//
// Nothing rather than a partial vector: one metric unanswered is not a base
// vector, and a score from the rest would be a number nobody could reproduce.
export function vectorOf(chosen: Record<string, string>, under: string): string {
  const metrics = metricsOf(under);
  const parts = metrics.map((m) => chosen[m.key]);
  if (parts.some((p) => !p)) return "";
  return under + "/" + metrics.map((m, i) => `${m.key}:${parts[i]}`).join("/");
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
  // The scheme being composed under, which an empty form does not get from a
  // vector. Held here so that picking one opens the right metrics before any
  // of them are answered.
  const [version, setVersion] = useState(() => versionOf(vector));

  // Kept in step with whatever the caller holds, so that a vector pasted in
  // whole lights up the metrics it states. Re-seeded rather than remounted:
  // picking the last metric completes the vector, and a remount would collapse
  // the metric list at the moment somebody finished with it.
  useReseed(vector, () => {
    setChosen(read(vector));
    if (vector !== "") setVersion(versionOf(vector));
  });

  const scored = useQuery({
    queryKey: ["score", vector],
    enabled: vector !== "",
    queryFn: async () => unwrap(await api.GET("/v1/score", { params: { query: { vector } } })),
  });

  const metrics = metricsOf(version);

  function pick(metric: string, value: string) {
    const next = { ...chosen, [metric]: value };
    setChosen(next);
    onChange(vectorOf(next, version));
  }

  // Changing the scheme keeps the answers the new one also asks for. The two
  // generations share five metrics and ask the rest differently, so what
  // carries over is what means the same thing in both.
  function compose(under: string) {
    const keeps = new Set(metricsOf(under).map((m) => m.key));
    const next: Record<string, string> = {};
    for (const [metric, value] of Object.entries(chosen)) {
      if (keeps.has(metric)) next[metric] = value;
    }
    setVersion(under);
    setChosen(next);
    onChange(vectorOf(next, under));
    setOpen(true);
  }

  const answered = metrics.filter((m) => chosen[m.key]).length;
  const left = metrics.length - answered;

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
          <span className="hint">
            {left} more to answer — a score needs all {metrics.length}.
          </span>
        )}
      </div>

      {open && (
        <div className="fields">
          <div className="field">
            <label htmlFor="cvss-version">Scheme</label>
            <select
              id="cvss-version"
              value={version}
              onChange={(event) => compose(event.target.value)}
            >
              {SCHEMES.map((scheme) => (
                <option key={scheme.version} value={scheme.version}>
                  {scheme.version.replace("CVSS:", "CVSS ")}
                </option>
              ))}
            </select>
            {version === "CVSS:4.0" && (
              <p className="hint">
                Published advisories carry no score under 4.0. CSAF 2.0 has a field for a 3.x score
                and none for a 4.0 one.
              </p>
            )}
          </div>
          {metrics.map((metric) => (
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
