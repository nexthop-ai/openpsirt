import { notACredential } from "../ui/noautofill";
import { useState } from "react";
import { Loading } from "../ui/Loading";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";
import { composable, humane, read, write, UNITS, type Unit } from "./duration";
import { humaneBytes, readBytes, writeBytes, SIZES, type Size } from "./bytes";

// What this deployment has decided for everybody in it, grouped the way the
// mockup groups them. Every setting the server exposes renders; a setting no
// group names lands under "Other", so nothing offered is hidden.
export function Settings() {
  const queries = useQueryClient();
  const settings = useQuery({
    queryKey: ["settings"],
    queryFn: async () => unwrap(await api.GET("/v1/settings", {})),
  });

  const set = useMutation({
    mutationFn: async ({ name, value }: { name: string; value: string }) =>
      unwrap(await api.PUT("/v1/settings/{name}", { params: { path: { name } }, body: { value } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["settings"] }),
  });

  if (settings.isPending) return <Loading />;
  if (settings.isError) {
    return <Failed error={settings.error} what="The settings could not be read." />;
  }

  const items = settings.data?.items ?? [];
  const named = new Set<string>();
  const group = (test: (name: string) => boolean) =>
    items.filter((each) => {
      const name = each.name ?? "";
      if (named.has(name) || !test(name)) return false;
      named.add(name);
      return true;
    });
  const deadlines = group((name) => name.startsWith("remediation.due."));
  const floor = group((name) => name === "triage.floor");
  const threshold = group(
    (name) => name === "triage.deferral-threshold" || name === "triage.together-cap",
  );
  // The four periods after which work that has not moved is reported. One
  // card, because they are one question asked four ways and the answer to each
  // depends on the others: a deployment that approves weekly wants all four
  // longer.
  const stale = group((name) =>
    [
      "triage.waiting-after",
      "triage.sent-back-after",
      "triage.deferral-lead",
      "triage.queued-after",
    ].includes(name),
  );
  const rest = group(() => true);

  const field = (each: (typeof items)[number]) => (
    <Field
      key={each.name}
      setting={each}
      onSet={(value) => set.mutate({ name: each.name ?? "", value })}
    />
  );

  return (
    <>
      <div className="screen-head">
        <h2>Settings</h2>
        <p>Applies to everyone.</p>
      </div>

      {set.error != null && <Failed error={set.error} what="That could not be recorded." />}

      {deadlines.length > 0 && (
        <div className="card" style={{ marginBottom: 14 }}>
          <h3>Remediation deadlines</h3>
          <div style={{ display: "flex", gap: 18, flexWrap: "wrap", alignItems: "flex-end" }}>
            {deadlines.map(field)}
          </div>
          <p className="reading" style={{ marginTop: 10 }}>
            Counted from when a finding was first seen. Exploited findings use their own window.
          </p>
        </div>
      )}

      {floor.length > 0 && (
        <div className="card" style={{ marginBottom: 14 }}>
          <h3>Severity floor</h3>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "flex-end" }}>
            {floor.map(field)}
          </div>
          <p className="reading" style={{ marginTop: 10 }}>
            Applies to every shared figure. Below the line, nothing has a deadline.
          </p>
        </div>
      )}

      {threshold.length > 0 && (
        <div className="card" style={{ marginBottom: 14 }}>
          <h3>Approval thresholds</h3>
          <div style={{ display: "flex", gap: 18, flexWrap: "wrap", alignItems: "flex-end" }}>
            {threshold.map(field)}
          </div>
          <p className="reading" style={{ marginTop: 10 }}>
            Measured against the total already deferred. A bulk decision always needs a second
            person, and is bounded.
          </p>
        </div>
      )}

      {stale.length > 0 && (
        <div className="card" style={{ marginBottom: 14 }}>
          <h3>Stalled work reminders</h3>
          <div className="filters">{stale.map(field)}</div>
          <p className="reading" style={{ marginTop: 10 }}>
            Derived rather than sent, because nothing happening raises no event. Each clears when
            the thing finally happens.
          </p>
        </div>
      )}

      {rest.map((each) => (
        <div className="card" key={each.name} style={{ marginBottom: 14 }}>
          <h3>{title(each.name)}</h3>
          {field(each)}
          <p className="reading" style={{ marginTop: 10 }}>
            {each.means}
          </p>
        </div>
      ))}

      <p className="hint">Defaults, not recommendations. Zero or negative is refused.</p>
    </>
  );
}

// What a setting is called. A noun phrase naming the thing, the way a settings
// screen anywhere else names one — not a description of the situation it
// governs. What it does and why is the paragraph underneath, which is where a
// reader looks second.
function title(name?: string): string {
  switch (name) {
    case "session.lifetime":
      return "Session lifetime";
    case "token.max-lifetime":
      return "Personal token lifetime";
    case "signin.claim-window":
      return "Authorization redemption window";
    case "upstream.currency":
      return "Upstream version checks";
    case "scanning.quiet-after":
      return "Quiet build threshold";
    case "scanning.every":
      return "Rescan interval";
    case "attachment.max-size":
      return "Maximum attachment size";
    case "attachment.quota":
      return "Total attachment storage";
    case "attachment.per-person-quota":
      return "Attachment storage per person";
    case "queue.backlog":
      return "Queued work limit";
    case "routing.batch":
      return "Findings placed per pass";
    case "people.absent-after":
      return "Inactive account threshold";
    // These three fell through to the last segment of the key, which named
    // one of them "After" — a card heading that says nothing at all about
    // what is being set.
    case "disclosure.after":
      return "Default embargo period";
    case "disclosure.extension-threshold":
      return "Embargo extension threshold";
    case "disclosure.lead-time":
      return "Embargo expiry warning";
    default:
      return (
        (name ?? "")
          .split(".")
          .pop()
          ?.replace(/-/g, " ")
          .replace(/^\w/, (c) => c.toUpperCase()) ?? ""
      );
  }
}

// The same rule for a field inside a group: the name of the value, not a
// description of when it applies.
function label(name?: string): string {
  switch (name) {
    case "triage.waiting-after":
      return "Awaiting approval";
    case "triage.sent-back-after":
      return "Returned, untouched";
    case "triage.deferral-lead":
      return "Deferral expiry warning";
    case "triage.queued-after":
      return "Unclaimed in a team queue";
    case "triage.together-cap":
      return "Bulk claim limit";
    case "triage.floor":
      return "Minimum severity";
    case "triage.deferral-threshold":
      return "Second approver above";
    default:
      return ((name ?? "").split(".").pop() ?? "").replace(/-/g, " ");
  }
}

// What a value is, and what it may be, come from the server.
//
// They were three tables here keyed on setting names, beside the server's own
// — five copies of one fact. A setting added to the server and not to these
// was offered as a text field somebody typed a refused value into, and a word
// list that drifted offered a word the write path refuses. The server is what
// checks the value, so the server is what says what it is.

function Field({
  setting,
  onSet,
}: {
  setting: {
    name?: string;
    value?: string;
    default?: boolean;
    means?: string;
    kind: "duration" | "count" | "size" | "word" | "switch";
    words?: string[] | null;
  };
  onSet: (value: string) => void;
}) {
  const [value, setValue] = useState(setting.value ?? "");
  const words = setting.words;
  const timed = setting.kind === "duration";
  // A duration this can compose. Where it cannot — somebody set "90m" from a
  // script, and they meant it — the text field stays, because a control that
  // can only say whole hours must not offer to edit one of those.
  const composed = timed ? read(setting.value ?? "") : null;
  // A setting nobody has set is composed too. Nothing to read is not a value
  // the composer refuses, and the text box it used to fall to is the one
  // control that cannot say which unit a number is in — the embargo periods
  // arrive unset, so that is the state they are first seen in.
  const takes = timed && composable(setting.value ?? "");
  // The same composition for a size, where the setting is one.
  const measured = setting.kind === "size" ? readBytes(setting.value ?? "") : null;

  // **The number and the unit are held as typed, not re-derived.**
  //
  // Both composers used to write the canonical value on every keystroke and
  // read the control back out of it, which is three bugs in one gesture.
  // Clearing the box made it empty, which is zero, which the writer floors at
  // one — so the first character could not be deleted. Typing a number that
  // divides differently flipped the unit underneath the cursor: 7 in days is
  // 168 hours, and the largest unit that divides that is a week, so the box
  // said 1 and the select said weeks while somebody was still typing. And a
  // double-click to replace the number selected a value that changed as soon
  // as the first digit landed.
  //
  // So the two controls hold what they were given, empty included, and the
  // canonical form is worked out once, when it is saved.
  const [count, setCount] = useState(() =>
    composed ? String(composed.count) : measured ? String(measured.count) : "",
  );
  // Days where there is nothing to read. A period nobody has set yet is an
  // embargo, which is said in days everywhere it is written down, and hours
  // would read a typed 90 as under four days.
  const [unit, setUnit] = useState<Unit>(composed ? composed.unit : "days");
  const [size, setSize] = useState<Size>(measured ? measured.unit : SIZES[0].unit);

  // What would be stored, from whatever the controls are showing. A box left
  // empty is not a value: saving is refused rather than a number invented for
  // somebody.
  const typed = Number(count);
  const usable = count.trim() !== "" && Number.isFinite(typed) && typed >= 1;
  const asked = takes
    ? usable
      ? write(typed, unit)
      : ""
    : measured
      ? usable
        ? writeBytes(typed, size)
        : ""
      : value;
  const changed = asked !== "" && asked !== (setting.value ?? "");

  return (
    <div className="field" style={{ margin: 0, maxWidth: takes || measured ? 320 : 240 }}>
      {/* The sentence sits on the label rather than on the control. A
          password manager classifies a field by the words it can reach
          through it, and what a setting means is prose about sign-ins,
          accounts and dates — which is how three of these came to be offered
          a saved login despite saying they were not credentials. */}
      <label htmlFor={setting.name} title={setting.means}>
        {label(setting.name)}
        {setting.default && <span className="hint"> · default</span>}
      </label>
      <div style={{ display: "flex", gap: 6 }}>
        {words ? (
          <select
            id={setting.name}
            name="setting"
            {...notACredential}
            value={value}
            onChange={(event) => setValue(event.target.value)}
          >
            {words.map((word) => (
              <option key={word} value={word}>
                {word}
              </option>
            ))}
          </select>
        ) : takes ? (
          <>
            <input
              id={setting.name}
              name="setting"
              {...notACredential}
              type="number"
              min={1}
              style={{ width: 90 }}
              value={count}
              onChange={(event) => setCount(event.target.value)}
            />
            <select
              aria-label={`${label(setting.name)} unit`}
              name="unit"
              {...notACredential}
              style={{ width: "auto" }}
              value={unit}
              onChange={(event) => setUnit(event.target.value as Unit)}
            >
              {UNITS.map((each) => (
                <option key={each.unit} value={each.unit}>
                  {each.unit}
                </option>
              ))}
            </select>
          </>
        ) : measured ? (
          <>
            <input
              id={setting.name}
              name="setting"
              {...notACredential}
              type="number"
              min={1}
              style={{ width: 90 }}
              value={count}
              onChange={(event) => setCount(event.target.value)}
            />
            <select
              aria-label={`${label(setting.name)} unit`}
              name="unit"
              {...notACredential}
              style={{ width: "auto" }}
              value={size}
              onChange={(event) => setSize(event.target.value as Size)}
            >
              {SIZES.map((each) => (
                <option key={each.unit} value={each.unit}>
                  {each.unit}
                </option>
              ))}
            </select>
          </>
        ) : (
          <input
            id={setting.name}
            name="setting"
            {...notACredential}
            type="text"
            value={value}
            onChange={(event) => setValue(event.target.value)}
          />
        )}
        {changed && (
          <button type="button" className="btn" onClick={() => onSet(asked)}>
            Save
          </button>
        )}
      </div>
      {/* Said in words only where the control could not say it. A composer
          showing "30 days" and then "stored as 720h" underneath is telling
          somebody the storage format of a thing they just chose in the unit
          they chose it in, which is arithmetic nobody asked for. A value the
          composer cannot take is the case that needs the sentence: it sits in
          a plain text field, and what it means is not obvious. */}
      {!takes && !measured && !words && humane(value) && (
        <span className="hint">= {humane(value)}</span>
      )}
      {!measured && setting.kind === "size" && humaneBytes(value) && (
        <span className="hint">= {humaneBytes(value)}</span>
      )}
      {(takes || measured) && count.trim() !== "" && !usable && (
        <span className="hint" style={{ color: "var(--sev-high)" }}>
          A whole number of one or more.
        </span>
      )}
    </div>
  );
}
