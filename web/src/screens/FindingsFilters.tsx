// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { FLOORS } from "../ui/severities";
import { labeled } from "../ui/Outcome";
import { notACredential } from "../ui/noautofill";
import { Choices } from "../ui/Choices";
import { Words } from "../ui/Words";
// The findings list's filters, apart from the list itself.
//
// Everything the server can narrow by is here, named for what it asks.
// The panel this replaced offered a third of them behind a "more" control, in
// a flat run of unlabeled boxes whose values read as phrases — "whatever it
// did", "any deadline", "anyone or nobody". Two of the filters people asked
// for most often, what upstream declined to fix and what somebody entered by
// hand, were already there and were not found: one was a word in an unlabeled
// dropdown and the other a chip that said "Recorded here". A filter nobody
// can find is a filter that is not there.
//
// A label says what it asks; a value says what it is. "Upstream fix: will
// not fix" rather than "Upstream: declined to fix". The words are the ones the
// domain uses, because somebody scanning for theirs has to find it in a
// second and a paraphrase that avoids naming the thing reads as a riddle.
//
// The active filters are visible without opening anything. Each is a
// chip above the list saying which filter and which value, and removing one is
// clicking it — which is the other half of the discoverability problem: a
// narrowed list that looks unnarrowed is how two people read the same screen
// and disagree about what it says.

// The groups, in the order somebody works through them: what it is, what
// upstream did, where we are with it, where it came from, what it sits in,
// and when.

// A floor is picked by asking "at least this bad", so the words run least
// first — which is what FLOORS is. Derived rather than listed here: written
// out, a rung added to the ladder was one this filter could not be set to.
//
// The label says what picking it means rather than naming the word again: the
// least of them is every finding there is, and the worst of them is only that
// one.
export const SEVERITIES = FLOORS.map((word, i) => [
  word,
  i === 0 ? "Any" : i === FLOORS.length - 1 ? "Critical only" : titled(word) + " and above",
]) as unknown as readonly (readonly [string, string])[];

// titled is a word as a label opens it.
function titled(word: string): string {
  return word.charAt(0).toUpperCase() + word.slice(1);
}

export const FIX_STATES = [
  ["", "Any"],
  ["fixed", "Fixed upstream"],
  ["none", "No fix released"],
  ["wont-fix", "Will not fix"],
  ["unknown", "Not stated"],
  ["mixed", "Differs between builds"],
] as const;

// How a group is spread over the variants of a branch. "Only this variant"
// is offered where one is named, because it is a question about that one.
export const SPREADS = [
  ["", "Any"],
  ["only", "Only this variant"],
  ["every", "Every variant"],
] as const;

export const STATES = [
  ["", "Any"],
  ["undecided", "Undecided"],
  ["waiting", "Pending approval"],
  ["agreed", "Decided"],
  ["lapsed", "Lapsed"],
] as const;

// The outcomes this filter offers, labeled from the one map rather than
// beside the tokens here: a second spelling of a word somebody picks and then
// reads back is how the two stop agreeing, which is what happened to the
// decision form's "Backport needed".
export const OUTCOMES: readonly (readonly [string, string])[] = [
  ["", "Any"],
  ...(
    [
      "affected",
      "not-applicable",
      "mismatched",
      "wont-fix",
      "deferred",
      "already-fixed",
      "upgrade-needed",
      "patch-needed",
    ] as const
  ).map((each) => [each, labeled(each)] as const),
];

export const ASSIGNED = [
  ["", "Any"],
  ["me", "Me or my team"],
  ["somebody", "Someone"],
  ["nobody", "No one"],
] as const;

export const PLANNED = [
  ["either", "Covered or not"],
  ["unplanned", "Not covered by a planned upgrade"],
  ["planned", "Covered by a planned upgrade"],
] as const;

// The sort of release, and its support. Two questions
// kept apart because they are two: a tag can be in support and a branch can be
// past its date.
export const RELEASES = [
  ["branch", "Branches"],
  ["tag", "Tags"],
] as const;

export const SUPPORT = [
  ["in-support", "In support"],
  ["past-eol", "Past end-of-life"],
] as const;

export const ORIGINS = [
  ["", "Any"],
  ["scanner", "Scanner"],
  ["manual", "Entered by hand"],
] as const;

export const VEX_STATUS = [
  ["", "Any"],
  ["not_affected", "Not affected"],
  ["affected", "Affected"],
  ["fixed", "Fixed"],
  ["under_investigation", "Under investigation"],
] as const;

export const DEADLINES = [
  ["", "Any"],
  ["overdue", "Overdue"],
  ["7", "Due within 7 days"],
  // A fortnight, because that is what the front page's "due soon" tile
  // navigates with. Absent here, the panel showed nothing chosen while the
  // list was narrowed — a filter in force that the reader could neither see
  // nor turn off.
  ["14", "Due within 14 days"],
  ["30", "Due within 30 days"],
  ["90", "Due within 90 days"],
] as const;

// The package kinds worth offering, most numerous first. The name is the one
// the package identifier spells, with the language beside it where they differ
// — Rust is cargo and Python is pypi, and somebody looking for one of those
// searches for the language.
//
// The server takes an open set, and this is the offered part of it. The filter
// carries whatever string arrives and matches the identifier against it, so
// this list bounds the picker rather than the question — and a list short of
// what an image actually holds is a capability that exists and cannot be
// reached. `apk` and `rpm` were missing from it, so on an Alpine or RPM image
// the majority of the inventory could not be narrowed to at all, while the
// server would have answered either correctly.
//
// A kind this does not list is still askable: the address carries it, the
// server matches it, and the chip above the list labels it with the word
// itself. What it has no way to do is offer it, and the durable answer to that
// is the kinds actually present travelling with the read rather than a longer
// list here — which is a question the server does not answer yet.
export const ECOSYSTEMS = [
  ["", "Any"],
  ["generic", "Generic"],
  ["golang", "Go (golang)"],
  ["deb", "Debian (deb)"],
  ["rpm", "RPM"],
  ["apk", "Alpine (apk)"],
  ["cargo", "Rust (cargo)"],
  ["pypi", "Python (pypi)"],
  ["npm", "npm"],
  ["gem", "Ruby (gem)"],
  ["oci", "Container image (oci)"],
  ["github", "GitHub"],
  ["maven", "Maven"],
] as const;

// The scopes a producer may state for a dependency, in the two formats' own
// words.
//
// Two vocabularies rather than one, and they are not folded together: a
// CycloneDX component scope and an SPDX lifecycle scope say related things in
// different words, and a label claiming they are the same word would be a
// reading the tool deliberately does not make. The label says which format the
// word comes from for the same reason.
export const DECLARED_AS = [
  ["required", "required (CycloneDX)"],
  ["optional", "optional (CycloneDX or SPDX)"],
  ["excluded", "excluded (CycloneDX)"],
  ["runtime", "runtime (SPDX)"],
  ["build", "build (SPDX)"],
  ["development", "development (SPDX)"],
  ["design", "design (SPDX)"],
  ["other", "other (SPDX)"],
] as const;

type Pairs = readonly (readonly [string, string])[];

function said(pairs: Pairs, value: string): string {
  return pairs.find(([each]) => each === value)?.[1] ?? value;
}

// One active filter, for the summary above the list: which filter, what it is
// set to, and what removing it means.
//
// A filter that takes several values is several of these, one per value, so
// removing one leaves the rest — which is the whole point of asking for two.
// The pairs say what to remove: a key with an empty word is the whole filter,
// a key with a word is that one value of it.
export type Active = {
  key: string;
  label: string;
  value: string;
  clears: [string, string][];
  // The words for a default, rather than silence. A filter the list applies
  // unless told otherwise cannot be turned off by deleting it — deleting it is
  // how the address asks for the default — so removing that chip writes the
  // word that means "ask for everything".
  then?: [string, string[]][];
};

// The filters narrowing the list right now. Read from the address rather than
// from the controls, so a filter set by a link somebody was sent shows up
// exactly like one set by clicking.
export function activeFilters(params: URLSearchParams): Active[] {
  const out: Active[] = [];
  const at = (key: string) => params.get(key) ?? "";
  const add = (key: string, label: string, value: string, clears?: [string, string][]) => {
    if (value) out.push({ key, label, value, clears: clears ?? [[key, ""]] });
  };

  add("q", "Text", at("q"));
  if (at("floor") && at("floor") !== "low") {
    add("floor", "Severity", said(SEVERITIES, at("floor")));
  }
  // Every one below reads the raw value first. `said` answers "Any" for an
  // empty one, which is a label rather than a value — taken as the test, it
  // reported seven dropdowns as narrowing a list none of them touched.
  const pick = (key: string, label: string, pairs: Pairs) => {
    if (at(key)) add(key, label, said(pairs, at(key)));
  };
  if (at("below") === "yes") add("below", "Below the triage line", "included");
  if (at("exploited") === "1" || at("only") === "exploited") {
    out.push({
      key: "exploited",
      label: "Known exploited",
      value: "only",
      clears: [
        ["exploited", ""],
        ["only", ""],
      ],
    });
  }
  if (at("fixable") === "1" || at("only") === "hasFix") {
    out.push({
      key: "fixable",
      label: "Fix version known",
      value: "only",
      clears: [
        ["fixable", ""],
        ["only", ""],
      ],
    });
  }
  add(
    "epss_at_least",
    "Exploit likelihood",
    at("epss_at_least") && `at least ${at("epss_at_least")}`,
  );
  // The four that take several values, one chip each. Chipped by value rather
  // than as "3 chosen", because a summary somebody cannot act on sends them
  // back into the panel to find out what it means.
  const each = (key: string, label: string, pairs: Pairs) => {
    for (const value of params.getAll(key).filter(Boolean)) {
      out.push({ key, label, value: said(pairs, value), clears: [[key, value]] });
    }
  };
  each("fix_state", "Upstream fix", FIX_STATES);
  each("state", "Decision state", STATES);
  each("outcome", "Decision outcome", OUTCOMES);
  if (at("sent_back") === "1") add("sent_back", "Sent back to its author", "only");
  if (at("planned") && at("planned") !== "either") {
    out.push({
      key: "planned",
      label: "Planned upgrade",
      value: said(PLANNED, at("planned")),
      clears: [["planned", ""]],
      then: [["planned", ["either"]]],
    });
  }
  // Drawn whenever the answer is one of the two rather than both, which
  // includes the default — a default that narrows silently makes the count
  // something other than the whole count with nothing saying so. Removing the
  // chip widens to both rather than deleting the parameter, because deleting
  // it is how the address asks for the default back.
  const oneOf = (key: string, label: string, pairs: Pairs, both: string[]) => {
    const chosen = params.getAll(key).filter(Boolean);
    if (chosen.length !== 1) return;
    out.push({
      key,
      label,
      value: said(pairs, chosen[0] ?? ""),
      clears: [[key, ""]],
      then: [[key, both]],
    });
  };
  oneOf("on", "Release", RELEASES, ["branch", "tag"]);
  oneOf("support", "Support", SUPPORT, ["in-support", "past-eol"]);
  each("assigned", "Assigned to", ASSIGNED);
  if (at("reassessed") === "1") add("reassessed", "Rated differently here", "only");
  // Not oneOf: `on` and `support` are read off the address with getAll, so
  // naming both values means both, and origin is a single enum the reader
  // takes with get — the both-values spelling came back as "scanner" alone and
  // clearing the chip hid every hand-recorded finding with nothing left saying
  // so. Leaving the parameter out already means both, on the wire and here.
  pick("origin", "Origin", ORIGINS);
  if (at("unconfirmed") === "1") add("unconfirmed", "Not confirmed by a packager", "only");
  each("vex_publisher", "VEX publisher", []);
  each("vex_status", "VEX status", VEX_STATUS);
  each("component", "Component", []);
  each("ecosystem", "Package type", ECOSYSTEMS);
  each("declared_as", "Producer said", DECLARED_AS);
  add("under", "Inside container", at("under"));
  add("beneath", "At or under", at("beneath"));
  if (at("under_build") === "yes") add("under_build", "Held directly by the build", "only");
  // One chip per component hidden, and the page has no second list of them:
  // hiding drew its own row saying the same names the summary already said,
  // so removing one was two controls doing one thing in two places.
  each("hide", "Excluding", []);
  pick("running", "Deadline", DEADLINES);
  add("open_for", "Open for", at("open_for") && `${at("open_for")} days or more`);
  add("opened_after", "First seen after", at("opened_after"));
  // A chip rather than a control in the panel: nobody types a run identifier,
  // and what puts it in the address is a link from the run that reports it.
  // It removes itself like every other chip, which is how somebody arriving
  // from that link widens back out to the whole build.
  add("opened_by_run", "Opened by run", at("opened_by_run"));
  add("proposed_after", "Claimed after", at("proposed_after"));
  add("closed_after", "Closed after", at("closed_after"));
  each("weakness", "Weakness", []);
  each("tag", "Tag", []);
  if (at("differs") === "1") add("differs", "Differs between builds", "only");
  add(
    "variants",
    "Across variants",
    SPREADS.find(([word]) => word !== "" && word === at("variants"))?.[1].toLowerCase() ?? "",
  );
  return out;
}

// The address with one chip's filter removed. A pair naming a word removes
// that word alone, because a filter asked for twice is two chips and clicking
// one of them must leave the other standing.
export function without(params: URLSearchParams, chip: Active): URLSearchParams {
  const next = new URLSearchParams(params);
  for (const [key, value] of chip.clears) {
    if (!value) {
      next.delete(key);
      continue;
    }
    const left = next.getAll(key).filter((each) => each !== value);
    next.delete(key);
    for (const each of left) next.append(key, each);
  }
  for (const [key, values] of chip.then ?? []) {
    next.delete(key);
    for (const value of values) next.append(key, value);
  }
  return next;
}

// The address with every filter removed, which is every chip's own removal
// applied in turn — so a filter the summary does not name is not silently
// cleared by "clear all" either.
export function withoutAny(params: URLSearchParams): URLSearchParams {
  let next = params;
  for (const each of activeFilters(params)) next = without(next, each);
  return next;
}

// A labeled control. Every filter has one: the panel this replaced left half
// of them to be identified by their values, which is what made two of them
// invisible to somebody looking straight at them.
function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="field" title={hint}>
      <span>{label}</span>
      {children}
    </label>
  );
}

function Pick({
  label,
  hint,
  value,
  options,
  onChange,
  disabled,
}: {
  label: string;
  hint?: string;
  value: string;
  options: Pairs;
  onChange: (value: string) => void;
  disabled?: boolean;
}) {
  return (
    <Field label={label} hint={hint}>
      <select value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)}>
        {options.map(([each, says]) => (
          <option key={each} value={each}>
            {says}
          </option>
        ))}
      </select>
    </Field>
  );
}

function Flag({
  label,
  hint,
  on,
  onChange,
  disabled,
}: {
  label: string;
  hint?: string;
  on: boolean;
  onChange: (on: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <label className="check" title={hint}>
      <input
        type="checkbox"
        checked={on}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
      />
      <span>{label}</span>
    </label>
  );
}

function Group({ legend, children }: { legend: string; children: React.ReactNode }) {
  return (
    <fieldset className="filtergroup">
      <legend>{legend}</legend>
      <div className="filterset">{children}</div>
    </fieldset>
  );
}

// The whole panel. What it can offer depends on where it is: a subtree and
// "differs between builds" are statements about one build's edges and one
// selection, so they are absent rather than dead where there is no build to
// walk, and a VEX publisher or a tag is a per-product list.
export function Filters({
  params,
  set,
  setEach,
  setMany,
  tags,
  oneBuild,
  spanning,
  variantNamed,
}: {
  params: URLSearchParams;
  set: (key: string, value: string) => void;
  // Several filters in one act. Two `set` calls in a row each build their
  // change from the same parameters, so the second writes over the first.
  setEach: (changes: Record<string, string>) => void;
  // The filters that take several values at once. Separate from `set` rather
  // than a set taking an array, because the address carries them as a repeated
  // parameter and replacing one word is not the same act as replacing all of
  // them.
  setMany: (key: string, values: string[]) => void;
  tags: string[];
  oneBuild: boolean;
  spanning: boolean;
  // Whether the selection names a variant, which is what "only this
  // variant" is about.
  variantNamed: boolean;
}) {
  const at = (key: string) => params.get(key) ?? "";
  const all = (key: string) => params.getAll(key).filter(Boolean);
  const flag = (key: string, on: boolean) => set(key, on ? "1" : "");

  return (
    <div className="filterpanel">
      <Group legend="Severity and risk">
        <Pick
          label="Minimum severity"
          value={at("floor") || "low"}
          options={SEVERITIES}
          onChange={(value) => set("floor", value === "low" ? "" : value)}
        />
        <Field label="Exploit likelihood at least" hint="The published EPSS estimate, 0 to 1">
          <input
            {...notACredential}
            type="number"
            min={0}
            max={1}
            step={0.05}
            value={at("epss_at_least")}
            onChange={(event) => set("epss_at_least", event.target.value)}
          />
        </Field>
        <Flag
          label="Known exploited"
          hint="Somebody is known to be exploiting this"
          on={at("exploited") === "1" || at("only") === "exploited"}
          onChange={(on) => setEach({ only: "", exploited: on ? "1" : "" })}
        />
        <Flag
          label="Include below the triage line"
          hint="Always recorded and counted"
          on={at("below") === "yes"}
          onChange={(on) => set("below", on ? "yes" : "")}
        />
      </Group>

      <Group legend="Upstream fix">
        <Choices
          label="Fix status"
          hint="Upstream's own answer"
          chosen={all("fix_state")}
          options={FIX_STATES}
          onChange={(chosen) => setMany("fix_state", chosen)}
        />
        <Flag
          label="Fix version known"
          hint="An upstream fixed version is recorded"
          on={at("fixable") === "1" || at("only") === "hasFix"}
          onChange={(on) => setEach({ only: "", fixable: on ? "1" : "" })}
        />
        <Flag
          label="Not confirmed by a packager"
          hint="Matched on a version range, not a packager advisory"
          on={at("unconfirmed") === "1"}
          onChange={(on) => flag("unconfirmed", on)}
        />
      </Group>

      <Group legend="Triage">
        {/* Also above the list, because it is the first thing most people
            narrow by. Both controls read and write the same address, so
            whichever is used the other says the same thing. */}
        <Choices
          label="Decision state"
          hint="Anything unfinished"
          chosen={all("state")}
          options={STATES}
          onChange={(chosen) => setMany("state", chosen)}
        />
        <Choices
          label="Decision outcome"
          hint="The outcome that stands"
          chosen={all("outcome")}
          options={OUTCOMES}
          onChange={(chosen) => setMany("outcome", chosen)}
        />
        <Choices
          label="Assigned to"
          hint="Mine and unassigned together"
          chosen={all("assigned")}
          options={ASSIGNED}
          onChange={(chosen) => setMany("assigned", chosen)}
        />
        <Flag
          label="Sent back to its author"
          on={at("sent_back") === "1"}
          onChange={(on) => flag("sent_back", on)}
        />
        {/* Derived from the decisions rather than stored, so withdrawing a
            promise puts what it covered back with nothing to clean up. */}
        <Pick
          label="Planned upgrade"
          hint="Findings a promised upgrade already covers"
          value={at("planned") || "either"}
          options={PLANNED}
          onChange={(value) => set("planned", value)}
        />
        <Flag
          label="Rated differently here than by the world"
          on={at("reassessed") === "1"}
          onChange={(on) => flag("reassessed", on)}
        />
      </Group>

      <Group legend="Origin">
        <Pick
          label="Recorded by"
          hint="Only manually entered flaws can be closed by hand"
          value={at("origin")}
          options={ORIGINS}
          onChange={(value) => set("origin", value)}
        />
        <Words
          label="VEX publisher"
          hint="Publisher of the VEX document. Enter adds one"
          placeholder="debian"
          words={all("vex_publisher")}
          onChange={(words) => setMany("vex_publisher", words)}
        />
        <Choices
          label="VEX status"
          hint="VEX status. With a publisher, both must match"
          chosen={all("vex_status")}
          options={VEX_STATUS}
          onChange={(chosen) => setMany("vex_status", chosen)}
        />
      </Group>

      {/* What the list is a work list of. No work lands in a tag whatever
          anybody decides about it, and none lands in a release past
          end-of-life either — so both default to the working population and
          both say so in a chip above the list. Two controls rather than one,
          because a tag can be in support and a branch can be past its date. */}
      {/* Cleared means the key goes, not both values written in.
          Both of these default to the working population when the address is
          silent, and the default is applied only where the key is absent — so
          writing "branch and tag" to mean "I have not narrowed this" made the
          address say something, suppressed the default, and quietly widened the
          list. There was then no way to express from this panel what the rail's
          own address says, which is how one screen came to disagree with the
          number that opened it. */}
      <Group legend="Release">
        <Choices
          label="Release kind"
          hint="Tags are built once, so no work lands in them"
          anything="Branches and tags"
          chosen={all("on")}
          options={RELEASES}
          onChange={(chosen) => setMany("on", chosen)}
        />
        <Choices
          label="Support"
          hint="End-of-life date, from the release or the product"
          anything="Whatever its support"
          chosen={all("support")}
          options={SUPPORT}
          onChange={(chosen) => setMany("support", chosen)}
        />
      </Group>

      <Group legend="Component">
        <Words
          label="Component name"
          hint="Exact package name, any version. Enter adds one"
          placeholder="openssl"
          words={all("component")}
          onChange={(words) => setMany("component", words)}
        />
        <Choices
          label="Package type"
          chosen={all("ecosystem")}
          options={ECOSYSTEMS}
          onChange={(chosen) => setMany("ecosystem", chosen)}
        />
        <Choices
          label="Producer said"
          hint="What the inventory called the dependency. Nothing here ranks or decides by it"
          chosen={all("declared_as")}
          options={DECLARED_AS}
          onChange={(chosen) => setMany("declared_as", chosen)}
        />
        <Field label="Inside container">
          <input
            {...notACredential}
            type="text"
            value={at("under")}
            disabled={at("under_build") === "yes"}
            placeholder="a container, by name"
            onChange={(event) => set("under", event.target.value)}
          />
        </Field>
        <Flag
          label="Held directly by the build"
          hint="Components with no container above them"
          on={at("under_build") === "yes"}
          onChange={(on) => set("under_build", on ? "yes" : "")}
        />
        {oneBuild && (
          <Field label="At or under" hint="The component and everything beneath it">
            <input
              {...notACredential}
              type="text"
              value={at("beneath")}
              placeholder="a component, by name"
              onChange={(event) => set("beneath", event.target.value)}
            />
          </Field>
        )}
      </Group>

      <Group legend="Timing">
        <Pick
          label="Deadline"
          value={at("running")}
          options={DEADLINES}
          onChange={(value) => set("running", value)}
        />
        <Field label="Open for at least" hint="Days since first seen">
          <input
            {...notACredential}
            type="number"
            min={1}
            value={at("open_for")}
            onChange={(event) => set("open_for", event.target.value)}
          />
        </Field>
        <Field label="First seen after">
          <input
            type="date"
            value={at("opened_after")}
            onChange={(event) => set("opened_after", event.target.value)}
          />
        </Field>
        <Field label="Claimed after">
          <input
            type="date"
            value={at("proposed_after")}
            onChange={(event) => set("proposed_after", event.target.value)}
          />
        </Field>
        <Field label="Closed after" hint="Includes closed findings">
          <input
            type="date"
            value={at("closed_after")}
            onChange={(event) => set("closed_after", event.target.value)}
          />
        </Field>
      </Group>

      <Group legend="Other">
        <Words
          label="Weakness"
          hint="Kinds of flaw, by CWE identifier. A class is usually several"
          placeholder="CWE-79"
          words={all("weakness")}
          onChange={(words) => setMany("weakness", words)}
        />
        <Words
          label="Tag"
          hint="Words somebody tagged findings with here. Any of them"
          words={all("tag")}
          onChange={(words) => setMany("tag", words)}
          offered={tags}
          listId="findings-tags"
        />
        {!spanning && !oneBuild && (
          <Flag
            label="Differs between builds"
            hint="Open in some builds of this selection and not others"
            on={at("differs") === "1"}
            onChange={(on) => flag("differs", on)}
          />
        )}
        {!spanning && (
          <Pick
            label="Across variants"
            hint={
              variantNamed
                ? "What no other variant on the same branch has, or what every variant has"
                : "What every variant on the branch has. Pick a variant to ask what is specific to it"
            }
            value={at("variants")}
            options={variantNamed ? SPREADS : SPREADS.filter(([word]) => word !== "only")}
            onChange={(value) => set("variants", value)}
          />
        )}
      </Group>
    </div>
  );
}

// The filters narrowing the list, above the list, whether or not the panel is
// open. Each says which filter and what it is set to, and clicking one removes
// it — so what is on can be read and undone without opening anything.
export function Narrowed({
  params,
  scope,
  widen,
  clear,
  clearAll,
}: {
  params: URLSearchParams;
  // The narrowing the selection puts on this list, which is a filter like any
  // other and was the one that did not say so. It rides on the path rather
  // than in the parameters, so it drew no chip — and a list scoped to one
  // product sat under filters identical to the list across every product,
  // counting fewer rows, with nothing on the screen to explain the
  // difference. The rule the three implicit filters are written into the
  // address for is the same rule: a list that narrows itself and does not say
  // so is how two people read one screen and disagree about what it holds.
  scope: { product: string; stream: string; variant: string };
  // Widening by a level. Removing a scope chip only ever widens, like every
  // other chip here.
  widen: (to: { product: string; stream: string; variant: string }) => void;
  clear: (chip: Active) => void;
  clearAll: () => void;
}) {
  const active = activeFilters(params);
  const where: { label: string; value: string; to: typeof scope }[] = [];
  if (scope.product) {
    where.push({
      label: "Product",
      value: scope.product,
      to: { product: "", stream: "", variant: "" },
    });
    if (scope.stream) {
      where.push({
        label: "Branch or tag",
        value: scope.stream,
        to: { product: scope.product, stream: "", variant: "" },
      });
    }
    if (scope.variant) {
      where.push({
        label: "Variant",
        value: scope.variant,
        to: { product: scope.product, stream: scope.stream, variant: "" },
      });
    }
  }
  if (active.length === 0 && where.length === 0) return null;
  return (
    <div className="narrowed">
      <span className="hint">Narrowed by</span>
      {/* First, because it is the widest of them: everything after it is
          narrowing what this one already chose. */}
      {where.map((each) => (
        <button
          key={`scope ${each.label}`}
          type="button"
          className="chip"
          aria-pressed
          title="Widen to everything under this"
          onClick={() => widen(each.to)}
        >
          <span className="l">{each.label}:</span> {each.value}
          <span aria-hidden>&times;</span>
        </button>
      ))}
      {active.map((each) => (
        <button
          // The key and the value, because a multi-valued filter puts one
          // entry here per value and they all carry the filter's key. Keyed
          // on the key alone, two values of one filter were siblings with the
          // same key, and removing either left the survivor drawing the one
          // that went.
          key={`${each.key} ${each.value}`}
          type="button"
          className="chip"
          aria-pressed
          title="Remove this filter"
          onClick={() => clear(each)}
        >
          <span className="l">{each.label}:</span> {each.value}
          <span aria-hidden>&times;</span>
        </button>
      ))}
      {active.length > 1 && (
        <button type="button" className="linkish" onClick={clearAll}>
          Clear all {active.length} filters
        </button>
      )}
    </div>
  );
}
