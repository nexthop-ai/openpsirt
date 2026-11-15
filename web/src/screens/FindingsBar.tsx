// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { FilterMenu, type MenuOption } from "../ui/FilterMenu";
import { Icon } from "../ui/Icons";
import { notACredential } from "../ui/noautofill";
import { Saved } from "../ui/Saved";
import { FLOORS } from "../ui/severities";
import { ASSIGNED, DEADLINES, STATES, type Active } from "./FindingsFilters";
import { daysBack } from "./list";

// The filters the bar sets itself, so the count on More filters leaves them out.
const ON_THE_BAR = new Set(["q", "floor", "state", "assigned", "running"]);

// The severity scale as the bar offers it: a floor, read as "and up". The
// lowest step is no floor at all, and the highest has nothing above it.
const FLOOR_MENU: readonly MenuOption[] = FLOORS.map((band, i) => {
  const name = `${band[0]?.toUpperCase() ?? ""}${band.slice(1)}`;
  if (i === 0) return ["", "Any"] as const;
  return [band, i === FLOORS.length - 1 ? name : `${name} and up`] as const;
});

// The deadlines, worded to read after "Due".
const DUE_MENU: readonly MenuOption[] = DEADLINES.map(([word, label]) => [
  word,
  word === "" ? "Any time" : label.replace(/^Due within/, "Within"),
]);

// The findings list's filter bar: the component search, one menu per question
// asked every day, the day's new findings, the way into More filters, and the
// saved filters. Each control sets the address through the screen's own
// setters, so a change here clears the selection as every other change does.
export function FindingsBar({
  asked,
  chips,
  searching,
  typed,
  setTyped,
  floor,
  set,
  setMany,
  more,
  setMore,
  onBuild,
  onPicked,
}: {
  asked: URLSearchParams;
  // The chips in force, as the list under the bar draws them.
  chips: Active[];
  searching: string;
  typed: string;
  setTyped: (to: string) => void;
  floor: string;
  set: (key: string, value: string) => void;
  setMany: (key: string, values: string[]) => void;
  more: boolean;
  setMore: (to: boolean) => void;
  onBuild: boolean;
  onPicked: (next: URLSearchParams) => void;
}) {
  // What narrows the list from behind More filters, which is every chip but
  // the ones the bar sets itself — so the count on that button is about what
  // it opens.
  const elsewhere = chips.filter(
    (each) =>
      !ON_THE_BAR.has(each.key) && !(each.key === "opened_after" && each.value === daysBack(1)),
  ).length;
  return (
    <div className="filters filterbar">
      <form
        className="searchbox"
        onSubmit={(event) => {
          event.preventDefault();
          set("q", typed.trim());
        }}
      >
        <Icon name="search" />
        <input
          {...notACredential}
          type="text"
          value={typed}
          onChange={(event) => setTyped(event.target.value)}
          placeholder="Find a component — openssl, linux, python…"
          aria-label="Find a component"
        />
      </form>
      {searching && (
        <button
          type="button"
          className="linkish"
          onClick={() => {
            setTyped("");
            set("q", "");
          }}
        >
          Clear “{searching}”
        </button>
      )}
      {/* One button per question asked every day, each naming itself and
        what it is set to. Whatever else narrows the list is behind More
        filters, and every filter in force is a chip under the bar. */}
      <FilterMenu
        label="Decision"
        multi
        options={STATES}
        chosen={asked.getAll("state").filter(Boolean)}
        onChange={(chosen) => setMany("state", chosen)}
      />
      <FilterMenu
        label="Severity"
        options={FLOOR_MENU}
        chosen={floor === "low" ? [] : [floor]}
        onChange={(chosen) => set("floor", chosen[0] ?? "")}
      />
      <FilterMenu
        label="Assigned"
        multi
        anything="Anyone"
        options={ASSIGNED}
        chosen={asked.getAll("assigned").filter(Boolean)}
        onChange={(chosen) => setMany("assigned", chosen)}
      />
      <FilterMenu
        label="Due"
        anything="Any time"
        options={DUE_MENU}
        chosen={asked.get("running") ? [asked.get("running") ?? ""] : []}
        onChange={(chosen) => set("running", chosen[0] ?? "")}
      />
      {/* The date rather than the word, so a list somebody sends means the
        same thing when it is opened. */}
      <button
        type="button"
        className="chip"
        aria-pressed={asked.get("opened_after") === daysBack(1)}
        title="Findings first seen in the last day"
        onClick={() =>
          set("opened_after", asked.get("opened_after") === daysBack(1) ? "" : daysBack(1))
        }
      >
        New today
      </button>
      <span className="spacer" />
      <button
        type="button"
        className="chip"
        aria-pressed={elsewhere > 0 || more}
        aria-expanded={more}
        onClick={() => setMore(!more)}
      >
        More filters{elsewhere > 0 ? ` · ${elsewhere}` : ""}
      </button>
      {/* Picking a saved filter replaces what is on screen, so it replaces
      the population a selection was made out of. Keeping the selection
      across that would carry rows chosen under one question into an act
      taken under another. */}
      <Saved onBuild={onBuild} onPicked={onPicked} />
    </div>
  );
}
