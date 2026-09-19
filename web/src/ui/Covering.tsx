import { notACredential } from "./noautofill";
import { useEffect, useRef, useState } from "react";
import type { Body } from "../api/client";

// The places a decision covers.
//
// All of them by default, which is the rule a decision is written under. A
// checkbox per place is a summary line instead, and excluding is a deliberate
// second step that groups places by what pulls the component in —
// so leaving out a whole container is one click, leaving out one module is
// still possible, and the result reads back as "59 of 62, three left open
// under X".

export type Sitting = Body<"SittingBody">;

// A component the inventory placed nowhere. Not "the product itself", which
// would be a claim the inventory never made.
export const UNPLACED = "nothing recorded what pulls this in";

type Group = { consumer: string; note?: string; items: Sitting[] };

function groupsOf(places: Sitting[]): Group[] {
  const byConsumer = new Map<string, Group>();
  for (const place of places) {
    const chain = place.chain ?? [];
    const consumer =
      place.consumer || (chain.length > 1 ? (chain[chain.length - 2]?.component ?? "") : "");
    const key = consumer || UNPLACED;
    const note = !consumer ? undefined : chain.length === 2 ? "the build itself" : undefined;
    const group = byConsumer.get(key) ?? { consumer: key, note, items: [] };
    if (!group.items.some((p) => p.place === place.place)) group.items.push(place);
    byConsumer.set(key, group);
  }
  return [...byConsumer.values()].sort((a, b) => b.items.length - a.items.length);
}

export function Covering({
  places,
  excluded,
  onChange,
  matching,
  differing,
}: {
  places: Sitting[];
  excluded: Set<string>;
  onChange: (next: Set<string>) => void;
  // Other builds, merged from the reach of the covered places.
  matching: number;
  differing: number;
}) {
  const [open, setOpen] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const [filter, setFilter] = useState("");
  const groups = groupsOf(places);
  const total = places.length;
  const covered = total - excluded.size;
  // Counted in the units somebody acts in. A judgment covers the whole fold,
  // so what it reaches is packages and the things that pull them in — a place
  // count is a figure a reader cannot reconcile with anything else on the
  // screen, and it is what the narrowing below works at rather than what the
  // summary states.
  const packages = new Set(places.map((place) => place.component)).size;
  const leftUnder = groups
    .filter((g) => g.items.some((p) => excluded.has(p.place ?? "")))
    .map((g) => g.consumer);

  // The rows it is given, which are the rows on screen. Handed the whole group
  // while a filter was narrowing what was drawn, unticking a consumer showing
  // one row excluded all forty under it — and this control is what decides
  // what a claim covers, which is the thing the panel exists to get right.
  function toggleGroup(items: Sitting[], on: boolean) {
    const next = new Set(excluded);
    for (const place of items) {
      if (on) next.delete(place.place ?? "");
      else next.add(place.place ?? "");
    }
    onChange(next);
  }

  return (
    <div className="scopebox">
      <header>
        <h5>Scope</h5>
        <span className="n">
          {covered} of {total}
        </span>
      </header>
      {excluded.size === 0 ? (
        <p className="said">
          <b>
            {packages > 1 && <>All {packages} packages · </>}
            {groups.length} {groups.length === 1 ? "consumer" : "consumers"}
          </b>{" "}
          in this build.{" "}
          {total > 1 && (
            <button type="button" className="linkish" onClick={() => setOpen(!open)}>
              {open ? "Done" : "Exclude places…"}
            </button>
          )}
        </p>
      ) : (
        <p className="said">
          <b>
            {covered} of {total}
          </b>{" "}
          covered · {excluded.size} left open under{" "}
          {leftUnder.map((c, i) => (
            <span key={c}>
              {i > 0 && ", "}
              <span className="id">{c}</span>
            </span>
          ))}
          .{" "}
          <button type="button" className="linkish" onClick={() => setOpen(!open)}>
            {open ? "Done" : "Edit"}
          </button>{" "}
          <button
            type="button"
            className="linkish"
            style={{ color: "var(--muted)" }}
            onClick={() => {
              onChange(new Set());
              setOpen(false);
            }}
          >
            Cover all
          </button>
        </p>
      )}

      {open && total > 1 && (
        <div className="groups">
          {total > 12 && (
            <input
              {...notACredential}
              type="text"
              className="locfilter"
              placeholder="Filter places…"
              aria-label="Filter places"
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
            />
          )}
          {groups.map((group) => {
            // The rows on screen under this consumer, which are what the
            // checkbox beside it acts on and what the count beside that says.
            // The three read the same rows, so the number names what the
            // click will do.
            const shown = filter
              ? group.items.filter((p) =>
                  (p.chain?.[p.chain.length - 1]?.component ?? "")
                    .toLowerCase()
                    .includes(filter.toLowerCase()),
                )
              : group.items;
            // A consumer with nothing matching is not drawn while a filter
            // is on. Its header would offer a checkbox over no rows and a
            // count of none, which is a control that does nothing.
            if (shown.length === 0) return null;
            const out = shown.filter((p) => excluded.has(p.place ?? "")).length;
            const state = out === 0 ? "all" : out === shown.length ? "none" : "some";
            const isOpen = expanded.has(group.consumer);
            return (
              <div key={group.consumer}>
                <div className="grp">
                  <label>
                    <Mixed
                      checked={state === "all"}
                      mixed={state === "some"}
                      onChange={(on) => toggleGroup(shown, on)}
                    />
                    <span className="id">{group.consumer}</span>
                    {group.note && <span className="hint">{group.note}</span>}
                    <span className="cnt">
                      {shown.length - out} of {shown.length}
                    </span>
                  </label>
                  {group.items.length > 1 && (
                    <button
                      type="button"
                      className="peek"
                      aria-expanded={isOpen}
                      onClick={() =>
                        setExpanded((prev) => {
                          const next = new Set(prev);
                          if (next.has(group.consumer)) next.delete(group.consumer);
                          else next.add(group.consumer);
                          return next;
                        })
                      }
                    >
                      {isOpen ? "▾" : "▸"}
                    </button>
                  )}
                </div>
                {isOpen &&
                  shown.map((place) => {
                    const name =
                      place.chain?.[place.chain.length - 1]?.component ?? place.place ?? "";
                    const key = place.place ?? "";
                    return (
                      <label key={key} className="loc">
                        <input
                          type="checkbox"
                          checked={!excluded.has(key)}
                          onChange={(event) => {
                            const next = new Set(excluded);
                            if (event.target.checked) next.delete(key);
                            else next.add(key);
                            onChange(next);
                          }}
                        />
                        <span className="id">{name}</span>
                        {(place.chain ?? []).length > 2 && (
                          <span className="hint">
                            {(place.chain ?? [])
                              .slice(0, -1)
                              .map((s) => s.component)
                              .join(" › ")}
                          </span>
                        )}
                      </label>
                    );
                  })}
              </div>
            );
          })}
          <p className="hint" style={{ margin: "8px 0 0" }}>
            A place left out stays <b>open</b> and asks nothing further of you.
          </p>
        </div>
      )}

      <p
        className="said"
        style={{ marginTop: 8, paddingTop: 8, borderTop: "1px solid var(--line)" }}
      >
        <b>
          {matching} other {matching === 1 ? "build matches" : "builds match"}
        </b>{" "}
        automatically · <b>{differing}</b> at other{" "}
        {differing === 1 ? "version is" : "versions are"} reviewed one at a time on submit.
      </p>
    </div>
  );
}

// A checkbox that can say "some". The DOM has the state and no attribute for
// it, so it is set after render.
function Mixed({
  checked,
  mixed,
  onChange,
}: {
  checked: boolean;
  mixed: boolean;
  onChange: (on: boolean) => void;
}) {
  const box = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (box.current) box.current.indeterminate = mixed;
  }, [mixed]);
  return (
    <input
      ref={box}
      type="checkbox"
      checked={checked}
      onChange={(event) => onChange(event.target.checked)}
    />
  );
}
