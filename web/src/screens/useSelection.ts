import { useState } from "react";
import { identityOf, type Row } from "./list";

// What is selected on the findings list, and what a bulk act does with it.
//
// A hook rather than five pieces of state inside a thousand-line render
// function, because one rule holds them together and that rule was written at
// three of five call sites and missing at two: a selection is made out of a
// population, so replacing the population replaces what was selected. Here
// it is enforced once, where the question changes, and there is no call site
// left that could bypass it.
//
// What it cost when it was bypassed: a triager filtering to low, ticking
// thirty rows and then clicking critical had a bar still saying thirty while
// four rows were listed — and handing them over wrote assignments for
// twenty-six rows nobody could see.
//
// The rows are held, not only their keys. The selection survives paging
// and a page does not, so an act built from what is on screen reaches part of
// what was ticked: picking thirty on one page and twenty on the next and
// pressing "Assign 50" wrote twenty and dropped thirty, silently.

// What the list is asking, with the position in it left out. Two addresses
// that differ only by offset are the same question asked from a different row.
export function questionIn(params: URLSearchParams): string {
  const question = new URLSearchParams(params);
  question.delete("offset");
  return question.toString();
}

export function useSelection(asked: URLSearchParams): {
  picked: Map<string, Row>;
  // One row, ticked or unticked.
  pick: (key: string, row: Row, on: boolean) => void;
  // A page, added to or taken out of the selection — which spans pages, so
  // this cannot replace it.
  pickAll: (rows: Row[], keys: string[], on: boolean) => void;
  // Everything ticked, forgotten, wherever it was ticked.
  clear: () => void;
  // The address the list is asking under, with the selection cleared because
  // the population changed.
  asking: (next: URLSearchParams) => URLSearchParams;
  // How many of the last bulk act did not land. Said rather than swallowed:
  // the loop writes one row at a time, so a failure partway through leaves
  // part of a selection acted on, and the rows that failed stay picked.
  failed: number;
  // Applies one act to every row in the selection, wherever it was picked,
  // carrying every refusal to the end rather than stopping at the first. What
  // is left ticked afterwards is exactly what was refused.
  through: (act: (row: Row) => Promise<unknown>) => Promise<void>;
} {
  const [picked, setPicked] = useState<Map<string, Row>>(new Map());
  const [failed, setFailed] = useState(0);
  // The question the selection was made out of, so a change to it clears the
  // selection here rather than at each place that changes it.
  //
  // The offset is not part of the question. Turning the page asks the same
  // question from a different row, and the selection is deliberately wider
  // than a page — so counting the offset as a change emptied the selection on
  // every page turn, under a bar still saying "across pages".
  const [under, setUnder] = useState(() => questionIn(asked));
  const question = questionIn(asked);
  if (under !== question) {
    setUnder(question);
    if (picked.size > 0) setPicked(new Map());
    if (failed !== 0) setFailed(0);
  }

  function pick(key: string, row: Row, on: boolean) {
    setPicked((prev) => {
      const next = new Map(prev);
      if (on) next.set(key, row);
      else next.delete(key);
      return next;
    });
  }

  function pickAll(rows: Row[], keys: string[], on: boolean) {
    setPicked((prev) => {
      const next = new Map(prev);
      rows.forEach((row, at) => {
        const key = keys[at] ?? identityOf(row);
        if (on) next.set(key, row);
        else next.delete(key);
      });
      return next;
    });
  }

  function asking(next: URLSearchParams): URLSearchParams {
    // A filter change lands somebody on page nine of a list with two pages,
    // which draws as an empty list under a filter that matches plenty.
    next.delete("offset");
    setPicked(new Map());
    setFailed(0);
    setUnder(questionIn(next));
    return next;
  }

  // Everything ticked, forgotten. The whole selection rather than the page it
  // is looked at through: walking the rows on screen left somebody who had
  // picked fifty across two pages with thirty still selected and an act armed
  // on rows they could not see.
  function clear() {
    setPicked(new Map());
    setFailed(0);
  }

  async function through(act: (row: Row) => Promise<unknown>) {
    const refused: string[] = [];
    const handled: string[] = [];
    for (const [key, row] of picked) {
      handled.push(key);
      try {
        await act(row);
      } catch {
        refused.push(key);
      }
    }
    // What is selected *now*, minus what went through. Written from the
    // snapshot the loop began with, anything ticked while it ran — eight
    // seconds for fifty rows, with the checkboxes live throughout — was
    // discarded and the count dropped with nothing explaining it.
    const sent = new Set(refused);
    setPicked((prev) => {
      const left = new Map(prev);
      for (const key of handled) {
        if (!sent.has(key)) left.delete(key);
      }
      return left;
    });
    setFailed(refused.length);
  }

  return { picked, pick, pickAll, clear, asking, failed, through };
}
