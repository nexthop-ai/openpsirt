// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { bandOf, ratedAs } from "./severities";

// Severity reads at a glance and never borrows the accent color: "urgent" and
// "clickable" must never look like the same thing.
//
// The rating and the fact are shown separately, because they are separate.
// Severity says how bad the flaw is; being exploited says somebody is using
// it. Replacing "medium" with "exploited" answers one question by destroying
// the other — and the two together are what explain why an exploited medium
// sits above an unexploited high in the list.
export function Severity({ word }: { word?: string }) {
  // One word for one state. A scanner's own "unknown", a producer's invented
  // word and no rating at all rank alike everywhere that orders or filters —
  // below every band, surviving no floor — and only what a reader sees
  // differs: one row saying "Unknown" and the row under it saying "Unrated"
  // about the same nothing.
  //
  // Two answers about one row, and they are not the same question. The band
  // is where everything that sorts, filters and colors puts it; the word is
  // what somebody rated it. They differ only for the two words below low —
  // "rated negligible" read as "Unrated" says nobody looked at a finding
  // somebody looked at and dismissed.
  const band = bandOf(word);
  const said = ratedAs(word);
  // The class says what the band says. `unrated` is not one of the four, so
  // the test that decided the class was always false for it and the badge
  // drew as a low while reading "Unrated" — the same row counted as a medium
  // by the chart beside it and drawn with a low's stripe in the card view.
  return (
    <span
      className={`sev ${band}`}
      title={said === band ? undefined : `Rated ${said}, which ranks in the low band`}
    >
      {said[0]?.toUpperCase()}
      {said.slice(1)}
    </span>
  );
}

// Known-exploited, said outright rather than left to a color. It is a fact
// about the world rather than a judgment, and it is what decides the order.
export function Exploited({ when }: { when?: boolean }) {
  if (!when) return null;
  return (
    <span
      className="kev"
      title="Somebody is known to be using this. It sorts above everything else, whatever the severity says"
    >
      Exploited
    </span>
  );
}

// Somebody here recorded that this product was attacked through the issue.
//
// A badge of its own beside the one above, never instead of it. The one above
// is a feed saying the world is using this; this is a person saying it was
// used against us, and a reader who takes one for the other has the wrong
// answer to the only question a regulator asks.
export function ExploitedHere({ when }: { when?: boolean }) {
  if (!when) return null;
  return (
    <span
      className="kev here"
      title="Somebody recorded that this product was attacked through this issue. It sorts above everything, including a feed saying the world is exploiting it"
    >
      Exploited here
    </span>
  );
}
