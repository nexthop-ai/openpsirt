// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The accent is for what opens something: a link, a focus ring, the hover on
// something that opens. A state — picked, pressed, checked, in force, the one
// you are on — is drawn in ink or on the raised tone. A state drawn in the
// accent reads as something to click.

import { readFileSync } from "node:fs";
import path from "node:path";
import { cssRules } from "./class-rules.mjs";
import { sourceFiles, SRC } from "./parsed.mjs";

// A selector that describes a state rather than an interaction.
const STATE =
  /\[aria-(pressed|checked|selected|current)|\[data-on|:checked|\.on\b|\.here\b|\.set\b/;

// An interaction, which the accent is for even where a state is also named.
const INTERACTION = /:hover|:focus/;

// Every rule whose selector names a state and whose body uses the accent, as
// "file: selector".
export function stateInAccent(file, css) {
  const out = [];
  let examined = 0;
  for (const { selector, body } of cssRules(css)) {
    if (selector.startsWith("@")) continue;
    examined++;
    const states = selector
      .split(",")
      .map((each) => each.trim())
      .filter((each) => STATE.test(each) && !INTERACTION.test(each));
    if (states.length === 0) continue;
    if (/var\(--accent(-soft|-line|-ink)?\)/.test(body)) {
      out.push(`${file}: ${states.join(", ")}`);
    }
  }
  return { examined, found: out };
}

// Every stylesheet of the interface.
export function sweep() {
  let examined = 0;
  const found = [];
  for (const file of sourceFiles({ ext: [".css"] })) {
    const one = stateInAccent(path.relative(SRC, file), readFileSync(file, "utf8"));
    examined += one.examined;
    found.push(...one.found);
  }
  return { examined, found };
}
