// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The accent is for what opens something: a link, a focus ring, the hover on
// something that opens. A state — picked, pressed, checked, in force, the one
// you are on — is drawn in ink or on the raised tone. A state drawn in the
// accent reads as something to click.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

// A selector that describes a state rather than an interaction.
const STATE =
  /\[aria-(pressed|checked|selected|current)|\[data-on|:checked|\.on\b|\.here\b|\.set\b/;

// An interaction, which the accent is for even where a state is also named.
const INTERACTION = /:hover|:focus/;

// Every rule whose selector names a state and whose body uses the accent, as
// "file: selector". Comments are dropped first so a word in one is not a rule.
export function stateInAccent(file, css) {
  const out = [];
  let examined = 0;
  const source = css.replace(/\/\*[\s\S]*?\*\//g, "");
  const rule = /([^{}]+)\{([^{}]*)\}/g;
  for (let match = rule.exec(source); match; match = rule.exec(source)) {
    const selector = (match[1] ?? "").trim();
    if (selector.startsWith("@")) continue;
    examined++;
    const states = selector
      .split(",")
      .map((each) => each.trim())
      .filter((each) => STATE.test(each) && !INTERACTION.test(each));
    if (states.length === 0) continue;
    if (/var\(--accent(-soft|-line|-ink)?\)/.test(match[2] ?? "")) {
      out.push(`${file}: ${states.join(", ")}`);
    }
  }
  return { examined, found: out };
}

// Every stylesheet under src/styles.
export function sweep() {
  const dir = join(import.meta.dirname, "..", "src", "styles");
  let examined = 0;
  const found = [];
  for (const name of readdirSync(dir).filter((each) => each.endsWith(".css"))) {
    const one = stateInAccent(name, readFileSync(join(dir, name), "utf8"));
    examined += one.examined;
    found.push(...one.found);
  }
  return { examined, found };
}
