// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// An outcome a claim can carry that has no color of its own.
//
// A claim is drawn in the color of what it does: warm where it hides risk,
// green where it does not. An outcome with no arm falls through to the neutral
// base, which is the color of a claim that hides nothing — so the one reading
// the queue exists to prevent is the one it gives.

import { readFileSync } from "node:fs";
import { join } from "node:path";

// Every outcome word the generated client names on any field holding a
// judgment's outcome. Other fields are called outcome too — what became of an
// upload is one — so a field counts where it names a judgment's own word.
export function outcomesIn(schema) {
  const out = new Set();
  const field = /^\s*outcome\??: \(?([^;\n]*)/gm;
  for (let match = field.exec(schema); match; match = field.exec(schema)) {
    const words = [...(match[1] ?? "").matchAll(/"([a-z_-]+)"/g)].map((each) => each[1]);
    if (!words.includes("not-applicable")) continue;
    for (const word of words) out.add(word);
  }
  return [...out].sort();
}

// Every outcome a stylesheet gives a claim a color for.
export function armsIn(css) {
  return new Set([...css.matchAll(/\.claimed\.([a-z-]+)\s*[,{]/g)].map((each) => each[1]));
}

// The outcomes with no arm.
export function uncolored(outcomes, arms) {
  return outcomes.filter((outcome) => !arms.has(outcome));
}

// What the tree holds: the outcomes read, and those with no color.
export function sweep() {
  const root = join(import.meta.dirname, "..", "src");
  const outcomes = outcomesIn(readFileSync(join(root, "api", "schema.d.ts"), "utf8"));
  const arms = armsIn(readFileSync(join(root, "styles", "parts.css"), "utf8"));
  return { outcomes, missing: uncolored(outcomes, arms) };
}
