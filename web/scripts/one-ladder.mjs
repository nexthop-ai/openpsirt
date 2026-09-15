// The severity ladder, written down more than once.
//
// `src/ui/severities.ts` exists because the order and membership of these
// words had been written out eight times under seven names, with three
// different memberships — and a second copy is not a tidiness problem. It is
// how two screens come to disagree about which words are real: the tree drew
// four bands beside a count of all five, so a quarter of what was under a node
// was invisible and the numbers on the row did not add up to the number beside
// them.
//
// So a list of these words anywhere but there is refused. A `switch` over them
// is not a list — it is a mapping, and every arm is visible — and neither is a
// type. What this looks for is an array literal, which is the shape a ladder
// takes and the shape that silently loses a rung.
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const here = path.dirname(new URL(import.meta.url).pathname);
const src = path.join(here, "..", "src");
// Where the ladder is allowed to be written down.
const home = path.join(src, "ui", "severities.ts");

export const RUNGS = new Set([
  "critical",
  "high",
  "medium",
  "low",
  "unrated",
  "unknown",
  "negligible",
  "none",
]);

async function sources(dir) {
  const found = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) found.push(...(await sources(full)));
    else if (/\.(ts|tsx)$/.test(entry.name) && entry.name !== "schema.d.ts") found.push(full);
  }
  return found;
}

// Every array literal of string literals in a file, as the words it holds.
// Read with a regular expression rather than parsed: a literal list of quoted
// words is a shape a pattern recognizes exactly, and the alternative is a
// TypeScript parser in a check that exists to be cheap enough to always run.
export function listsIn(text) {
  const out = [];
  for (const match of text.matchAll(
    /\[\s*((?:"[^"\n]*"|'[^'\n]*')(?:\s*,\s*(?:"[^"\n]*"|'[^'\n]*'))*)\s*,?\s*\]/g,
  )) {
    const words = match[1].split(",").map((each) =>
      each
        .trim()
        .replace(/^["']|["']$/g, "")
        .toLowerCase(),
    );
    out.push({ words, at: text.slice(0, match.index).split("\n").length });
  }
  return out;
}

// A ladder written as an array of objects, or of tuples.
//
// The plain list above is one shape a ladder takes and not the only one. Both
// of these are in this tree: an array of `{ key, color }` objects drawing four
// bands, and an array of `[word, label]` tuples offering four floors. Each
// loses a rung exactly the way a plain list does — the bug the whole check was
// written after was four bands beside a count of five — and neither has a
// quoted word directly after the opening bracket, which is all the pattern
// above looks for.
//
// **Only where the word is the entry's own name**: the first element of a
// tuple, or a property that names the thing rather than labels it. A list of
// CVSS metric values reads `{ value: "H", label: "High" }`, and three of those
// labels are rungs while none of them is a severity.
const NAMING = /["']?(?:key|name|id|value|severity|band|level|word)["']?\s*:\s*["']([^"'\n]*)["']/g;

export function groupsIn(text) {
  const out = [];
  for (const match of text.matchAll(/\[\s*[[{][\s\S]{0,800}?[\]}]\s*,?\s*\]/g)) {
    const block = match[0];
    const words = [
      // The first element of every inner tuple.
      ...[...block.matchAll(/\[\s*["']([^"'\n]*)["']/g)].map((each) => each[1]),
      // And the naming property of every inner object.
      ...[...block.matchAll(NAMING)].map((each) => each[1]),
    ].map((word) => word.toLowerCase());
    if (words.length === 0) continue;
    out.push({ words, at: text.slice(0, match.index).split("\n").length });
  }
  return out;
}

// laddersIn is every shape together, with the rungs each one holds.
//
// **Most of the entries, not two of them.** A list of fix states holds "none"
// and "unknown", which are rungs and are not severities there — so a pair of
// shared words is a coincidence and a list that is mostly rungs is the ladder.
export function laddersIn(text) {
  return [...listsIn(text), ...groupsIn(text)]
    .map((found) => ({
      ...found,
      rungs: found.words.filter((word) => RUNGS.has(word)),
    }))
    .filter((found) => found.rungs.length * 2 > found.words.length);
}

// Run when this is the program, not when a test imports it.
//
// A script that does its work at import time cannot have a test beside it: the
// test would walk the tree, and a tree with a copy of the ladder in it would
// call process.exit and take the test runner down with it. What is exported
// above is the detection; this is the program.
if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  let bad = 0;
  let looked = 0;
  for (const file of await sources(src)) {
    if (path.resolve(file) === path.resolve(home)) continue;
    const text = await readFile(file, "utf8");
    looked++;
    const reported = new Set();
    for (const { words, at, rungs } of laddersIn(text)) {
      // Two of them together is a ladder. One is a word being used.
      if (rungs.length < 2) continue;
      // One literal can match as more than one shape. Reported once, by where
      // it is: a line named twice reads as two copies of the ladder.
      if (reported.has(at)) continue;
      reported.add(at);
      bad++;
      console.error(
        `${path.relative(src, file)}:${at}: [${words.join(", ")}] is the severity ladder written ` +
          `out again — import it from ui/severities.ts, and add the word there if it is missing`,
      );
    }
  }
  if (bad > 0) {
    console.error(
      `\n${bad} ${bad === 1 ? "copy" : "copies"} of the ladder outside ui/severities.ts`,
    );
    process.exit(1);
  }
  console.log(`the severity ladder is written down once (${looked} files checked)`);
}
