// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The severity ladder, written down more than once.
//
// `src/ui/severities.ts` holds the order and membership of these words, and a
// second copy is not a tidiness problem. It is how two screens come to
// disagree about which words are real: four bands drawn beside a count of all
// five leave a quarter of what is under a node invisible, and the numbers on
// the row do not add up to the number beside them.
//
// So a list of these words anywhere but there is refused. A `switch` over them
// is not a list — it is a mapping, and every arm is visible — and neither is a
// type. What this looks for is an array literal, which is the shape a ladder
// takes and the shape that silently loses a rung.
import { readFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { sourceFiles, SRC } from "./parsed.mjs";

// Where the ladder is allowed to be written down, relative to src/.
const HOME = path.join("ui", "severities.ts");

// rungsOf is the words the ladder's home writes down, read from its text: the
// bands, the word a count folds everything unrated into, and the two words
// beneath low. Read rather than restated, so a rung added there is a rung this
// looks for.
export function rungsOf(text) {
  const rungs = new Set();
  for (const name of ["BANDS", "ROLLED", "BELOW_LOW"]) {
    const declared = text.match(new RegExp(`export const ${name}\\b[^=]*=\\s*\\[([^\\]]*)\\]`));
    if (!declared) throw new Error(`${HOME} no longer declares ${name} as a list`);
    for (const word of declared[1].matchAll(/["']([^"'\n]*)["']/g))
      rungs.add(word[1].toLowerCase());
  }
  return rungs;
}

// The rungs, and "unknown", which is the word a scanner reports for a rating
// nobody gave and which the ladder folds into unrated rather than holding.
const RUNGS = new Set([...rungsOf(readFileSync(path.join(SRC, HOME), "utf8")), "unknown"]);

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
// The plain list above is one shape a ladder takes. An array of
// `{ key, color }` objects drawing bands, and an array of `[word, label]`
// tuples offering floors, each lose a rung exactly the way a plain list does,
// and neither has a quoted word directly after the opening bracket, which is
// all the pattern above looks for.
//
// **Only where the word is the entry's own name**: the first element of a
// tuple, or a property that names the thing rather than labels it. A list of
// CVSS metric values reads `{ value: "H", label: "High" }`, and three of those
// labels are rungs while none of them is a severity.
const NAMING = /["']?(?:key|name|id|value|severity|band|level|word)["']?\s*:\s*["']([^"'\n]*)["']/g;

// The index just past the quoted text opening at `start`, or -1 where it is not
// quoted text. A backslash escapes the character after it. A single or double
// quote with no partner before the end of its line opens nothing, which is
// what an apostrophe in JSX text is.
function pastQuote(text, start) {
  const quote = text[start];
  for (let i = start + 1; i < text.length; i++) {
    const c = text[i];
    if (c === "\\") i++;
    else if (c === quote) return i + 1;
    else if (c === "\n" && quote !== "`") return -1;
  }
  return -1;
}

// The index of the bracket closing the one opened at `start`, or -1. Quoted
// text and comments are skipped, so a bracket inside either closes nothing,
// and so is a character after a backslash, which outside a string is a regular
// expression's escaped bracket.
function closing(text, start) {
  let depth = 0;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (c === "\\") {
      i++;
    } else if (c === "/" && text[i + 1] === "/") {
      const end = text.indexOf("\n", i);
      i = end < 0 ? text.length : end;
    } else if (c === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end < 0 ? text.length : end + 1;
    } else if (c === '"' || c === "'" || c === "`") {
      const past = pastQuote(text, i);
      if (past >= 0) i = past - 1;
    } else if (c === "[" || c === "{" || c === "(") {
      depth++;
    } else if (c === "]" || c === "}" || c === ")") {
      depth--;
      if (depth === 0) return c === "]" ? i : -1;
    }
  }
  return -1;
}

// How far past its opening bracket a block that cannot be closed is read.
const WINDOW = 800;

// Every array whose first entry is an array or an object, found by matching
// its brackets rather than within a window: a ladder of objects carrying a
// label, a color and a hint runs well past any length a pattern could bound.
// An array inside another is read as well as the one holding it, since a
// ladder nested among other entries is a minority of the outer array's words.
// A block whose brackets do not match, because something unread opened or
// closed one, is read over a window from its opening bracket rather than
// dropped.
function blocksIn(text) {
  const out = [];
  for (const match of text.matchAll(/\[\s*[[{]/g)) {
    const end = closing(text, match.index);
    const block =
      end < 0 ? text.slice(match.index, match.index + WINDOW) : text.slice(match.index, end + 1);
    out.push({ block, index: match.index });
  }
  return out;
}

export function groupsIn(text) {
  const out = [];
  for (const { block, index } of blocksIn(text)) {
    const words = [
      // The first element of every inner tuple.
      ...[...block.matchAll(/\[\s*["']([^"'\n]*)["']/g)].map((each) => each[1]),
      // And the naming property of every inner object.
      ...[...block.matchAll(NAMING)].map((each) => each[1]),
    ].map((word) => word.toLowerCase());
    if (words.length === 0) continue;
    out.push({ words, at: text.slice(0, index).split("\n").length });
  }
  return out;
}

// laddersIn is every copy of the ladder in a text, with the rungs each holds.
//
// **Most of the entries, not two of them.** A list of fix states holds "none"
// and "unknown", which are rungs and are not severities there — so a pair of
// shared words is a coincidence and a list that is mostly rungs is the ladder.
//
// **Two rungs at least.** One is a word being used.
//
// **One per line.** One literal can match as more than one shape, and a line
// named twice reads as two copies of the ladder.
export function laddersIn(text) {
  const lines = new Set();
  return [...listsIn(text), ...groupsIn(text)]
    .map((found) => ({
      ...found,
      rungs: found.words.filter((word) => RUNGS.has(word)),
    }))
    .filter((found) => found.rungs.length >= 2 && found.rungs.length * 2 > found.words.length)
    .filter((found) => !lines.has(found.at) && lines.add(found.at));
}

// laddersOutside is every copy of the ladder across the files, given as
// { path relative to src/: text }, except in the one file allowed to hold it.
// Each copy is { file, at, words }; `looked` is how many files were read.
export function laddersOutside(files) {
  const found = [];
  let looked = 0;
  for (const [file, text] of Object.entries(files)) {
    if (path.normalize(file) === HOME) continue;
    looked++;
    for (const { words, at } of laddersIn(text)) found.push({ file, at, words });
  }
  return { found, looked };
}

// What to say where the walk read no file, or nothing where it read some. A
// tree moved out from under the walk holds no copy of the ladder for the
// reason that nothing was looked at.
export function checkedNothing(looked) {
  return looked === 0 ? "no source file was found under src/, so this checked nothing" : "";
}

// Run when this is the program, not when a test imports it.
//
// A script that does its work at import time cannot have a test beside it: the
// test would walk the tree, and a tree with a copy of the ladder in it would
// call process.exit and take the test runner down with it. What is exported
// above is the detection; this is the program.
//
// Tests are read too: a test holding its own copy of the ladder pins a list
// that can drift from the one the screens draw.
if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const files = Object.fromEntries(
    sourceFiles({ ext: [".ts", ".tsx"], tests: true }).map((file) => [
      path.relative(SRC, file),
      readFileSync(file, "utf8"),
    ]),
  );
  const { found, looked } = laddersOutside(files);
  for (const { file, at, words } of found) {
    console.error(
      `${file}:${at}: [${words.join(", ")}] is the severity ladder written ` +
        `out again — import it from ui/severities.ts, and add the word there if it is missing`,
    );
  }
  const nothing = checkedNothing(looked);
  if (nothing) {
    console.error(nothing);
    process.exit(1);
  }
  const bad = found.length;
  if (bad > 0) {
    console.error(
      `\n${bad} ${bad === 1 ? "copy" : "copies"} of the ladder outside ui/severities.ts`,
    );
    process.exit(1);
  }
  console.log(`the severity ladder is written down once (${looked} files checked)`);
}
