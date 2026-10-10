// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Invalidations that reach no read.
//
// TanStack Query matches an invalidation by prefix, and a key nothing reads
// matches nothing without a word: the write succeeds, the screen keeps what it
// had, and a control that saved looks as though it did not. So every key an
// invalidation names is held against the keys the reads are declared with.
//
// Parsed rather than matched, and only as far as the keys are literal. A key
// is read up to its first element that is not a string, and that part is what
// is compared: an invalidation of ["home"] reaches a read of
// ["home", "trend", scope], and one of ["trend"] does not. A read whose key
// turns into an expression after its literal part may still match a longer
// invalidation, so it is counted as one.
import path from "node:path";
import { pathToFileURL } from "node:url";
import ts from "typescript";

import { interfaceSources, parse } from "./parsed.mjs";

const here = path.dirname(new URL(import.meta.url).pathname);
const src = path.join(here, "..", "src");

// The string elements a key opens with, and whether anything follows them.
function literalPrefix(array) {
  const words = [];
  for (const element of array.elements) {
    if (ts.isStringLiteral(element) || ts.isNoSubstitutionTemplateLiteral(element)) {
      words.push(element.text);
    } else {
      return { words, open: true };
    }
  }
  return { words, open: false };
}

// The array a `queryKey:` property holds, where it is written as one.
function keyOf(object) {
  for (const property of object.properties) {
    if (
      ts.isPropertyAssignment(property) &&
      property.name.getText() === "queryKey" &&
      ts.isArrayLiteralExpression(property.initializer)
    ) {
      return property.initializer;
    }
  }
  return null;
}

// What a call on the query client does with the options it is handed: an
// invalidation, something else that names a key without declaring a read, or
// nothing of the kind.
const NAMING = new Set(["cancelQueries", "refetchQueries", "removeQueries", "resetQueries"]);

function calledAs(object) {
  const call = object.parent;
  if (!call || !ts.isCallExpression(call)) return "";
  const callee = call.expression;
  return ts.isPropertyAccessExpression(callee) ? callee.name.text : "";
}

// keysIn reads one source file: the keys its reads declare and the keys its
// invalidations name.
export function keysIn(text, file = "x.tsx", source = parse(text, file)) {
  const reads = [];
  const invalidates = [];
  const walk = (node) => {
    if (ts.isObjectLiteralExpression(node)) {
      const key = keyOf(node);
      if (key) {
        const at = source.getLineAndCharacterOfPosition(key.getStart()).line + 1;
        const prefix = literalPrefix(key);
        const called = calledAs(node);
        if (called === "invalidateQueries") invalidates.push({ at, ...prefix });
        else if (!NAMING.has(called)) reads.push({ at, ...prefix });
      }
    }
    ts.forEachChild(node, walk);
  };
  walk(source);
  return { reads, invalidates };
}

// reaches says whether an invalidation's literal words can match a read.
export function reaches(invalidation, read) {
  const asked = invalidation.words;
  if (asked.length === 0) return true;
  if (read.words.length >= asked.length) return asked.every((word, i) => read.words[i] === word);
  // The read's key is shorter in its literal part: it can match only where it
  // goes on past that part, and only where the part it has agrees.
  return read.open && read.words.every((word, i) => asked[i] === word);
}

// stale is every invalidation, across a set of files, that reaches no read in
// any of them.
export function stale(files) {
  const reads = files.flatMap((each) => each.reads);
  const found = [];
  for (const each of files) {
    for (const invalidation of each.invalidates) {
      if (!reads.some((read) => reaches(invalidation, read))) {
        found.push({ file: each.file, at: invalidation.at, key: invalidation.words });
      }
    }
  }
  return found;
}

// The whole tree: every invalidation that reaches nothing, and how many
// invalidations and reads were examined.
export function sweep() {
  const files = interfaceSources().map(({ file, text, source }) => ({
    file: path.relative(src, file),
    ...keysIn(text, file, source),
  }));
  return {
    found: stale(files),
    invalidations: files.reduce((n, each) => n + each.invalidates.length, 0),
    reads: files.reduce((n, each) => n + each.reads.length, 0),
  };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const { found, invalidations, reads } = sweep();
  if (invalidations === 0 || reads === 0) {
    console.error("No invalidation or no read was found, so this checked nothing.");
    process.exit(1);
  }
  for (const each of found) {
    console.error(
      `src/${each.file}:${each.at}: invalidates ${JSON.stringify(each.key)}, which no read's key starts with.`,
    );
  }
  if (found.length > 0) process.exit(1);
}
