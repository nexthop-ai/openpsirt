// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// A state chip drawn in the "done" color whose words say something is wrong.
// Green reads as good news, which is the one reading a failure must not get.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

// A word that names something wrong.
const TROUBLE = /\b(fail\w*|stopped|never|limit|refused|broken|error)\b/i;

// Every chip drawn as done whose words say something is wrong, as
// "file:line: words". The chip's text is everything up to the closing span,
// expressions included, so a word computed from the row is still read.
export function doneButTrouble(file, source) {
  const out = [];
  const chip = /<span className="state closed"[^>]*>([\s\S]*?)<\/span>/g;
  for (let match = chip.exec(source); match; match = chip.exec(source)) {
    const words = match[1] ?? "";
    if (TROUBLE.test(words)) {
      const line = source.slice(0, match.index).split("\n").length;
      out.push(`${file}:${line}: ${words.replace(/\s+/g, " ").trim()}`);
    }
  }
  return out;
}

function sources(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return path.endsWith(".tsx") && !path.endsWith(".test.tsx") ? [path] : [];
  });
}

// What every screen under src draws, and how many files were read.
export function sweep() {
  const files = sources(join(import.meta.dirname, "..", "src"));
  return {
    files: files.length,
    found: files.flatMap((file) => doneButTrouble(file, readFileSync(file, "utf8"))),
  };
}
