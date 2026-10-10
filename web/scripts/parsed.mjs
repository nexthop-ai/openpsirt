// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The interface's source, read and parsed once per process.
//
// Every whole-interface check reads the same files as the same syntax trees,
// and parsing them is most of what each check costs. So the trees are built the
// first time any check asks and every other check reads them. Nothing that
// reads a tree changes it.
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import ts from "typescript";

const src = path.join(import.meta.dirname, "..", "src");

// parse reads one file as TSX, which every check reads every file as: a `.ts`
// file parses the same either way, and the JSX in a `.tsx` one only this way.
export function parse(text, file) {
  return ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
}

function sources(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...sources(full));
    else if (
      /\.tsx?$/.test(entry.name) &&
      !entry.name.includes(".test.") &&
      !entry.name.endsWith(".d.ts")
    )
      out.push(full);
  }
  return out;
}

let parsed;

// Every source file of the interface that is not a test or a declaration, as
// its path, its text and its tree, in the order the directories list them.
export function interfaceSources() {
  parsed ??= sources(src).map((file) => {
    const text = readFileSync(file, "utf8");
    return { file, text, source: parse(text, file) };
  });
  return parsed;
}
