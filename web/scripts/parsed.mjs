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

// The interface's own directory and its source directory.
export const WEB = path.join(import.meta.dirname, "..");
export const SRC = path.join(WEB, "src");

// Files under the source directory no check reads, as paths relative to it.
// The generated API client is the server's document as TypeScript: a word in
// an operation's description is neither markup nor code anybody here wrote.
const GENERATED = new Set([path.join("api", "schema.d.ts")]);

// sourceFiles is the one definition of which files a check reads: every file
// under `under` whose name ends in one of `ext`, the generated files left out,
// and test files left out unless `tests` is set. A test file is one whose name
// carries `.test.`. Absolute paths, sorted, so every check reads the same set
// in the same order.
export function sourceFiles({ ext, tests = false, under = SRC }) {
  const out = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (
        ext.some((each) => entry.name.endsWith(each)) &&
        (tests || !entry.name.includes(".test.")) &&
        !GENERATED.has(path.relative(SRC, full))
      )
        out.push(full);
    }
  };
  walk(under);
  return out.sort();
}

// parse reads one file as TSX, which every check reads every file as: a `.ts`
// file parses the same either way, and the JSX in a `.tsx` one only this way.
export function parse(text, file) {
  return ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
}

let parsed;

// Every TypeScript source file of the interface that is not a test, as its
// path, its text and its tree.
export function interfaceSources() {
  parsed ??= sourceFiles({ ext: [".ts", ".tsx"] }).map((file) => {
    const text = readFileSync(file, "utf8");
    return { file, text, source: parse(text, file) };
  });
  return parsed;
}
