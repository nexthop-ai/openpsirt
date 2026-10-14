// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Design tokens referred to and never defined.
//
// A `var(--thing)` naming a token that does not exist is not an error anywhere:
// CSS drops the declaration, the element keeps whatever it inherited, and the
// screen looks nearly right. A token renamed with one reference left behind is
// invisible until somebody compares two screens side by side.
//
// So every reference is put to the set of definitions. A fallback counts as a
// definition of nothing: `var(--gone, 8px)` is a deliberate default and is
// exempt, because the author said what happens when it is absent.
//
// And every definition is put to the set of references, which is the mirror of
// the same failure: a token defined and named nowhere is that rename with the
// other half left behind. Checking one direction alone cannot see it, because
// a definition nothing refers to is exactly what a reference loop never
// reaches.
import { readFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { sourceFiles, WEB } from "./parsed.mjs";

// A comment is prose, not a reference.
//
// The words that name a token appear in the comments that explain it — a block
// saying why a color is not composed at run time has to write the shape it is
// not composing, and read as a reference that is a token named and defined
// nowhere. Both the stylesheets and the TypeScript are stripped of comments
// before they are read.
//
// Line comments and block comments alike, and a URL's `//` is left alone
// because it is inside quotes by the time it matters here. A block comment
// leaves its newlines behind, so a line number read afterwards is the line in
// the file.
export function withoutComments(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, (comment) => comment.replace(/[^\n]/g, ""))
    .split("\n")
    .map((line) => {
      const cut = line.indexOf("//");
      if (cut < 0) return line;
      // Not a comment where it is inside a string: an odd number of quotes
      // before it means the `//` is part of one.
      const before = line.slice(0, cut);
      const quotes = (before.match(/["'`]/g) ?? []).length;
      return quotes % 2 === 1 ? line : before;
    })
    .join("\n");
}

// tokensIn reads one file as the tokens it defines and the tokens it names.
//
// Lifted out of the walk so a test reaches the comment stripping through the
// reader. Asked of `withoutComments` directly, a test passes with the calls
// to it deleted — the missing-call shape this gate exists to catch, in the
// gate itself.
export function tokensIn(text, at = "") {
  const source = withoutComments(text);
  const lines = source.split("\n");
  const defined = new Map();
  const named = new Map();
  for (let i = 0; i < lines.length; i++) {
    for (const [, name] of lines[i].matchAll(/(?:^|[;{,]|\s)["']?(--[a-zA-Z0-9_-]+)["']?\s*:/g)) {
      if (!defined.has(name)) defined.set(name, `${at}:${i + 1}`);
    }
    // A reference carrying its own fallback is a deliberate default, and the
    // author said what happens when it is absent.
    for (const [, name, fallback] of lines[i].matchAll(/var\(\s*(--[a-zA-Z0-9_-]+)\s*(,?)/g)) {
      if (fallback === ",") continue;
      if (!named.has(name)) named.set(name, []);
      named.get(name).push(`${at}:${i + 1}`);
    }
  }
  return { defined, named };
}

// What to say where the walk examined nothing, or nothing where it examined
// something. A gate over an empty tree, or over files holding no token at all,
// finds nothing wrong for the reason that it looked at nothing.
export function checkedNothing({ files, defined, named }) {
  if (files === 0)
    return "no stylesheet or source file was found under src/, so this checked nothing";
  if (defined === 0 || named === 0) {
    return `${files} file(s) held ${defined} token definition(s) and ${named} reference(s), so this checked nothing`;
  }
  return "";
}

// tokenFindings puts every file's definitions to every file's references, in
// both directions. It takes the files as { path: text } and returns the tokens
// named and defined nowhere, as name to the places naming it; the tokens
// defined and named nowhere, as [name, place] pairs; and how many of each
// were read.
//
// A reference carrying its own fallback counts as naming a token in the second
// direction: what that direction asks is whether anybody refers to it at all.
export function tokenFindings(files) {
  const definedAt = new Map();
  const namedAt = new Map();
  const refersToIt = new Set();
  for (const [at, text] of Object.entries(files)) {
    const { defined, named } = tokensIn(text, at);
    for (const [name, where] of defined) if (!definedAt.has(name)) definedAt.set(name, where);
    for (const [name, where] of named) namedAt.set(name, [...(namedAt.get(name) ?? []), ...where]);
    for (const [, name] of withoutComments(text).matchAll(/var\(\s*(--[a-zA-Z0-9_-]+)/g)) {
      refersToIt.add(name);
    }
  }
  const missing = new Map([...namedAt].filter(([name]) => !definedAt.has(name)).sort());
  const orphaned = [...definedAt].filter(([name]) => !refersToIt.has(name)).sort();
  return { missing, orphaned, defined: definedAt.size, named: refersToIt.size };
}

// Run when this is the program, not when a test imports it.
//
// A script that does its work at import time cannot have a test beside it: the
// test would walk the tree, and a tree with an undefined token in it would
// call process.exit and take the test runner down with it. What is exported
// above is the detection; this is the program.
//
// What is defined is any `--name:` at the start of a declaration, in a
// stylesheet or in a style object a component hands an element — a token set
// per element is as defined as one set on a selector, and the swatch that
// draws two colors is exactly that. Tests are read too: a token a test sets on
// an element is defined there.
//
// Nothing is exempt in the second direction: a token defined and never named
// is dead whether it is in tokens.css or beside a rule that no longer reads
// it. The bundle is self-contained and embedded in the binary, so there is no
// consumer outside this directory for one to be defined for.
if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const paths = sourceFiles({ ext: [".css", ".tsx", ".ts"], tests: true });
  const files = Object.fromEntries(
    paths.map((file) => [path.relative(WEB, file), readFileSync(file, "utf8")]),
  );
  const { missing, orphaned, defined, named } = tokenFindings(files);

  if (missing.size > 0) {
    for (const [name, where] of missing) {
      console.error(`${name} is used at ${where.join(", ")} and defined nowhere`);
    }
    console.error(
      `\n${missing.size} token(s) named and never defined. CSS drops the ` +
        `declaration silently, so the screen looks nearly right.`,
    );
    process.exit(1);
  }

  if (orphaned.length > 0) {
    for (const [name, at] of orphaned) {
      console.error(`${name} is defined at ${at} and named nowhere`);
    }
    console.error(`\n${orphaned.length} token(s) defined and never used. Delete the definition.`);
    process.exit(1);
  }

  const nothing = checkedNothing({ files: paths.length, defined, named });
  if (nothing) {
    console.error(nothing);
    process.exit(1);
  }

  // The count is the referenced set rather than the defined one, so the number
  // reported is the number vouched for.
  console.log(`every token is defined where it is named and named where it is defined (${named})`);
}
