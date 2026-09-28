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
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const here = import.meta.dirname;
const src = path.join(here, "..", "src");

// A comment is prose, not a reference.
//
// The words that name a token appear in the comments that explain it — a block
// saying why a color is not composed at run time has to write the shape it is
// not composing, and read as a reference that is a token named and defined
// nowhere. Both the stylesheets and the TypeScript are stripped of comments
// before they are read.
//
// Line comments and block comments alike, and a URL's `//` is left alone
// because it is inside quotes by the time it matters here.
export function withoutComments(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, "")
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

async function sources(dir) {
  const found = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      found.push(...(await sources(full)));
    } else if (/\.(css|tsx|ts)$/.test(entry.name) && entry.name !== "schema.d.ts") {
      found.push(full);
    }
  }
  return found;
}

// Run when this is the program, not when a test imports it.
//
// A script that does its work at import time cannot have a test beside it: the
// test would walk the tree, and a tree with an undefined token in it would
// call process.exit and take the test runner down with it. What is exported
// above is the detection; this is the program.
if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const files = await sources(src);

  // What is defined: any `--name:` at the start of a declaration, in a
  // stylesheet or in a style object a component hands an element — a token set
  // per element is as defined as one set on a selector, and the swatch that
  // draws two colors is exactly that.
  const definedAt = new Map();
  const namedAt = new Map();
  for (const file of files) {
    const at = path.relative(path.join(here, ".."), file);
    const { defined, named } = tokensIn(await readFile(file, "utf8"), at);
    for (const [name, where] of defined) if (!definedAt.has(name)) definedAt.set(name, where);
    for (const [name, where] of named) namedAt.set(name, [...(namedAt.get(name) ?? []), ...where]);
  }

  // What is referred to and defined nowhere.
  const missing = new Map();
  for (const [name, where] of namedAt) {
    if (!definedAt.has(name)) missing.set(name, where);
  }

  if (missing.size > 0) {
    for (const [name, where] of [...missing].sort()) {
      console.error(`${name} is used at ${where.join(", ")} and defined nowhere`);
    }
    console.error(
      `\n${missing.size} token(s) named and never defined. CSS drops the ` +
        `declaration silently, so the screen looks nearly right.`,
    );
    process.exit(1);
  }

  // The other direction. Nothing is exempt: a token defined and never named is
  // dead whether it is in tokens.css or beside a rule that no longer reads it.
  // The bundle is self-contained and embedded in the binary, so there is no
  // consumer outside this directory for one to be defined for — which the check
  // above already assumes in the other direction.
  // Through the same reader, so both directions strip comments by the same
  // call rather than by two that can drift apart. A reference carrying its own
  // fallback still counts as naming the token here: what this asks is whether
  // anybody refers to it at all.
  const refersToIt = new Set();
  for (const file of files) {
    const text = withoutComments(await readFile(file, "utf8"));
    for (const [, name] of text.matchAll(/var\(\s*(--[a-zA-Z0-9_-]+)/g)) refersToIt.add(name);
  }
  const orphaned = [...definedAt].filter(([name]) => !refersToIt.has(name)).sort();
  if (orphaned.length > 0) {
    for (const [name, at] of orphaned) {
      console.error(`${name} is defined at ${at} and named nowhere`);
    }
    console.error(`\n${orphaned.length} token(s) defined and never used. Delete the definition.`);
    process.exit(1);
  }

  const nothing = checkedNothing({
    files: files.length,
    defined: definedAt.size,
    named: refersToIt.size,
  });
  if (nothing) {
    console.error(nothing);
    process.exit(1);
  }

  // The count is the referenced set rather than the defined one, so the number
  // reported is the number vouched for.
  console.log(
    `every token is defined where it is named and named where it is defined (${refersToIt.size})`,
  );
}
