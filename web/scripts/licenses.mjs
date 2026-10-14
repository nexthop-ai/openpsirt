// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The license of everything the interface ships, against the allowlist.
//
// Nothing ships unless its license is permissive, because a self-hosted tool
// is redistributed by whoever installs it and a copyleft dependency makes that
// their problem. The Go side is held to the same policy; the interface ships
// too, because the bundle is built into the binary.
//
// It runs locally with one command, which the platform's dependency review
// cannot, and that is what REQ-75 asks for.
//
// Development dependencies are unrestricted, as they are on the Go side.
// Vite, ESLint and the type checker are not in the bundle, and a build tool's
// license binds whoever builds rather than whoever installs. What makes that
// true is that the interface's source imports none of them, so that is checked
// too: a development dependency imported by the source is in the bundle.
import { readFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import ts from "typescript";
import { parse, sourceFiles, SRC, WEB } from "./parsed.mjs";

const lockfile = path.join(WEB, "package-lock.json");

// The allowlist is the Makefile's, passed in rather than repeated here. A
// policy written in two files is a policy that differs in one of them, which
// is the failure `pins-check` exists for.
const allowed = new Set(
  (process.env.ALLOWED_LICENSES ?? "")
    .split(",")
    .map((name) => name.trim())
    .filter(Boolean),
);

// Licenses accepted for one package despite not being on the list.
//
// Passed in, like the allowlist above and for the same reason: one license
// policy with its exceptions in two files has no single place a new one is
// written.
//
// Each entry is `name=license`, so the license still has to match: an
// exception admits one package's actual license rather than waving the package
// through.
const exceptions = (process.env.LICENSE_EXCEPTIONS ?? "")
  .split(",")
  .map((each) => each.trim())
  .filter(Boolean)
  .map((each) => {
    const [prefix, license] = each.split("=");
    if (!prefix || !license) {
      console.error(`LICENSE_EXCEPTIONS entry ${each} is not name=license.`);
      process.exit(2);
    }
    return { prefix, license };
  });

// The package installed at a lockfile location, with its nested
// `node_modules/` segments collapsed to "/": the last package name in the
// path, where a name beginning "@" is a scope and takes the segment after it.
export function packageAt(location) {
  const segments = location.split("/").filter(Boolean);
  let last = "";
  for (let i = 0; i < segments.length; i++) {
    last =
      segments[i].startsWith("@") && i + 1 < segments.length
        ? `${segments[i]}/${segments[++i]}`
        : segments[i];
  }
  return last;
}

// Whether an exception names the package at a location. A name is matched
// whole, so "argparse" admits neither "argparse-lite" nor "@someone/argparse";
// a name ending in "/" is a scope, and admits every package in it.
export function excepts(prefix, location) {
  const name = packageAt(location);
  return prefix.endsWith("/") ? name.startsWith(prefix) : name === prefix;
}

// An SPDX expression is not a license name. "MIT AND ISC" is satisfied only if
// both are allowed; "(MPL-2.0 OR Apache-2.0)" by either. Treating the whole
// string as a name fails both, and adding both strings to the allowlist
// accepts every other expression that happens to be spelled the same way.
export function satisfies(expression, against = allowed) {
  const tokens = expression
    .replaceAll("(", " ( ")
    .replaceAll(")", " ) ")
    .split(/\s+/)
    .filter(Boolean);
  let position = 0;

  function term() {
    if (tokens[position] === "(") {
      position++;
      const inner = or();
      // The group has to close here. Taking whatever token stands here as
      // the bracket swallows a license name, and "(MIT GPL-3.0" reads as MIT.
      if (tokens[position] !== ")") {
        position = Number.POSITIVE_INFINITY;
        return false;
      }
      position++;
      return inner;
    }
    const name = tokens[position++];
    // Nothing left to read. A package whose license field is empty or missing
    // reaches here, and is refused rather than thrown on, so the gate names
    // the package.
    if (name === undefined) return false;
    // A trailing "+" means this version of the license or later.
    return against.has(name.replace(/\+$/, ""));
  }
  function and() {
    let result = term();
    while (tokens[position] === "AND") {
      position++;
      result = term() && result;
    }
    return result;
  }
  function or() {
    let result = and();
    while (tokens[position] === "OR") {
      position++;
      result = and() || result;
    }
    return result;
  }

  const result = or();
  // An expression this cannot parse to the end is one nobody has read. Refuse
  // it rather than accepting whatever the first token happened to be.
  return position === tokens.length && result;
}

// licenseVerdict holds every shipped package of a lockfile's `packages` to the
// allowlist and the exceptions. It returns the packages refused and the ones
// admitted by exception, each as a line naming the package and its license,
// and how many packages were checked.
export function licenseVerdict(packages, against = allowed, admitted = exceptions) {
  const refused = [];
  const excepted = [];
  let checked = 0;
  for (const [location, entry] of Object.entries(packages)) {
    // The root package is this repository, and dev dependencies do not ship.
    if (!location || entry.dev || entry.devOptional) continue;
    checked++;

    const name = location.replace(/^node_modules\//, "").replace(/\/node_modules\//g, "/");
    const license = entry.license;

    if (!license) {
      refused.push(`${name} declares no license`);
      continue;
    }
    if (satisfies(license, against)) continue;

    const exception = admitted.find((e) => excepts(e.prefix, name) && e.license === license);
    if (exception) {
      excepted.push(`${name} (${license})`);
      continue;
    }
    refused.push(`${name} is ${license}`);
  }
  return { refused: refused.sort(), excepted, checked };
}

// The package a bare import specifier names: "@scope/name" or "name", without
// any path inside it. A relative path, an absolute one and a builtin scheme
// name no package.
function packageNamed(specifier) {
  if (/^(\.|\/|[a-z]+:)/.test(specifier)) return "";
  const parts = specifier.split("/");
  return specifier.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
}

// Every specifier a file imports at run time: an import or re-export that is
// not type-only and a dynamic import in TypeScript, and an `@import` in a
// stylesheet.
function importsOf(file, text) {
  if (file.endsWith(".css")) {
    return [...text.matchAll(/@import\s+(?:url\()?["']([^"']+)["']/g)].map((m) => m[1]);
  }
  const out = [];
  const visit = (node) => {
    if (
      (ts.isImportDeclaration(node) && !node.importClause?.isTypeOnly) ||
      (ts.isExportDeclaration(node) && node.moduleSpecifier && !node.isTypeOnly)
    ) {
      if (ts.isStringLiteral(node.moduleSpecifier)) out.push(node.moduleSpecifier.text);
    } else if (
      ts.isCallExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ImportKeyword &&
      node.arguments[0] &&
      ts.isStringLiteral(node.arguments[0])
    ) {
      out.push(node.arguments[0].text);
    }
    ts.forEachChild(node, visit);
  };
  visit(parse(text, file));
  return out;
}

// shippedImports is every development dependency the shipped source imports,
// as a line naming the package and the file, and how many import specifiers
// it read. It takes the source as { path relative to src/: text } and a
// lockfile's `packages`. Tests and the test harness under src/test/ are not
// shipped and are not read.
export function shippedImports(files, packages) {
  const found = [];
  let read = 0;
  for (const [file, text] of Object.entries(files)) {
    if (file.includes(".test.") || file.split(/[\\/]/)[0] === "test") continue;
    for (const specifier of importsOf(file, text)) {
      read++;
      const name = packageNamed(specifier);
      const entry = name && packages[`node_modules/${name}`];
      if (entry && (entry.dev || entry.devOptional)) {
        found.push(`${name} is imported by src/${file} but is a development dependency`);
      }
    }
  }
  return { found: [...new Set(found)].sort(), read };
}

// What to say where no shipped dependency or no import was read, or nothing
// where both were. A lockfile whose every entry is marked for development, or
// one that moved, refuses no license for the reason that it examined none, and
// a source tree read from the wrong root passes the bundle check the same way.
export function checkedNothing(checked, imports) {
  if (checked === 0)
    return "no shipped dependency was found in the lockfile, so this checked nothing";
  if (imports === 0)
    return "no import was read from the interface's source, so this checked nothing";
  return "";
}

// Run when this is the program, not when a test imports it.
//
// A script that reads the lockfile at import time cannot have a test beside
// it: the test would read it, and a dependency under the wrong license would
// call process.exit and take the runner down. What is exported above is the
// policy; this is the program.
if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  if (allowed.size === 0) {
    console.error("no allowlist given. The list lives in the Makefile; run `make licenses`.");
    process.exit(2);
  }
  const lock = JSON.parse(readFileSync(lockfile, "utf8"));
  const { refused, excepted, checked } = licenseVerdict(lock.packages);
  const source = Object.fromEntries(
    sourceFiles({ ext: [".ts", ".tsx", ".css"] }).map((file) => [
      path.relative(SRC, file),
      readFileSync(file, "utf8"),
    ]),
  );
  const { found: imported, read } = shippedImports(source, lock.packages);

  const nothing = checkedNothing(checked, read);
  if (nothing) {
    console.error(nothing);
    process.exit(1);
  }
  if (imported.length > 0) {
    for (const line of imported) console.error(line);
    console.error(
      `\n${imported.length} development dependenc${imported.length === 1 ? "y is" : "ies are"} ` +
        `in the bundle. Move each to dependencies, where its license is checked.`,
    );
    process.exit(1);
  }
  if (refused.length === 0) {
    const note = excepted.length ? `, ${excepted.length} by documented exception` : "";
    console.log(
      `every shipped interface dependency is permissively licensed (${checked} of them${note})`,
    );
    process.exit(0);
  }
  for (const line of refused) console.error(line);
  console.error(
    `\n${refused.length} shipped dependency license(s) outside the allowlist. ` +
      `Either the dependency goes, or the exception is written down with a reason.`,
  );
  process.exit(1);
}
