// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The license of everything the interface ships, against the allowlist.
//
// The Go side of this has been checked since the build was written: nothing
// ships unless its license is permissive, because a self-hosted tool is
// redistributed by whoever installs it and a copyleft dependency makes that
// their problem. The interface was not checked at all. It ships too — the
// bundle is built into the binary — so half the shipped tree was going out
// against a policy the other half was held to.
//
// The platform product that would have covered it, dependency review, is a
// paid add-on on a private repository and is not enabled. This is not a
// stand-in for it: it runs locally with one command, which the action never
// could, and that is what REQ-75 actually asks for.
//
// Development dependencies are unrestricted, as they are on the Go side.
// Vite, ESLint and the type checker are not in the bundle, and a build tool's
// license binds whoever builds rather than whoever installs.
import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const here = path.dirname(new URL(import.meta.url).pathname);
const lockfile = path.join(here, "..", "package-lock.json");

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
// Passed in, like the allowlist above and for the same reason this file states
// there: the exceptions were hardcoded here, twenty-seven lines under the
// comment forbidding exactly that, so one license policy had two exception
// lists in two files and neither mentioned the other. Granting a fourth
// exception had no single place to be written.
//
// Each entry is `prefix=license`, so the license still has to match: an
// exception admits one package's actual license rather than waving the package
// through. The prefix is anchored to a path boundary, because a prefix match
// on "argparse" would also admit a package named "argparse-lite".
const exceptions = (process.env.LICENSE_EXCEPTIONS ?? "")
  .split(",")
  .map((each) => each.trim())
  .filter(Boolean)
  .map((each) => {
    const [prefix, license] = each.split("=");
    if (!prefix || !license) {
      console.error(`LICENSE_EXCEPTIONS entry ${each} is not prefix=license.`);
      process.exit(2);
    }
    const quoted = prefix.replace(/[-[\]{}()*+?.\\^$|]/g, "\\$&");
    return {
      match: new RegExp(`(^|/)${quoted}${prefix.endsWith("/") ? "" : "($|/)"}`),
      license,
    };
  });

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
      position++; // the closing parenthesis
      return inner;
    }
    const name = tokens[position++];
    // Nothing left to read. A package whose license field is empty or missing
    // reaches here, and throwing was a worse answer than refusing: the gate
    // exited with a stack trace rather than naming the package.
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
  const lock = JSON.parse(await readFile(lockfile, "utf8"));

  const refused = [];
  const excepted = [];
  let checked = 0;

  for (const [location, entry] of Object.entries(lock.packages)) {
    // The root package is this repository, and dev dependencies do not ship.
    if (!location || entry.dev || entry.devOptional) continue;
    checked++;

    const name = location.replace(/^node_modules\//, "").replace(/\/node_modules\//g, "/");
    const license = entry.license;

    if (!license) {
      refused.push(`${name} declares no license`);
      continue;
    }
    if (satisfies(license)) continue;

    const exception = exceptions.find((e) => e.match.test(name) && e.license === license);
    if (exception) {
      excepted.push(`${name} (${license})`);
      continue;
    }
    refused.push(`${name} is ${license}`);
  }

  if (refused.length === 0) {
    const note = excepted.length ? `, ${excepted.length} by documented exception` : "";
    console.log(
      `every shipped interface dependency is permissively licensed (${checked} of them${note})`,
    );
    process.exit(0);
  }
  for (const line of refused.sort()) console.error(line);
  console.error(
    `\n${refused.length} shipped dependency license(s) outside the allowlist. ` +
      `Either the dependency goes, or the exception is written down with a reason.`,
  );
  process.exit(1);
}
