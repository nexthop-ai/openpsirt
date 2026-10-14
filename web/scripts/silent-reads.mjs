// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// A read defaulted to an empty list where nothing in its file says the read
// failed. `x.data?.items ?? []` is the same empty list whether the server
// answered none or never answered, so a file drawing from it has to consult
// the read's failure somewhere, or the screen states a negative nobody read.
//
// A read that may quietly offer nothing, such as a suggestion list, carries
// `silent-read:` and its reason in a comment on the line or the line above.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

// A query's data defaulted to an empty list: `name.data ?? []`, or one field
// of it, `name.data?.items ?? []`, the name being whatever stands before
// `.data`. A
// call standing there, `useThing().data ?? []`, has no name anything else in
// the file can consult, so it is reported unless allowed.
const DEFAULTED = /([\w$.]*?)(\))?\.data(?:\?\.[\w$]+)?\s*\?\?\s*\[\]/g;

const escaped = (name) => name.replace(/[.$]/g, (c) => `\\${c}`);

// Whether the file consults the named read's failure: its error or status
// directly, through `known` or `<Count of=…>` or `<Unread of=…>`, among a list
// of reads searched for one that failed, or by handing it whole as `query` to a
// component that draws its arms, `Reading` among them.
function consulted(name, source) {
  const n = escaped(name);
  const ways = [
    new RegExp(`\\b${n}\\.(isError|error|isSuccess|status)\\b`),
    new RegExp(`\\bquery=\\{${n}\\}`),
    new RegExp(`\\bknown\\(\\[?[^)]*\\b${n}\\b`),
    new RegExp(`\\bof=\\{\\[?[^}]*\\b${n}\\b`),
    new RegExp(`\\[[^\\]]*\\b${n}\\b[^\\]]*\\]\\s*\\.(find|some|filter)\\([^)]*\\)?[^)]*isError`),
  ];
  return ways.some((way) => way.test(source));
}

// Every defaulted read in one file whose failure the file never consults, as
// "file:line: name", and how many defaulted reads it examined.
export function silentReads(file, source) {
  const lines = source.split("\n");
  const found = [];
  let examined = 0;
  for (let match = DEFAULTED.exec(source); match; match = DEFAULTED.exec(source)) {
    examined++;
    const line = source.slice(0, match.index).split("\n").length;
    const here = `${lines[line - 2] ?? ""}\n${lines[line - 1] ?? ""}`;
    if (/silent-read:[ \t]*\S/.test(here)) continue;
    const name = match[2] ? "" : (match[1] ?? "");
    if (name !== "" && consulted(name, source)) continue;
    found.push(`${file}:${line}: ${name || "a call's data"}`);
  }
  return { examined, found };
}

function sources(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return /\.tsx?$/.test(path) && !/\.test\.tsx?$/.test(path) && !path.endsWith(".d.ts")
      ? [path]
      : [];
  });
}

// Every silent read under src, and how many files and reads were examined.
export function sweep() {
  const files = sources(join(import.meta.dirname, "..", "src"));
  let examined = 0;
  const found = [];
  for (const file of files) {
    const one = silentReads(file, readFileSync(file, "utf8"));
    examined += one.examined;
    found.push(...one.found);
  }
  return { files: files.length, examined, found };
}

if (process.argv[1] === import.meta.filename) {
  const { files, examined, found } = sweep();
  if (files === 0 || examined === 0) {
    console.error("silent-reads: no reads were found in the source, so this checked nothing");
    process.exit(1);
  }
  for (const each of found) console.error(each);
  if (found.length > 0) {
    console.error(
      `silent-reads: ${found.length} read(s) default to an empty list with no failure arm in their file`,
    );
    process.exit(1);
  }
  console.log(
    `silent-reads: ${examined} defaulted reads in ${files} files, each with a failure arm`,
  );
}
