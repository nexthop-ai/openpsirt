// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Which exports of the web source nothing else names.
//
// An export with no importer is a defect rather than spare capacity: a reader
// takes it for an interface something depends on. A module's own use needs no
// export. A test counts as an importer, because exporting for a test is the
// only way a module's pure part is reached from one; so a symbol only its own
// tests reach passes, as it does in the server's check.
//
// It reads names rather than a module graph: an export is used where another
// file names it as a word. That can pass a name that is also an ordinary word
// in a comment elsewhere, and cannot fail one that is imported.

import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

const web = path.join(import.meta.dirname, "..");

const declared =
  /^export\s+(?:default\s+)?(?:async\s+)?(?:const|let|function|type|interface|class|enum)\s+([A-Za-z_$][\w$]*)/gm;

// Every source file under a directory, the generated API types left out: they
// are the server's document rather than code anybody here wrote.
function files(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...files(full));
    else if (/\.(ts|tsx|mjs)$/.test(entry.name) && !entry.name.endsWith(".d.ts")) out.push(full);
  }
  return out;
}

// unnamed takes the source as { file: text } and returns every export no
// other file names, as "file: name".
export function unnamed(sources) {
  const names = Object.entries(sources).map(([file, text]) => ({
    file,
    text,
    words: new Set(text.match(/[A-Za-z_$][\w$]*/g) ?? []),
  }));
  const found = [];
  let examined = 0;
  for (const { file, text } of names) {
    if (/\.test\.(ts|tsx)$/.test(file)) continue;
    for (const [, name] of text.matchAll(declared)) {
      examined += 1;
      const named = names.some((other) => other.file !== file && other.words.has(name));
      if (!named) found.push(`${file}: ${name}`);
    }
  }
  return { found: found.sort(), examined };
}

// The web source as the check reads it.
export function webSources() {
  const out = {};
  for (const dir of ["src", "scripts"]) {
    for (const full of files(path.join(web, dir))) {
      out[path.relative(web, full)] = readFileSync(full, "utf8");
    }
  }
  return out;
}
