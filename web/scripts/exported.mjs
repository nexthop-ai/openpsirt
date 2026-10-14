// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Which exports of the web source nothing else imports.
//
// An export with no importer is a defect rather than spare capacity: a reader
// takes it for an interface something depends on. A module's own use needs no
// export. A test counts as an importer, because exporting for a test is the
// only way a module's pure part is reached from one; so a symbol only its own
// tests reach passes, as it does in the server's check.
//
// It reads the names other files import — an import or re-export clause, a
// destructured dynamic import, and a screen loaded on demand as `m.Name` — rather
// than every word, so a local of the same name, a heading or a comment is not
// taken for an importer. It does not resolve paths: a name imported from any
// module counts for every module exporting it.

import { readFileSync } from "node:fs";
import path from "node:path";
import { sourceFiles, WEB } from "./parsed.mjs";

const declared =
  /^export\s+(?:default\s+)?(?:async\s+)?(?:const|let|function|type|interface|class|enum)\s+([A-Za-z_$][\w$]*)/gm;

// The names one file imports from others.
const clause = /\b(?:import|export)\s+(?:type\s+)?\{([^}]*)\}\s*from\s/g;
const dynamic = /\{([^}]*)\}\s*=\s*await\s+import\(/g;
const lazily = /\bm\.([A-Za-z_$][\w$]*)/g;

export function importedBy(text) {
  const names = new Set();
  for (const pattern of [clause, dynamic]) {
    for (const [, list] of text.matchAll(pattern)) {
      for (const part of list.split(",")) {
        const name = part
          .trim()
          .replace(/^type\s+/, "")
          .split(/\s+as\s+/)[0]
          .trim();
        if (name) names.add(name);
      }
    }
  }
  if (/\bimport\(/.test(text)) for (const [, name] of text.matchAll(lazily)) names.add(name);
  return names;
}

// unnamed takes the source as { file: text } and returns every export no
// other file imports, as "file: name".
export function unnamed(sources) {
  const files = Object.entries(sources).map(([file, text]) => ({
    file,
    text,
    imports: importedBy(text),
  }));
  const found = [];
  let examined = 0;
  for (const { file, text } of files) {
    if (/\.test\.(ts|tsx)$/.test(file)) continue;
    for (const [, name] of text.matchAll(declared)) {
      examined += 1;
      const named = files.some((other) => other.file !== file && other.imports.has(name));
      if (!named) found.push(`${file}: ${name}`);
    }
  }
  return { found: found.sort(), examined };
}

// The web source as the check reads it: the interface and its gate scripts,
// tests included, because a test is an importer.
export function webSources() {
  const out = {};
  for (const dir of ["src", "scripts"]) {
    for (const full of sourceFiles({
      ext: [".ts", ".tsx", ".mjs"],
      tests: true,
      under: path.join(WEB, dir),
    })) {
      out[path.relative(WEB, full)] = readFileSync(full, "utf8");
    }
  }
  return out;
}
