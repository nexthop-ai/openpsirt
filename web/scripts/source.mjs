// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Files of the web source a test reads as text. The tests are typed without
// Node's own declarations, so the reading is done here, in plain ESM.

import { readFileSync } from "node:fs";
import path from "node:path";
import { sourceFiles, WEB } from "./parsed.mjs";

// Every stylesheet of the interface, as its text, in path order: the set every
// stylesheet check reads.
export function stylesheets() {
  return sourceFiles({ ext: [".css"] }).map((file) => readFileSync(file, "utf8"));
}

// The page every screen is mounted in, as its text.
export function indexHtml() {
  return readFileSync(path.join(WEB, "index.html"), "utf8");
}
