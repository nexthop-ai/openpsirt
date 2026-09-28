// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Files of the web source a test reads as text. The tests are typed without
// Node's own declarations, so the reading is done here, in plain ESM.

import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

const web = path.join(import.meta.dirname, "..");

// Every stylesheet under src/styles, as its text, in name order.
export function stylesheets() {
  const styles = path.join(web, "src", "styles");
  return readdirSync(styles)
    .filter((name) => name.endsWith(".css"))
    .sort()
    .map((name) => readFileSync(path.join(styles, name), "utf8"));
}

// The page every screen is mounted in, as its text.
export function indexHtml() {
  return readFileSync(path.join(web, "index.html"), "utf8");
}
