// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

// Every stylesheet under src/styles, as its text, in name order.
export function stylesheets() {
  const styles = path.join(import.meta.dirname, "..", "src", "styles");
  return readdirSync(styles)
    .filter((name) => name.endsWith(".css"))
    .sort()
    .map((name) => readFileSync(path.join(styles, name), "utf8"));
}
