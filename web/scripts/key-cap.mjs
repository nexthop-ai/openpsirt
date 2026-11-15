// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The rules drawing the key cap a primary button carries, read from the
// stylesheet that holds them, for the test beside this file.
import { readFileSync } from "node:fs";
import path from "node:path";
import { cssRules } from "./class-rules.mjs";
import { SRC } from "./parsed.mjs";

export function keyCapRules() {
  const css = readFileSync(path.join(SRC, "styles", "frame.css"), "utf8");
  return cssRules(css).filter((rule) => rule.selector === "kbd.onbtn");
}
