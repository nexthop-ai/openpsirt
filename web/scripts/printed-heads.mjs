// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// A screen's head prints: its title, its breadcrumb, its counts. What is in it
// to press does not, and says so with `noprint` on the span holding it. The
// print sheet hides by that class rather than by position, because a span under
// the head is as often the breadcrumb naming the record as it is a button.

import { readFileSync } from "node:fs";
import path from "node:path";
import ts from "typescript";
import { cssRules } from "./class-rules.mjs";
import { interfaceSources, parse, SRC } from "./parsed.mjs";

// What a person presses: a button, or a link drawn as one. A plain link, such
// as a breadcrumb's, reads as its text on paper and stays.
const ACTION = /<(button|Downloads)\b|className="btn\b/;

function classOf(element) {
  for (const each of element.attributes.properties) {
    if (ts.isJsxAttribute(each) && each.name.getText() === "className" && each.initializer) {
      return each.initializer.getText();
    }
  }
  return "";
}

// Every span directly under a screen head that holds an action and is not
// marked `noprint`, as "file:line".
export function printedActions(file, source) {
  const found = [];
  let examined = 0;
  const visit = (node) => {
    if (ts.isJsxElement(node) && /\bscreen-head\b/.test(classOf(node.openingElement))) {
      for (const child of node.children) {
        if (!ts.isJsxElement(child) || child.openingElement.tagName.getText() !== "span") continue;
        examined++;
        if (/\bnoprint\b/.test(classOf(child.openingElement))) continue;
        if (!ACTION.test(child.getText())) continue;
        const line = source.getLineAndCharacterOfPosition(child.getStart()).line + 1;
        found.push(`${file}:${line}`);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { examined, found };
}

// Every print rule that hides spans under a head by position, as its selector.
export function hiddenByPosition(css) {
  return cssRules(css)
    .flatMap(({ selector, body }) =>
      /display:\s*none/.test(body) ? selector.split(",").map((each) => each.trim()) : [],
    )
    .filter((each) => /\.screen-head\s*>\s*span\b/.test(each));
}

// The whole interface, and the print sheet.
export function sweep() {
  let examined = 0;
  const found = [];
  for (const { file, text } of interfaceSources()) {
    if (!file.endsWith(".tsx")) continue;
    const one = printedActions(path.relative(SRC, file), parse(text, file));
    examined += one.examined;
    found.push(...one.found);
  }
  const hidden = hiddenByPosition(readFileSync(path.join(SRC, "styles", "print.css"), "utf8"));
  return { examined, found, hidden };
}
