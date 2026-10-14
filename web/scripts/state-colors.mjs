// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// A state chip drawn in the "done" color whose words say something is wrong.
// Green reads as good news, which is the one reading a failure must not get.
//
// A chip is written two ways, and both are read. A hand-written chip names its
// class in the markup. A computed chip takes its class and its words from a
// record — `{ cls: "agreed", said: "Approved" }` — and the markup only
// interpolates them, so the record is what is checked.

import { readFileSync } from "node:fs";
import path from "node:path";
import ts from "typescript";
import { cssRules } from "./class-rules.mjs";
import { interfaceSources, parse, sourceFiles, SRC } from "./parsed.mjs";

// A word that names something wrong.
const TROUBLE = /\b(fail\w*|stopped|never|limit|refused|broken|error)\b/i;

// The properties of a record that carry a chip's class, and the ones that
// carry its words.
const CLASS_PROPS = new Set(["cls", "tone"]);
const WORD_PROPS = new Set(["said", "word", "label", "means"]);

// doneClasses is every state class a stylesheet draws in the done color: a
// `.state.<name>` rule whose color is the ok token.
export function doneClasses(css) {
  const out = new Set();
  for (const { selector, body } of cssRules(css)) {
    if (!/--c\s*:\s*var\(--ok\)/.test(body)) continue;
    for (const part of selector.split(",")) {
      const match = /^\.state\.([-\w]+)$/.exec(part.trim());
      if (match) out.add(match[1]);
    }
  }
  return out;
}

// The text of a string literal or of a template's literal parts, or null for
// anything else.
function literalText(node) {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isTemplateExpression(node)) {
    return [node.head.text, ...node.templateSpans.map((span) => span.literal.text)].join(" ");
  }
  return null;
}

// doneButTrouble is every chip drawn as done whose words say something is
// wrong, as "file:line: words", across a hand-written chip and a record a
// computed chip reads. `done` is the set of classes drawn in the done color.
//
// A hand-written chip's text is everything up to the closing span,
// expressions included, so a word computed from the row is still read.
export function doneButTrouble(file, text, done, source = parse(text, file)) {
  const out = [];
  const lineOf = (index) => text.slice(0, index).split("\n").length;
  const chip = /<span className="state ([^"]*)"[^>]*>([\s\S]*?)<\/span>/g;
  for (let match = chip.exec(text); match; match = chip.exec(text)) {
    const classes = (match[1] ?? "").split(/\s+/);
    const words = match[2] ?? "";
    if (classes.some((each) => done.has(each)) && TROUBLE.test(words)) {
      out.push(`${file}:${lineOf(match.index)}: ${words.replace(/\s+/g, " ").trim()}`);
    }
  }
  const visit = (node) => {
    if (ts.isObjectLiteralExpression(node)) {
      let drawnDone = false;
      const said = [];
      for (const property of node.properties) {
        if (!ts.isPropertyAssignment(property)) continue;
        const name = property.name.getText(source);
        const value = literalText(property.initializer);
        if (value === null) continue;
        if (CLASS_PROPS.has(name) && done.has(value)) drawnDone = true;
        if (WORD_PROPS.has(name)) said.push(value);
      }
      const wrong = said.filter((each) => TROUBLE.test(each));
      if (drawnDone && wrong.length > 0) {
        out.push(
          `${file}:${lineOf(node.getStart(source))}: ${wrong.join(" ").replace(/\s+/g, " ").trim()}`,
        );
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return out;
}

// What every source under src draws, how many files were read, and which
// classes were taken as done.
export function sweep() {
  const done = new Set();
  for (const file of sourceFiles({ ext: [".css"] })) {
    for (const name of doneClasses(readFileSync(file, "utf8"))) done.add(name);
  }
  const files = interfaceSources();
  return {
    files: files.length,
    done: [...done].sort(),
    found: files.flatMap(({ file, text, source }) =>
      doneButTrouble(path.relative(SRC, file), text, done, source),
    ),
  };
}
