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
import { interfaceSources, SRC } from "./parsed.mjs";

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

// The elements one child of a head draws: itself, what a fragment holds, or
// what a condition in braces draws on either arm.
function drawn(node) {
  if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node)) return [node];
  if (ts.isJsxFragment(node)) return node.children.flatMap(drawn);
  if (ts.isJsxExpression(node)) return node.expression ? drawn(node.expression) : [];
  if (ts.isParenthesizedExpression(node)) return drawn(node.expression);
  if (ts.isBinaryExpression(node)) return drawn(node.right);
  if (ts.isConditionalExpression(node)) return [...drawn(node.whenTrue), ...drawn(node.whenFalse)];
  return [];
}

const tagOf = (element) =>
  (ts.isJsxElement(element) ? element.openingElement : element).tagName.getText();

// What a function body returns, from any return in it outside a nested
// function, or the expression an arrow function is.
function returned(body) {
  if (!ts.isBlock(body)) return drawn(body);
  const out = [];
  const visit = (node) => {
    if (ts.isFunctionLike(node)) return;
    if (ts.isReturnStatement(node) && node.expression) out.push(...drawn(node.expression));
    ts.forEachChild(node, visit);
  };
  body.statements.forEach(visit);
  return out;
}

// What each component declared in one source draws at its root, by name: the
// spans it would place directly under a head it is drawn in. A component is a
// capitalized function, declared or bound to a name.
export function componentRoots(file, source) {
  const roots = new Map();
  const add = (name, body) => roots.set(name, { file, source, drawn: returned(body) });
  const visit = (node) => {
    if (ts.isFunctionDeclaration(node) && node.name && /^[A-Z]/.test(node.name.text) && node.body) {
      add(node.name.text, node.body);
    }
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      /^[A-Z]/.test(node.name.text) &&
      node.initializer &&
      (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))
    ) {
      add(node.name.text, node.initializer.body);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return roots;
}

// Every span directly under a screen head, drawn there by a condition, or at
// the root of a component drawn there, that holds an action and is not marked
// `noprint`, as "file:line".
export function printedActions(file, source, components = new Map()) {
  const found = new Set();
  let examined = 0;
  const check = (child, where, text) => {
    if (ts.isJsxSelfClosingElement(child) || tagOf(child) !== "span") return;
    examined++;
    if (/\bnoprint\b/.test(classOf(child.openingElement))) return;
    if (!ACTION.test(child.getText())) return;
    const line = text.getLineAndCharacterOfPosition(child.getStart()).line + 1;
    found.add(`${where}:${line}`);
  };
  const visit = (node) => {
    if (ts.isJsxElement(node) && /\bscreen-head\b/.test(classOf(node.openingElement))) {
      for (const child of node.children.flatMap(drawn)) {
        const component = components.get(tagOf(child));
        if (component) {
          for (const inner of component.drawn) check(inner, component.file, component.source);
        } else {
          check(child, file, source);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { examined, found: [...found] };
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
  const found = new Set();
  const sources = interfaceSources()
    .filter(({ file }) => file.endsWith(".tsx"))
    .map(({ file, source }) => ({ file: path.relative(SRC, file), source }));
  const components = new Map();
  for (const { file, source } of sources) {
    for (const [name, root] of componentRoots(file, source)) components.set(name, root);
  }
  for (const { file, source } of sources) {
    const one = printedActions(file, source, components);
    examined += one.examined;
    for (const each of one.found) found.add(each);
  }
  const hidden = hiddenByPosition(readFileSync(path.join(SRC, "styles", "print.css"), "utf8"));
  return { examined, found: [...found], hidden };
}
