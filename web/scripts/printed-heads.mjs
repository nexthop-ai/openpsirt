// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// A screen's head prints: its title, its breadcrumb, its counts. What is in it
// to press does not, and says so with `noprint` on the element holding it. The
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
const PRESSED = /^(button|Downloads)$/;

function classOf(element) {
  for (const each of element.attributes.properties) {
    if (ts.isJsxAttribute(each) && each.name.getText() === "className" && each.initializer) {
      return each.initializer.getText();
    }
  }
  return "";
}

// The elements one child of a head draws: itself, what a fragment holds, what
// a condition in braces draws on either arm, or what a function handed to a
// call draws, as a list mapped to rows.
function drawn(node) {
  if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node)) return [node];
  if (ts.isJsxFragment(node)) return node.children.flatMap(drawn);
  if (ts.isJsxExpression(node)) return node.expression ? drawn(node.expression) : [];
  if (ts.isParenthesizedExpression(node)) return drawn(node.expression);
  if (ts.isBinaryExpression(node)) return drawn(node.right);
  if (ts.isConditionalExpression(node)) return [...drawn(node.whenTrue), ...drawn(node.whenFalse)];
  if (ts.isCallExpression(node)) {
    return node.arguments.flatMap((each) =>
      ts.isArrowFunction(each) || ts.isFunctionExpression(each) ? returned(each.body) : [],
    );
  }
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
// elements it would place directly under a head it is drawn in. A component is a
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

// Every action drawn under a screen head, directly, by a condition, inside
// another element, or by a component drawn there, that no element marked
// `noprint` holds, as "file:line".
//
// `declared` holds each source's components by file. A tag names the component
// its own file declares, or the one its import names; two files declaring one
// name are told apart that way.
export function printedActions(file, source, declared = new Map(), hidden = ["noprint"]) {
  const offPaper = new RegExp(`(^|[\\s"'])(${hidden.join("|")})(?=[\\s"']|$)`);
  const components = visibleIn(file, source, declared);
  const found = new Set();
  let examined = 0;
  let reported = 0;
  const report = (element, text, where) => {
    reported++;
    const line = text.getLineAndCharacterOfPosition(element.getStart()).line + 1;
    found.add(`${where}:${line}`);
  };
  // Whether anything under an element is marked to stay off paper.
  const marksInside = (element) => {
    let marked = false;
    const visit = (node) => {
      if (
        (ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) &&
        /\bnoprint\b/.test(classOf(node))
      ) {
        marked = true;
      }
      if (!marked) ts.forEachChild(node, visit);
    };
    ts.forEachChild(element, visit);
    return marked;
  };
  // One element and what it holds. `seen` keeps a component drawing itself
  // from being followed forever.
  const check = (element, where, text, seen) => {
    examined++;
    const opening = ts.isJsxElement(element) ? element.openingElement : element;
    if (offPaper.test(classOf(opening))) return;
    const component = components.get(tagOf(element));
    if (component && !seen.has(component)) {
      const next = new Set(seen).add(component);
      for (const inner of component.drawn) check(inner, component.file, component.source, next);
      return;
    }
    if (!ACTION.test(element.getText())) return;
    if (PRESSED.test(tagOf(element)) || /^"btn\b/.test(classOf(opening))) {
      report(element, text, where);
      return;
    }
    const before = reported;
    if (ts.isJsxElement(element)) {
      for (const child of element.children.flatMap(drawn)) check(child, where, text, seen);
    }
    // An action somewhere this walk does not follow, with no mark beside it.
    if (reported === before && !marksInside(element)) {
      report(element, text, where);
    }
  };
  const visit = (node) => {
    if (ts.isJsxElement(node) && /\bscreen-head\b/.test(classOf(node.openingElement))) {
      for (const child of node.children.flatMap(drawn)) check(child, file, source, new Set());
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { examined, found: [...found] };
}

// The components one source can draw, by the name it draws them under: its own,
// and each one a relative import brings in.
function visibleIn(file, source, declared) {
  const visible = new Map();
  for (const statement of source.statements) {
    if (!ts.isImportDeclaration(statement)) continue;
    const from = statement.moduleSpecifier.text;
    const bindings = statement.importClause?.namedBindings;
    if (!from.startsWith(".") || !bindings || !ts.isNamedImports(bindings)) continue;
    const target = declared.get(path.join(path.dirname(file), from) + ".tsx");
    if (!target) continue;
    for (const each of bindings.elements) {
      const root = target.get((each.propertyName ?? each.name).text);
      if (root) visible.set(each.name.text, root);
    }
  }
  for (const [name, root] of declared.get(file) ?? []) visible.set(name, root);
  return visible;
}

// Every print rule that hides spans under a head by position, as its selector.
export function hiddenByPosition(css) {
  return cssRules(css)
    .flatMap(({ selector, body }) =>
      /display:\s*none/.test(body) ? selector.split(",").map((each) => each.trim()) : [],
    )
    .filter((each) => /\.screen-head\s*>\s*span\b/.test(each));
}

// Every class the print sheet hides wherever it is drawn, from a rule whose
// selector is that class alone.
export function hiddenClasses(css) {
  return cssRules(css)
    .flatMap(({ selector, body }) =>
      /display:\s*none/.test(body) ? selector.split(",").map((each) => each.trim()) : [],
    )
    .flatMap((each) => (/^\.[\w-]+$/.test(each) ? [each.slice(1)] : []));
}

// The whole interface, and the print sheet.
export function sweep() {
  let examined = 0;
  const found = new Set();
  const sources = interfaceSources()
    .filter(({ file }) => file.endsWith(".tsx"))
    .map(({ file, source }) => ({ file: path.relative(SRC, file), source }));
  const declared = new Map(sources.map(({ file, source }) => [file, componentRoots(file, source)]));
  const sheet = readFileSync(path.join(SRC, "styles", "print.css"), "utf8");
  const offPaper = hiddenClasses(sheet);
  for (const { file, source } of sources) {
    const one = printedActions(file, source, declared, offPaper);
    examined += one.examined;
    for (const each of one.found) found.add(each);
  }
  const hidden = hiddenByPosition(sheet);
  return { examined, found: [...found], hidden };
}
