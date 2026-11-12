// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Invalidations that reach no read.
//
// TanStack Query matches an invalidation by prefix, and a key nothing reads
// matches nothing without a word: the write succeeds, the screen keeps what it
// had, and a control that saved looks as though it did not. So every key an
// invalidation names is held against the keys the reads are declared with.
//
// Parsed rather than matched, and only as far as the keys are literal. A key
// is read up to its first element that is not a string, and that part is what
// is compared: an invalidation of ["home"] reaches a read of
// ["home", "trend", scope], and one of ["trend"] does not. A read whose key
// turns into an expression after its literal part may still match a longer
// invalidation, so it is counted as one.
//
// An invalidation whose key is a name is resolved to the literal it names: a
// constant holding an array, or the variable of a `for … of` over a literal
// list of arrays, which is one invalidation per entry. A shorthand
// `{ queryKey }` is the same name. A key opening on a name is resolved the same
// way: a constant holding a string, or the variable of a `for … of` over a
// literal list of strings, or over a constant holding one, which is one
// invalidation per word. Any other key
// it cannot read is reported, an invalidation opening on a name it cannot
// resolve included, and so are options handed over as anything but an object
// literal, so a key nobody can check fails the gate rather than passing it. A
// read whose key opens on a name it cannot resolve is reported too.
import path from "node:path";
import ts from "typescript";

import { interfaceSources, parse, SRC } from "./parsed.mjs";

// The string elements a key opens with, and whether anything follows them.
function literalPrefix(array) {
  const words = [];
  for (const element of array.elements) {
    if (ts.isStringLiteral(element) || ts.isNoSubstitutionTemplateLiteral(element)) {
      words.push(element.text);
    } else {
      return { words, open: true };
    }
  }
  return { words, open: false };
}

// The expression a `queryKey:` property holds, or the name a shorthand
// `{ queryKey }` stands for.
function keyOf(object) {
  for (const property of object.properties) {
    if (ts.isPropertyAssignment(property) && property.name.getText() === "queryKey") {
      return property.initializer;
    }
    if (ts.isShorthandPropertyAssignment(property) && property.name.text === "queryKey") {
      return property.name;
    }
  }
  return null;
}

// An expression with any `as`, `satisfies` or parentheses around it taken off.
function bare(node) {
  while (
    ts.isAsExpression(node) ||
    ts.isSatisfiesExpression(node) ||
    ts.isParenthesizedExpression(node)
  ) {
    node = node.expression;
  }
  return node;
}

// The expression a name is bound to where `at` stands, and whether it is the
// variable of a `for … of` over that expression. Only a binding by a
// declaration in an enclosing block, or by an enclosing loop, is found.
function binding(name, at) {
  for (let node = at.parent; node; node = node.parent) {
    if (
      ts.isForOfStatement(node) &&
      ts.isVariableDeclarationList(node.initializer) &&
      node.initializer.declarations.some((d) => ts.isIdentifier(d.name) && d.name.text === name)
    ) {
      return { value: node.expression, each: true };
    }
    if (ts.isBlock(node) || ts.isSourceFile(node)) {
      for (const statement of node.statements) {
        if (!ts.isVariableStatement(statement)) continue;
        for (const d of statement.declarationList.declarations) {
          if (ts.isIdentifier(d.name) && d.name.text === name && d.initializer) {
            return { value: d.initializer, each: false };
          }
        }
      }
    }
  }
  return null;
}

// The literal arrays a key stands for: itself where it is one, what a name is
// bound to where it is a name, and null where neither can be read.
function literalKeys(key) {
  const node = bare(key);
  if (ts.isArrayLiteralExpression(node)) return [node];
  if (!ts.isIdentifier(node)) return null;
  const bound = binding(node.text, node);
  if (!bound) return null;
  const value = bare(bound.value);
  if (!ts.isArrayLiteralExpression(value)) return null;
  if (!bound.each) return [value];
  const entries = value.elements.map(bare);
  return entries.every((entry) => ts.isArrayLiteralExpression(entry)) ? entries : null;
}

const isWord = (node) => ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node);

// The words a key's first element stands for where it is a name: what a
// constant holding a string is bound to, or each word of a literal list a
// `for … of` loops over. Null where the element is not a name, or is one bound
// to nothing literal.
function openingWords(array) {
  const first = array.elements.length > 0 ? bare(array.elements[0]) : null;
  if (!first || !ts.isIdentifier(first)) return null;
  const bound = binding(first.text, first);
  if (!bound) return null;
  let value = bare(bound.value);
  if (!bound.each) return isWord(value) ? [value.text] : null;
  // The list looped over may itself be a name, bound to a literal list.
  if (ts.isIdentifier(value)) {
    const list = binding(value.text, value);
    value = list && !list.each ? bare(list.value) : value;
  }
  if (!ts.isArrayLiteralExpression(value)) return null;
  const entries = value.elements.map(bare);
  return entries.every(isWord) ? entries.map((entry) => entry.text) : null;
}

// The literal prefixes a key stands for, one per word its opening name can
// hold, or null where the key opens on something that cannot be read.
function prefixesOf(array) {
  const words = openingWords(array);
  if (words) {
    const rest = literalPrefix({ elements: array.elements.slice(1) });
    return words.map((word) => ({ words: [word, ...rest.words], open: rest.open }));
  }
  const prefix = literalPrefix(array);
  if (array.elements.length > 0 && prefix.words.length === 0) return null;
  return [prefix];
}

// What a call on the query client does with the options it is handed: an
// invalidation, something else that names a key without declaring a read, or
// nothing of the kind.
const NAMING = new Set(["cancelQueries", "refetchQueries", "removeQueries", "resetQueries"]);

function calledAs(object) {
  const call = object.parent;
  if (!call || !ts.isCallExpression(call)) return "";
  const callee = call.expression;
  return ts.isPropertyAccessExpression(callee) ? callee.name.text : "";
}

// keysIn reads one source file: the keys its reads declare and the keys its
// invalidations name.
export function keysIn(text, file = "x.tsx", source = parse(text, file)) {
  const reads = [];
  const invalidates = [];
  const walk = (node) => {
    // Options handed over as anything but an object literal hold a key that
    // cannot be read here.
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === "invalidateQueries" &&
      node.arguments.length > 0 &&
      !ts.isObjectLiteralExpression(bare(node.arguments[0]))
    ) {
      const at = source.getLineAndCharacterOfPosition(node.arguments[0].getStart()).line + 1;
      invalidates.push({ at, words: [], open: true, unread: true });
    }
    if (ts.isObjectLiteralExpression(node)) {
      const key = keyOf(node);
      if (key) {
        const at = source.getLineAndCharacterOfPosition(key.getStart()).line + 1;
        const called = calledAs(node);
        const keys = literalKeys(key);
        if (called === "invalidateQueries") {
          const prefixes = keys && keys.map(prefixesOf);
          if (prefixes && prefixes.every(Boolean)) {
            for (const each of prefixes.flat()) invalidates.push({ at, ...each });
          } else {
            invalidates.push({ at, words: [], open: true, unread: true });
          }
        } else if (keys && !NAMING.has(called)) {
          for (const each of keys) {
            const prefixes = prefixesOf(each);
            if (prefixes) for (const prefix of prefixes) reads.push({ at, ...prefix });
            else reads.push({ at, words: [], open: true, unread: true });
          }
        }
      }
    }
    ts.forEachChild(node, walk);
  };
  walk(source);
  return { reads, invalidates };
}

// reaches says whether an invalidation's literal words can match a read.
export function reaches(invalidation, read) {
  const asked = invalidation.words;
  if (asked.length === 0) return true;
  if (read.words.length >= asked.length) return asked.every((word, i) => read.words[i] === word);
  // The read's key is shorter in its literal part: it can match only where it
  // goes on past that part, and only where the part it has agrees.
  return read.open && read.words.every((word, i) => asked[i] === word);
}

// stale is every invalidation, across a set of files, that reaches no read in
// any of them, and every invalidation or read whose key could not be read,
// which is reported with a null key. A read whose key opens on something
// unreadable would otherwise reach every invalidation.
export function stale(files) {
  const reads = files.flatMap((each) => each.reads).filter((read) => !read.unread);
  const found = [];
  for (const each of files) {
    for (const read of each.reads) {
      if (read.unread) found.push({ file: each.file, at: read.at, key: null });
    }
    for (const invalidation of each.invalidates) {
      if (invalidation.unread) {
        found.push({ file: each.file, at: invalidation.at, key: null });
      } else if (!reads.some((read) => reaches(invalidation, read))) {
        found.push({ file: each.file, at: invalidation.at, key: invalidation.words });
      }
    }
  }
  return found;
}

// The whole tree: every invalidation that reaches nothing, and how many
// invalidations and reads were examined.
export function sweep() {
  const files = interfaceSources().map(({ file, text, source }) => ({
    file: path.relative(SRC, file),
    ...keysIn(text, file, source),
  }));
  return {
    found: stale(files),
    invalidations: files.reduce((n, each) => n + each.invalidates.length, 0),
    reads: files.reduce((n, each) => n + each.reads.length, 0),
  };
}
