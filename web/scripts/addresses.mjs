// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Addresses into this application, held to its route table.
//
// The table in src/app/routes.json is the one definition of which addresses
// the router answers and which query parameters a link may set on each. The
// router is built from it, the server's link builder is tested against it, and
// this reads the interface's source for the rest:
//
// - An address written out whole is matched against the table, query
//   parameters included. One the router does not know lands on the not-found
//   screen, and a parameter the screen does not read opens it on its default.
// - An address put together from parts — a template with a substitution, or a
//   string joined onto something — is built in src/app/routes.ts and nowhere
//   else, because a part left unescaped or a segment spelled wrong is exactly
//   what a hand-built address gets wrong and what reading one cannot see.
// - Every query parameter the table lists for a route is one the screen there
//   reads, so the table cannot promise a parameter nothing acts on. A read is
//   asked of query parameters, never of a map or a set that happens to hold
//   the same word.
//
// An API address opens on /v1, or is joined onto a call that builds one, and
// is not an address into this application.
import { readFileSync, statSync } from "node:fs";
import path from "node:path";
import ts from "typescript";

import { interfaceSources, parse } from "./parsed.mjs";

const here = import.meta.dirname;
const src = path.join(here, "..", "src");

// The one file an address may be put together in.
const BUILDER = path.join("app", "routes.ts");

export function table() {
  return JSON.parse(readFileSync(path.join(src, "app", "routes.json"), "utf8"));
}

function matches(pattern, address) {
  const want = pattern.split("/");
  const got = address.split("/");
  if (want.length !== got.length) return false;
  return want.every((part, i) => (part.startsWith(":") ? got[i] !== "" : part === got[i]));
}

// unrouted says why an address is not one the router answers, or "" where it
// is. A pattern's segment starting with a colon matches any one non-empty
// segment. A fragment is the screen's business and is not checked.
export function unrouted(routes, address) {
  const [whole] = address.split("#");
  const cut = whole.indexOf("?");
  const pathname = cut < 0 ? whole : whole.slice(0, cut);
  const query = cut < 0 ? "" : whole.slice(cut + 1);
  for (const route of Object.values(routes)) {
    if (!matches(route.path, pathname)) continue;
    for (const key of new URLSearchParams(query).keys()) {
      if (!(route.query ?? []).includes(key)) {
        return `the screen at ${route.path} does not read "${key}"`;
      }
    }
    return "";
  }
  return `no route matches ${pathname}`;
}

// The text of a literal, with each substitution of a template written ${}.
function textOf(node) {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isTemplateExpression(node)) {
    return node.head.text + node.templateSpans.map((span) => "${}" + span.literal.text).join("");
  }
  return null;
}

const joining = (node) =>
  node &&
  (ts.isParenthesizedExpression(node) ||
    (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken));

const API = /^\/v1(\/|$)/;

// The expression a joined string opens on.
function leftmost(node) {
  let left = node;
  for (;;) {
    if (ts.isParenthesizedExpression(left)) left = left.expression;
    else if (ts.isBinaryExpression(left)) left = left.left;
    else if (ts.isTemplateExpression(left) && left.head.text === "")
      left = left.templateSpans[0].expression;
    else return left;
  }
}

// Whether an expression is an API address: a literal under /v1, a call to a
// function whose name says it builds one, or a name the same file declares as
// one of those.
function isAPI(node, declared, seen = new Set()) {
  const left = leftmost(node);
  if (ts.isConditionalExpression(left)) {
    return isAPI(left.whenTrue, declared, seen) && isAPI(left.whenFalse, declared, seen);
  }
  if (ts.isCallExpression(left)) {
    const callee = left.expression;
    return ts.isIdentifier(callee) && /^api[A-Z]/.test(callee.text);
  }
  if (ts.isIdentifier(left) && declared.has(left.text) && !seen.has(left.text)) {
    seen.add(left.text);
    return isAPI(declared.get(left.text), declared, seen);
  }
  const text = textOf(left);
  return text !== null && API.test(text);
}

// Whether a string that is part of a larger one opens on an API address, or
// null where it is not part of one. Part of one is joined onto others, or a
// template opening on a substitution.
function underAPI(node, declared) {
  if (ts.isTemplateExpression(node) && node.head.text === "") return isAPI(node, declared);
  let top = node;
  while (joining(top.parent)) top = top.parent;
  if (top === node) return null;
  return isAPI(top, declared);
}

const escaping = (node) =>
  ts.isCallExpression(node) &&
  ts.isIdentifier(node.expression) &&
  node.expression.text === "encodeURIComponent";

// Whether a string escapes something for a path segment of its own: a
// template with a substitution escaped that way, or a string joined onto one,
// with a slash among its literal parts. An address built from a prefix held in
// a variable opens on no literal, and this is what finds it.
function escapesASegment(node) {
  if (ts.isTemplateExpression(node)) {
    const parts = node.head.text + node.templateSpans.map((span) => span.literal.text).join("");
    return parts.includes("/") && node.templateSpans.some((span) => escaping(span.expression));
  }
  let top = node;
  while (joining(top.parent)) top = top.parent;
  if (top === node || !(textOf(node) ?? "").includes("/")) return false;
  const leaves = [];
  const gather = (at) => {
    if (joining(at)) ts.forEachChild(at, gather);
    else leaves.push(at);
  };
  gather(top);
  return leaves.some(escaping);
}

// Whether a literal is a React key, which names an element rather than a place.
function isKey(node) {
  let at = node.parent;
  if (at && ts.isJsxExpression(at)) at = at.parent;
  return Boolean(at && ts.isJsxAttribute(at) && at.name.getText() === "key");
}

// Whether a string glues a query onto an address it did not build: a template
// opening on a substitution with a part that starts a query or adds to one,
// or the query mark itself chosen by a condition inside it. A question mark
// that ends a template is prose.
function gluesAQuery(node) {
  if (!ts.isTemplateExpression(node) || node.head.text !== "") return false;
  const spans = node.templateSpans;
  const mark = (text) => /^[?&]([a-z_]+=|$)/.test(text);
  const chosen = (expression) =>
    ts.isConditionalExpression(expression) &&
    [expression.whenTrue, expression.whenFalse].every(
      (branch) => ts.isStringLiteral(branch) && ["?", "&"].includes(branch.text),
    );
  return spans.some(
    (span, i) =>
      chosen(span.expression) ||
      (mark(span.literal.text) && (i < spans.length - 1 || span.literal.text.length > 1)),
  );
}

// addressesIn reads one source file: every address it writes out whole that
// the router does not answer, every address it puts together from parts, and
// how many literals it examined.
export function addressesIn(routes, text, file = "x.tsx", source = parse(text, file)) {
  const found = [];
  let examined = 0;
  const declared = new Map();
  const declare = (node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      declared.set(node.name.text, node.initializer);
    }
    ts.forEachChild(node, declare);
  };
  declare(source);
  const walk = (node) => {
    const literal = textOf(node);
    if (literal !== null) {
      examined++;
      const opens = /^\/[a-z$]/.test(literal) || /^\$\{\}\/[a-z]/.test(literal);
      const relative = /^(\/|\$\{\})/.test(literal);
      const glued = gluesAQuery(node);
      if ((opens || glued || (relative && escapesASegment(node))) && !API.test(literal)) {
        const at = source.getLineAndCharacterOfPosition(node.getStart()).line + 1;
        const api = underAPI(node, declared);
        if (api === true || isKey(node)) {
          // An API address, which the API document describes.
        } else if (api === false || ts.isTemplateExpression(node) || !opens || glued) {
          found.push({ at, address: literal, why: "put together outside routes.ts" });
        } else if (!/\.[a-z]+$/.test(literal.split(/[?#]/)[0])) {
          // Whole, and not a file the page loads.
          const why = unrouted(routes, literal);
          if (why) found.push({ at, address: literal, why });
        }
      }
    }
    ts.forEachChild(node, walk);
  };
  walk(source);
  return { found, examined };
}

const named = (node, name) => ts.isIdentifier(node) && node.text === name;

const typedSearch = (type) =>
  type && ts.isTypeReferenceNode(type) && named(type.typeName, "URLSearchParams");

// What the interface hands query parameters out through, across every file:
// the properties an object literal sets from them, as a hook returning the
// router's parameters does, and the functions declared to return them.
const nothingHanded = { properties: new Set(), returners: new Set() };

// Whether an expression yields query parameters: a new URLSearchParams, the
// router's useSearchParams(), a call to a function declared to return them, or
// a memo of any of those.
function isSearchSource(node, handed) {
  node = bareOf(node);
  if (ts.isNewExpression(node)) return named(node.expression, "URLSearchParams");
  if (!ts.isCallExpression(node)) return false;
  if (named(node.expression, "useSearchParams")) return true;
  if (ts.isIdentifier(node.expression) && handed.returners.has(node.expression.text)) return true;
  const [made] = node.arguments;
  return (
    named(node.expression, "useMemo") &&
    made !== undefined &&
    ts.isArrowFunction(made) &&
    !ts.isBlock(made.body) &&
    isSearchSource(made.body, handed)
  );
}

// searchNames is the names one source file gives query parameters, matched by
// name across the file since the parse holds no types: a variable holding
// them, the first element taken from useSearchParams(), a property destructured
// from one the interface hands them out through, and anything declared with
// the URLSearchParams type, parameters and properties included.
//
// Beside them, what this file hands them out through: an object literal's
// property set from one of those names, and a function declared to return
// them.
function searchNames(source, handed = nothingHanded) {
  const names = new Set();
  const properties = new Set();
  const returners = new Set();
  const visit = (node) => {
    if (
      (ts.isVariableDeclaration(node) ||
        ts.isParameter(node) ||
        ts.isPropertySignature(node) ||
        ts.isPropertyDeclaration(node)) &&
      ts.isIdentifier(node.name) &&
      (typedSearch(node.type) ||
        (ts.isVariableDeclaration(node) &&
          node.initializer &&
          isSearchSource(node.initializer, handed)))
    ) {
      names.add(node.name.text);
    }
    if (ts.isVariableDeclaration(node) && ts.isArrayBindingPattern(node.name)) {
      const [first] = node.name.elements;
      const made = node.initializer && bareOf(node.initializer);
      if (
        made &&
        ts.isCallExpression(made) &&
        named(made.expression, "useSearchParams") &&
        first &&
        ts.isBindingElement(first) &&
        ts.isIdentifier(first.name)
      ) {
        names.add(first.name.text);
      }
    }
    if (ts.isBindingElement(node) && ts.isObjectBindingPattern(node.parent)) {
      const property = node.propertyName ?? node.name;
      if (ts.isIdentifier(property) && handed.properties.has(property.text)) {
        if (ts.isIdentifier(node.name)) names.add(node.name.text);
      }
    }
    if (ts.isFunctionDeclaration(node) && node.name && typedSearch(node.type)) {
      returners.add(node.name.text);
    }
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer &&
      (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer)) &&
      typedSearch(node.initializer.type)
    ) {
      returners.add(node.name.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  const hands = (node) => {
    if (ts.isShorthandPropertyAssignment(node) && names.has(node.name.text)) {
      properties.add(node.name.text);
    }
    if (
      ts.isPropertyAssignment(node) &&
      ts.isIdentifier(node.name) &&
      ts.isIdentifier(bareOf(node.initializer)) &&
      names.has(bareOf(node.initializer).text)
    ) {
      properties.add(node.name.text);
    }
    ts.forEachChild(node, hands);
  };
  hands(source);
  return { names, properties, returners };
}

// handedThrough is what a set of parsed files hands query parameters out
// through, read until nothing new is found, since a hook may hand on what
// another hook handed it.
export function handedThrough(sources) {
  const handed = { properties: new Set(), returners: new Set() };
  for (;;) {
    const before = handed.properties.size + handed.returners.size;
    for (const source of sources) {
      const found = searchNames(source, handed);
      for (const name of found.properties) handed.properties.add(name);
      for (const name of found.returners) handed.returners.add(name);
    }
    if (handed.properties.size + handed.returners.size === before) return handed;
  }
}

// The query parameters one source file reads: the first argument, written as
// a string, of every get, getAll or has asked of query parameters. Query
// parameters are anything `isSearchSource` accepts, a name `searchNames` finds
// in this file, or a property the interface hands them out through; a get on a
// map, a set or headers is not one.
export function readsIn(
  text,
  file = "x.tsx",
  source = parse(text, file),
  handed = handedThrough([source]),
) {
  const reads = new Set();
  const { names } = searchNames(source, handed);
  const isSearch = (node) => {
    const receiver = bareOf(node);
    if (isSearchSource(receiver, handed)) return true;
    if (ts.isIdentifier(receiver)) return names.has(receiver.text);
    return (
      ts.isPropertyAccessExpression(receiver) &&
      (names.has(receiver.name.text) || handed.properties.has(receiver.name.text))
    );
  };
  const walk = (node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ["get", "getAll", "has"].includes(node.expression.name.text) &&
      node.arguments[0] &&
      ts.isStringLiteral(node.arguments[0]) &&
      isSearch(node.expression.expression)
    ) {
      reads.add(node.arguments[0].text);
    }
    ts.forEachChild(node, walk);
  };
  walk(source);
  return reads;
}

// An expression with parentheses, `as` and a non-null assertion taken off.
function bareOf(node) {
  while (
    ts.isParenthesizedExpression(node) ||
    ts.isAsExpression(node) ||
    ts.isNonNullExpression(node)
  ) {
    node = node.expression;
  }
  return node;
}

function isFile(at) {
  try {
    return statSync(at).isFile();
  } catch {
    return false;
  }
}

// The modules one module imports by a relative path, by the file each names.
function importsOf(file, text) {
  const out = [];
  for (const m of text.matchAll(/(?:from|import\()\s*"(\.[^"]+)"/g)) {
    const base = path.resolve(path.dirname(file), m[1]);
    const found = [base, `${base}.ts`, `${base}.tsx`].find(
      (candidate) => /\.tsx?$/.test(candidate) && isFile(candidate),
    );
    if (found) out.push(found);
  }
  return out;
}

// Every module one module reaches through relative imports, itself included,
// over a graph read once.
function closure(file, imports) {
  const seen = new Set();
  const visit = (at) => {
    if (seen.has(at)) return;
    seen.add(at);
    for (const next of imports.get(at) ?? []) visit(next);
  };
  visit(file);
  return [...seen];
}

// screensOf reads the router: the module each route's screen comes from, by
// route name. A route that renders no screen of its own — a redirect — is
// absent.
export function screensOf(appText) {
  const modules = new Map();
  for (const m of appText.matchAll(/const (\w+) = retrying\(\(\) =>\s*import\("([^"]+)"\)/g)) {
    modules.set(m[1], m[2]);
  }
  for (const m of appText.matchAll(/import \{([^}]+)\} from "(\.[^"]+)"/g)) {
    for (const name of m[1].split(",")) modules.set(name.trim(), m[2]);
  }
  const screens = new Map();
  for (const m of appText.matchAll(/<Route path=\{ROUTES\.(\w+)\} element=\{<(\w+)[\s/>]/g)) {
    const module = modules.get(m[2]);
    if (module) screens.set(m[1], module);
  }
  return screens;
}

// mountedIn is every route name the router mounts, as the name it reads out of
// the table.
export function mountedIn(appText) {
  return [...appText.matchAll(/<Route\s+path=\{ROUTES\.(\w+)\}/g)].map((m) => m[1]);
}

// The router's own source.
export function app() {
  return readFileSync(path.join(src, "app", "App.tsx"), "utf8");
}

// unread is every query parameter the table lists for a route that nothing the
// route's screen reaches reads.
export function unread(routes, screens, readsOf) {
  const found = [];
  for (const [name, route] of Object.entries(routes)) {
    const keys = route.query ?? [];
    if (keys.length === 0) continue;
    const module = screens.get(name);
    if (!module) {
      found.push({ route: name, key: keys[0], why: "the route renders no screen to read it" });
      continue;
    }
    const reads = readsOf(module);
    for (const key of keys) if (!reads.has(key)) found.push({ route: name, key, why: "unread" });
  }
  return found;
}

// The whole interface.
export function sweep() {
  const routes = table();
  const found = [];
  let files = 0;
  let literals = 0;
  // Each file is read and parsed once, and every rule reads that one tree.
  const imports = new Map();
  const reads = new Map();
  const sources = interfaceSources();
  const handed = handedThrough(sources.map(({ source }) => source));
  for (const { file, text, source } of sources) {
    imports.set(file, importsOf(file, text));
    reads.set(file, readsIn(text, file, source, handed));
    const relative = path.relative(src, file);
    if (relative === BUILDER) continue;
    const { found: here, examined } = addressesIn(routes, text, file, source);
    files++;
    literals += examined;
    for (const each of here) found.push({ file: relative, ...each });
  }
  const app = path.join(src, "app", "App.tsx");
  const screens = screensOf(readFileSync(app, "utf8"));
  const readsOf = (module) => {
    const out = new Set();
    const entry = path.resolve(path.dirname(app), module);
    const file = [`${entry}.tsx`, `${entry}.ts`].find(isFile);
    for (const each of file ? closure(file, imports) : []) {
      for (const key of reads.get(each) ?? []) out.add(key);
    }
    return out;
  };
  return {
    found,
    unread: unread(routes, screens, readsOf),
    files,
    literals,
    routes: Object.keys(routes).length,
    screens: screens.size,
  };
}
