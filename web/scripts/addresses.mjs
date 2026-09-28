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
//   reads, so the table cannot promise a parameter nothing acts on.
//
// An API address opens on /v1, or is joined onto a call that builds one, and
// is not an address into this application.
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import ts from "typescript";

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

// addressesIn reads one source file: every address it writes out whole that
// the router does not answer, every address it puts together from parts, and
// how many literals it examined.
function parse(text, file) {
  return ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
}

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
      if ((opens || (relative && escapesASegment(node))) && !API.test(literal)) {
        const at = source.getLineAndCharacterOfPosition(node.getStart()).line + 1;
        const api = underAPI(node, declared);
        if (api === true || isKey(node)) {
          // An API address, which the API document describes.
        } else if (api === false || ts.isTemplateExpression(node) || !opens) {
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

function sources(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...sources(full));
    else if (
      /\.tsx?$/.test(entry.name) &&
      !entry.name.includes(".test.") &&
      !entry.name.endsWith(".d.ts")
    )
      out.push(full);
  }
  return out;
}

// The query parameters one source file reads: the first argument of every
// get, getAll or has that is written as a string.
export function readsIn(text, file = "x.tsx", source = parse(text, file)) {
  const reads = new Set();
  const walk = (node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ["get", "getAll", "has"].includes(node.expression.name.text) &&
      node.arguments[0] &&
      ts.isStringLiteral(node.arguments[0])
    ) {
      reads.add(node.arguments[0].text);
    }
    ts.forEachChild(node, walk);
  };
  walk(source);
  return reads;
}

function isFile(at) {
  try {
    return statSync(at).isFile();
  } catch {
    return false;
  }
}

// Every module one module reaches through relative imports, itself included.
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
  for (const file of sources(src)) {
    const text = readFileSync(file, "utf8");
    const source = parse(text, file);
    imports.set(file, importsOf(file, text));
    reads.set(file, readsIn(text, file, source));
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

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const result = sweep();
  if (result.files === 0 || result.literals === 0 || result.routes === 0 || result.screens === 0) {
    console.error("No source, route or screen was read, so this checked nothing.");
    process.exit(1);
  }
  for (const each of result.found)
    console.error(`src/${each.file}:${each.at}: ${each.address}: ${each.why}`);
  for (const each of result.unread)
    console.error(`routes.json: ${each.route} lists "${each.key}": ${each.why}`);
  if (result.found.length + result.unread.length > 0) process.exit(1);
}
