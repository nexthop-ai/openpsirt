// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Standing prose on a screen.
//
// Screen copy is labels and values (DESIGN-interface.md § Screen copy). What
// this refuses is the shape it drifts into: a paragraph under a heading that
// explains the design to somebody working a list. It measures the words a
// paragraph can put on the screen at once — every text node and string it
// renders, taking the longer side of a condition — so prose inside a
// `{cond && (…)}` branch is counted like prose outside one.
//
// Parsed rather than matched: a paragraph's text is split across conditions
// and fragments, and a pattern that skips expressions skips exactly the
// branches the long sentences hide in.
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import ts from "typescript";

const here = path.dirname(new URL(import.meta.url).pathname);
const src = path.join(here, "..", "src");

// The most words one paragraph, hint, or empty-state detail may put on screen.
export const BOUND = 20;

// Paragraphs that stay longer, each with the reason. Keyed on file and the
// paragraph's first words, so an edit that moves it keeps it allowed and an
// edit that rewrites it has to earn its place again.
export const ALLOWED = new Map([]);

// Props that render as standing text: a field's hint and an empty state's
// detail. A title is a tooltip, which is where clarification belongs.
const TEXT_PROPS = new Set(["hint", "detail"]);

function words(text) {
  return (text.replace(/&[a-z]+;/gi, " ").match(/[A-Za-z’']+/g) ?? []).length;
}

function tagName(node) {
  const opening = ts.isJsxElement(node) ? node.openingElement : node;
  return opening.tagName.getText();
}

function className(node) {
  const opening = ts.isJsxElement(node) ? node.openingElement : node;
  for (const attr of opening.attributes.properties) {
    if (ts.isJsxAttribute(attr) && attr.name.getText() === "className" && attr.initializer) {
      if (ts.isStringLiteral(attr.initializer)) return attr.initializer.text;
    }
  }
  return "";
}

// The words a node can put on screen at once.
function shown(node) {
  if (!node) return 0;
  if (ts.isJsxText(node)) return words(node.text);
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
    return words(node.text);
  }
  if (ts.isTemplateExpression(node)) {
    return (
      words(node.head.text) + node.templateSpans.reduce((n, s) => n + words(s.literal.text), 0)
    );
  }
  if (ts.isJsxElement(node) || ts.isJsxFragment(node)) {
    return node.children.reduce((n, child) => n + shown(child), 0);
  }
  if (ts.isJsxExpression(node)) return shown(node.expression);
  if (ts.isParenthesizedExpression(node)) return shown(node.expression);
  if (ts.isConditionalExpression(node)) {
    return Math.max(shown(node.whenTrue), shown(node.whenFalse));
  }
  if (ts.isBinaryExpression(node)) {
    const op = node.operatorToken.kind;
    if (op === ts.SyntaxKind.AmpersandAmpersandToken) return shown(node.right);
    if (op === ts.SyntaxKind.BarBarToken || op === ts.SyntaxKind.QuestionQuestionToken) {
      return Math.max(shown(node.left), shown(node.right));
    }
    if (op === ts.SyntaxKind.PlusToken) return shown(node.left) + shown(node.right);
  }
  return 0;
}

// The first words of what a node renders as text, to name it in a report.
function lead(node) {
  const parts = [];
  const walk = (n) => {
    if (ts.isJsxText(n)) parts.push(n.text);
    else if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) parts.push(n.text);
    else if (ts.isTemplateExpression(n)) parts.push(n.head.text);
    ts.forEachChild(n, walk);
  };
  walk(node);
  return parts.join(" ").split(/\s+/).filter(Boolean).slice(0, 6).join(" ");
}

// Every paragraph, element styled as a hint, and empty-state detail in one
// file past the bound,
// and how many were examined.
export function proseIn(text, file = "x.tsx", bound = BOUND) {
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const found = [];
  let examined = 0;
  const report = (node, n) => {
    examined++;
    if (n > bound) {
      const at = source.getLineAndCharacterOfPosition(node.getStart()).line + 1;
      found.push({ at, words: n, lead: lead(node) });
    }
  };
  const visit = (node) => {
    if (ts.isJsxElement(node)) {
      const tag = tagName(node);
      if (tag === "p" || /\bhint\b/.test(className(node))) {
        report(node, shown(node));
      }
    }
    if (ts.isJsxAttribute(node) && TEXT_PROPS.has(node.name.getText()) && node.initializer) {
      report(node, shown(node.initializer));
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { found, examined };
}

// A control whose whole text names nothing: what it leads to or does is left
// for the reader to guess from where it sits.
export const VAGUE = new Set([
  "read them",
  "see them",
  "read more",
  "see more",
  "more",
  "here",
  "click here",
  "view",
  "open",
  "show",
  "go",
  "link",
  "this",
]);

// A heading or label that asks rather than names. Headings and field labels
// are noun phrases (REQ-60).
const ASKS = /^(what|where|who|whom|whose|how|when|which|why)\b/i;

// The text a node says when all of it is written out, or undefined where any
// of it is computed: a label built from a value names that value.
function written(node) {
  let out = "";
  let computed = false;
  const walk = (n) => {
    if (ts.isJsxAttributes(n)) return;
    if (ts.isJsxText(n)) out += n.text;
    else if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) out += n.text;
    else if (ts.isJsxExpression(n) && n.expression && !ts.isStringLiteral(n.expression)) {
      computed = true;
    } else ts.forEachChild(n, walk);
  };
  if (ts.isJsxElement(node)) node.children.forEach(walk);
  else walk(node);
  return computed ? undefined : out.replace(/\s+/g, " ").trim();
}

const CONTROLS = new Set(["a", "Link", "button"]);
const HEADINGS = new Set(["h2", "h3", "h4", "label", "legend"]);
const LABEL_PROPS = new Set(["label", "legend", "title"]);
const LABELLED = new Set([
  "Field",
  "Pick",
  "Group",
  "Check",
  "Choices",
  "Editor",
  "ChoiceCards",
  "FilterMenu",
]);

// Every control whose whole text is vague, and every heading or label that
// asks rather than names, in one file, and how many were examined.
export function namesIn(text, file = "x.tsx") {
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const found = [];
  let examined = 0;
  const at = (node) => source.getLineAndCharacterOfPosition(node.getStart()).line + 1;
  const visit = (node) => {
    if (ts.isJsxElement(node)) {
      const tag = tagName(node);
      const said = written(node);
      if (CONTROLS.has(tag) && said !== undefined && said !== "") {
        examined++;
        const bare = said
          .replace(/[→←›»…]/g, "")
          .trim()
          .toLowerCase();
        if (VAGUE.has(bare)) found.push({ at: at(node), rule: "vague", said });
      }
      if (HEADINGS.has(tag) && said !== undefined && said !== "") {
        examined++;
        if (ASKS.test(said)) found.push({ at: at(node), rule: "asks", said });
      }
    }
    if (ts.isJsxAttribute(node) && node.initializer && ts.isStringLiteral(node.initializer)) {
      const owner = node.parent?.parent;
      const tag =
        owner && (ts.isJsxOpeningElement(owner) || ts.isJsxSelfClosingElement(owner))
          ? owner.tagName.getText()
          : "";
      if (LABEL_PROPS.has(node.name.getText()) && LABELLED.has(tag)) {
        examined++;
        const said = node.initializer.text.trim();
        if (ASKS.test(said)) found.push({ at: at(node), rule: "asks", said });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { found, examined };
}

async function sources(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await sources(full)));
    else if (entry.name.endsWith(".tsx") && !entry.name.includes(".test.")) out.push(full);
  }
  return out;
}

// The whole tree: every finding past the bound that is not allowed, and how
// many paragraphs were examined.
export async function sweep() {
  const found = [];
  let examined = 0;
  for (const file of await sources(src)) {
    const rel = path.relative(src, file);
    const result = proseIn(await readFile(file, "utf8"), file);
    examined += result.examined;
    for (const each of result.found) {
      const allowed = [...ALLOWED.keys()].some(
        (key) => key.startsWith(rel + ":") && each.lead.startsWith(key.slice(rel.length + 1)),
      );
      if (!allowed) found.push({ file: rel, ...each });
    }
  }
  return { found, examined };
}

// The whole tree, for vague controls and asking labels.
export async function sweepNames() {
  const found = [];
  let examined = 0;
  for (const file of await sources(src)) {
    const result = namesIn(await readFile(file, "utf8"), file);
    examined += result.examined;
    for (const each of result.found) found.push({ file: path.relative(src, file), ...each });
  }
  return { found, examined };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const names = await sweepNames();
  if (names.examined === 0) {
    console.error("No control, heading or label was found, so this checked nothing.");
    process.exit(1);
  }
  for (const each of names.found) {
    console.error(
      each.rule === "vague"
        ? `src/${each.file}:${each.at}: "${each.said}" names nothing. Say what it opens or does.`
        : `src/${each.file}:${each.at}: "${each.said}" asks. A heading or label names the thing.`,
    );
  }
  if (names.found.length > 0) process.exit(1);
  const { found, examined } = await sweep();
  if (examined === 0) {
    console.error("No paragraph was found in the interface, so this checked nothing.");
    process.exit(1);
  }
  for (const each of found) {
    console.error(`src/${each.file}:${each.at}: ${each.words} words, past ${BOUND}: ${each.lead}…`);
  }
  if (found.length > 0) {
    console.error(
      "Screen copy is labels and values. Cut it, or move it onto a hover or into a design document.",
    );
    process.exit(1);
  }
  console.log(`${examined} paragraphs, hints and details, none past ${BOUND} words.`);
}
