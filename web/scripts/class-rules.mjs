// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// How a stylesheet's class rules and a source file's class names are read,
// and which of them cannot be right.
//
// A module of its own so that a test can import it. The program beside this
// one does its work at import time — it walks the stylesheets, compiles
// Tailwind and exits non-zero on a finding — so a test that imported it would
// take the runner down at exactly the moment the check is doing its job.

// A modifier sharing a name with a text style is ordinary and correct:
// `.linkish.id` beside a bare `.id` that sets a font is two rules that agree.
// What cannot be right is a modifier whose bare rule takes an element **out of
// normal flow** — a chip does not become positioned because of the word beside
// it. So the test is the property, not the name.
const escapes = /(^|[\s;])(position\s*:\s*(fixed|absolute|sticky)|inset\s*:)/;

// cssRules is every rule a stylesheet holds, as its selector and its body, in
// order. A rule inside an at-rule block is read like any other; the block's
// own prelude never reaches a selector.
//
// A rule nested inside another rule is refused rather than read. The reader
// takes innermost blocks, so a nested rule would arrive with the outer rule's
// declarations as its selector, or with nothing but its own selector where it
// opens its parent, and the outer rule would never be seen. A block is nested
// where the brace before it opens a block whose prelude is not an at-rule.
//
// A rule is read as the text before its brace, so everything else that can
// stand before one goes first:
//
//   - A comment. A prose paragraph above `.overpane` is otherwise the
//     selector, and the rule is never seen.
//   - An at-rule statement ending in a semicolon. `@import
//     "@fontsource/instrument-sans/400.css";` above a rule otherwise joins its
//     selector, which then names a class `css` and hides the rule's own.
export function cssRules(text) {
  const css = text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/@[\w-]+[^;{}]*;/g, " ");
  const out = [];
  for (const match of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const [, selector, body] = match;
    if (selector.includes(";") || insideRule(css, match.index)) {
      throw new Error(`a rule nested inside another is not read: ${selector.trim()}`);
    }
    out.push({ selector: selector.trim(), body });
  }
  return out;
}

// insideRule is whether the text at an offset sits in a block a rule opened,
// at any depth. The top level and at-rule blocks alone are outside one.
function insideRule(css, at) {
  const opened = [];
  for (let i = 0; i < at; i++) {
    if (css[i] === "{") opened.push(i);
    else if (css[i] === "}") opened.pop();
  }
  return opened.some((open) => {
    const before = Math.max(css.lastIndexOf("{", open - 1), css.lastIndexOf("}", open - 1));
    return !css
      .slice(before + 1, open)
      .trim()
      .startsWith("@");
  });
}

// definedClasses is every class name a stylesheet's selectors carry, in the
// order they first appear. Every class in a selector counts, a modifier's
// included, since each is a name Tailwind may also answer for.
export function definedClasses(text) {
  const names = [];
  for (const { selector } of cssRules(text)) {
    for (const [, name] of selector.matchAll(/\.(-?[A-Za-z_][\w-]*)/g)) {
      if (!names.includes(name)) names.push(name);
    }
  }
  return names;
}

// rulesIn reads one stylesheet as two maps: what each bare class declares, and
// which classes are only ever reached as a modifier beside another.
//
// Lifted out of the walk so it can be asked directly: a gate reachable only by
// running the program over the tree has an exit code for its only evidence,
// and an exit code cannot tell a check that found nothing from one that looked
// at nothing.
export function rulesIn(text, into = { declared: new Map(), modifiers: new Map() }) {
  for (const { selector, body } of cssRules(text)) {
    for (const part of selector.split(",")) {
      const one = part.trim();
      if (!/^(?:\.[-\w]+)+$/.test(one)) continue;
      const names = [...one.matchAll(/\.([-\w]+)/g)].map(([, name]) => name);
      if (names.length === 1) {
        into.declared.set(names[0], (into.declared.get(names[0]) ?? "") + ";" + body);
      } else {
        for (const name of names.slice(1)) {
          if (!into.modifiers.has(name)) into.modifiers.set(name, one);
        }
      }
    }
  }
  return into;
}

// A bare rule that draws a box: a display, spacing, border or background. A
// class reached as a modifier carries its bare rule too, at the same
// specificity, so a later bare rule of this kind replaces the box of the thing
// it modifies.
export const DRAWS_A_BOX =
  /(^|[\s;])(display|margin(-[a-z]+)*|padding(-[a-z]+)*|border(-[a-z]+)*|background(-[a-z]+)*)\s*:/;

// modifiersWhoseRule is every class reached as a modifier whose own bare rule
// matches a pattern, sorted.
export function modifiersWhoseRule({ declared, modifiers }, pattern) {
  return [...modifiers.keys()].filter((name) => pattern.test(declared.get(name) ?? "")).sort();
}

// positionedModifiers is every class reached as a modifier whose own bare rule
// takes an element out of normal flow.
//
// Narrow on purpose: a modifier sharing a name with a text style is ordinary
// and correct. What cannot be right is a chip becoming positioned because of
// the word beside it — so the test is the property rather than the name.
export function positionedModifiers(read) {
  return modifiersWhoseRule(read, escapes);
}

// emits is whether a stylesheet holds a rule for a class, as a whole name.
//
// Bounded after the name, so a rule for `.text-sm` is not read as one for
// `.text`. A bare substring test is absolved by every longer name that opens
// with the one being asked about.
export function emits(css, name) {
  const quoted = name.replace(/[-[\]{}()*+?.\\^$|]/g, "\\$&");
  return new RegExp(`\\.${quoted}(?=[\\s,:{>+~])`).test(css);
}

// styleless is every name a stylesheet holds no rule for, in order.
export function styleless(names, css) {
  return names.filter((name) => !emits(css, name)).sort();
}

// Names that come from somewhere other than our own markup, so their absence
// says nothing: a charting library writes its own, and print rules are matched
// by the browser rather than by us.
const foreign = /^(recharts-|markdown-body$)/;

// unusedClasses is every name, in order, that the markup never applies. The
// markup is the quoted runs of the source, each with a space either side.
//
// A name counts as applied after whitespace, a quote, a backtick or a dot, and
// before any of those, a colon, or "$": a name at the head of a template
// literal is followed by the interpolation that adds its modifiers —
// `noticekind${…}` — and reading that as never applied would ask somebody to
// delete a rule that is in use.
export function unusedClasses(names, markup) {
  return names.filter(
    (name) =>
      !foreign.test(name) &&
      !new RegExp(`[\\s"'\`.]${name.replace(/[-[\]{}()*+?.\\^$|]/g, "\\$&")}[\\s"'\`:.$]`).test(
        markup,
      ),
  );
}

// quotedRuns is the quoted and template text of a source file, each run with a
// space either side, which is the markup a class can reach an element through.
//
// Comments go first, since many class names are also ordinary English words
// in a sentence. A line comment opens on `//` not preceded by a colon or a
// word character, so a URL inside a string is kept. A class inside an
// interpolation is itself a quoted string, so nested runs are kept.
export function quotedRuns(text) {
  const bare = text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(?<![:\w])\/\/[^\n]*/g, " ");
  const runs = [];
  for (const [, single, double, template] of bare.matchAll(/"([^"\n]*)"|'([^'\n]*)'|`([^`]*)`/g)) {
    runs.push(` ${single ?? double ?? template ?? ""} `);
  }
  return runs.join("\n");
}

// writtenClasses is every literal class name a source file writes into a
// `className`, with the line it is on. An interpolation in a template is
// skipped, since what it holds is unknown here.
export function writtenClasses(text) {
  const out = [];
  text.split("\n").forEach((line, i) => {
    for (const m of line.matchAll(/className=(?:"([^"]*)"|\{`([^`]*)`\})/g)) {
      for (const word of (m[1] ?? m[2] ?? "").replace(/\$\{[^}]*\}/g, " ").split(/\s+/)) {
        if (/^[A-Za-z][\w-]*$/.test(word)) out.push({ word, line: i + 1 });
      }
    }
  });
  return out;
}
