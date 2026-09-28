// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// How a stylesheet's class rules are read, and which of them cannot be right.
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
// declarations as its selector and the outer rule would never be seen.
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
  for (const [, selector, body] of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    if (selector.includes(";")) {
      throw new Error(`a rule nested inside another is not read: ${selector.trim()}`);
    }
    out.push({ selector: selector.trim(), body });
  }
  return out;
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

// positionedModifiers is every class reached as a modifier whose own bare rule
// takes an element out of normal flow.
//
// Narrow on purpose: a modifier sharing a name with a text style is ordinary
// and correct. What cannot be right is a chip becoming positioned because of
// the word beside it — so the test is the property rather than the name.
export function positionedModifiers({ declared, modifiers }) {
  return [...modifiers.keys()].filter((name) => escapes.test(declared.get(name) ?? "")).sort();
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
